#include "ptu.h"
#include "buffer.h"
#include "utils.h"
#include "time.h"
#include "hash.h"

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/un.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <signal.h>
#include <unistd.h>

#define IDX_SAVETIMEOUT		5 /* timeout in seconds when to save idx */

#define HASHTABLE_SIZE		1009 /* needs to be prime */

/* represents a logging client */
struct client {
	struct client * next;
	struct buffer * buf;
	char prefix[PTU_MAX_PREFIXLEN+1];
	uint32_t id;
	int fd;
	int registered;
};

/* maximum number of simultaneously connected logging clients */
#define MAX_NRCLIENTS	128

/* holds connected logging clients */
static struct client * clients[HASHTABLE_SIZE];

/* number of currently connected clients */
static uint32_t client_cnt = 0;

/* represents a pair of log and timestamp files based 
   on a specific index entry */
struct log {
	struct log * next;
	struct idx_entry * idx;
	int ts_fd;
	int lg_fd;
};

/* holds all active log and timestamp pairs */
static struct log * logs[HASHTABLE_SIZE];

/* stores highest unique id for a specific prefix */
struct prefixid {
	struct prefixid * next;
	char prefix[PTU_MAX_PREFIXLEN+1];
	uint32_t id;
};

/* holds top unique id's for prefixes */
static struct prefixid * prefixids[HASHTABLE_SIZE];

/* holds references to the linked list of active idx entries */
static struct idx_entry * first_idx_entry;
static struct idx_entry * last_idx_entry;

/* currently active log directory */
static char * logdir;

/* used to signify polling loop that signal was received */
static int signal_received;

/* points to current active index file name if set */
static char * idx_filename;

/* last save of idx file */
static struct taia last_idx_save;

static int
open_logfile(struct log * log)
{
	char * buf;
	struct stat st;
	size_t ts_filesz, lg_filesz, fnlen;
	int ts_fd, lg_fd, ret;	

	if (!log) return -1;

	if (log->ts_fd != -1 && log->lg_fd != -1) {
	}

	fnlen = strlen(log->idx->prefix) + strlen("/_00000000_0000.log")
		+ strlen(logdir) + 1;
	buf = xmalloc(fnlen);
	snprintf(buf, fnlen, "%s/%s_%.8x_%.4u.log", logdir,
		log->idx->prefix,
		log->idx->id,
		log->idx->no);

	lg_fd = open(buf, O_APPEND|O_CREAT|O_WRONLY,
		S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH); /* rw-r--r-- */
	fd_set_cloexec(lg_fd);
	ret = fstat(lg_fd, &st);
	if (ret < 0) {
		free(buf);
		fd_close(lg_fd);
		return -1;
	}
	lg_filesz = st.st_size;

	strncpy(buf + fnlen - 4, "tsd", 3);
	ts_fd = open(buf, O_APPEND|O_CREAT|O_WRONLY,
		S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH); /* rw-r--r-- */
	fd_set_cloexec(ts_fd);
	ret = fstat(ts_fd, &st);
	if (ret < 0) {
		free(buf);
		fd_close(lg_fd);
		fd_close(ts_fd);
		return -1;
	}
	ts_filesz = st.st_size;

	/* newly created log and ts files so initialize the hash */
	if (ts_filesz == lg_filesz && ts_filesz == 0) {
		log->idx->ts_hash = DJB_HASH_MAGIC;
		log->idx->lg_hash = DJB_HASH_MAGIC;
	}
	log->ts_fd = ts_fd;
	log->lg_fd = lg_fd;
	log->idx->lg_filesz = lg_filesz;
	log->idx->ts_filesz = ts_filesz;

	free(buf);
	return 0;
}

/* write_log returns -1 if an error occurs, 0 if the logs were cycled
   and the log entry was NOT written out and 1 if the entry was
   logged successfully. */
static int
write_log(const char * prefix, uint32_t id, void * data, size_t len)
{
	char packedtm[TAIA_PACK];
	struct taia tm;
	struct log * log;
	struct idx_entry * idx;
	uint32_t hlen, hsize;
	uint32_t hash;
	int ret;

	if (!prefix || !data || !len) return -1;

	taia_now(&tm);
	taia_pack(packedtm, &tm);

	// XXX: turn to function
	hash = djb_hash(prefix, strlen(prefix), DJB_HASH_MAGIC);
	hash = djb_hash((char *)&id, sizeof(id), hash);
	log = logs[hash % HASHTABLE_SIZE];
	while (log && (log->idx->id != id ||
			strcmp(log->idx->prefix, prefix))) {
		log = log->next;
	}
	if (!log) {
		log = xmalloc(sizeof(struct log));
		idx = xmalloc(sizeof(struct idx_entry));

		log->idx = idx;

		if (!first_idx_entry) first_idx_entry = idx;
		if (last_idx_entry) last_idx_entry->next = idx;
		last_idx_entry = idx;

		strcpy(idx->prefix, prefix);
		idx->id = id;
		idx->no = 1;
		memcpy(&idx->t0, &tm, sizeof(struct taia));

		log->ts_fd = -1;
		log->lg_fd = -1;
		log->next = logs[hash % HASHTABLE_SIZE];
		logs[hash % HASHTABLE_SIZE] = log;
	}

	/* open the log and timestamp file if they're not opened yet */
	if (log->ts_fd == -1) {
		ret = open_logfile(log);
		if (ret < 0) return -1;

		/* Force a log cycle after opening a new log so that a client
		   has the opportunity to write out a file header if it
		   desires to do so. */
		if (!log->idx->lg_filesz) {
			return 0;
		}
	}

	/* cycle logs if necessary */
	if ((log->idx->lg_filesz + len) > PTU_MAX_LOGSIZE) {
		fd_close(log->ts_fd);
		fd_close(log->lg_fd);
	
		idx = xmalloc(sizeof(struct idx_entry));
		memcpy(idx->prefix, log->idx->prefix, sizeof(idx->prefix));
		idx->id = log->idx->id;
		idx->no = log->idx->no + 1;

		// XXX; what if we hit the limit of 'no'?
		idx->ts_filesz = idx->lg_filesz = 0;
		idx->ts_hash = DJB_HASH_MAGIC;
		idx->lg_hash = DJB_HASH_MAGIC;
		memcpy(&idx->t0, &tm, sizeof(struct taia));

		if (!first_idx_entry) first_idx_entry = idx;
		if (last_idx_entry) last_idx_entry->next = idx;
		last_idx_entry = idx;

		log->idx = idx;
		log->ts_fd = -1;
		log->lg_fd = -1;
		return 0;
	}

	memcpy(&log->idx->t1, &tm, sizeof(struct taia));

	log->idx->lg_hash = djb_hash(data, len, log->idx->lg_hash);
	fd_write(log->lg_fd, data, len);

	hlen = htonl(len);
	hsize = htonl(log->idx->lg_filesz);

	log->idx->ts_hash = djb_hash((char *)&packedtm, TAIA_PACK,
		log->idx->ts_hash); 
	log->idx->ts_hash = djb_hash((char *)&hlen, 4, log->idx->ts_hash);
	log->idx->ts_hash = djb_hash((char *)&hsize, 4,
		log->idx->ts_hash);

	fd_write(log->ts_fd, &packedtm, TAIA_PACK);
	fd_write(log->ts_fd, &hlen, 4);
	fd_write(log->ts_fd, &hsize, 4);

	log->idx->lg_filesz += len;
	log->idx->ts_filesz += TAIA_PACK + 4 + 4;

	return 1;
}

static void
handle_msg(struct client * c, int * remove)
{
	struct prefixid * pfxid;
	struct ptu_msg msg;
	size_t avail;
	uint32_t hash;
	int ret;

	if (!c || !remove) fatal("error in calling handle_msg");

	*remove = 0;
	avail = buffer_avail(c->buf);
	if (avail < sizeof(struct ptu_msg))
		return;
	buffer_peek(c->buf, &msg, sizeof(struct ptu_msg));
	avail -= sizeof(struct ptu_msg);

	/* message too long */
	if (msg.len > PTU_MAX_MSGSIZE) {
		debug("message too long: %u\n", msg.len);
		*remove = 1;
		return;
	}

	/* if the entire message is there start processing it */
	if (avail < msg.len) return;
	buffer_consume(c->buf, NULL, sizeof(struct ptu_msg));

	/* if the client's not registered yet only allow register messages */
	if (!(c->registered)) {
		if (msg.type != PTU_MSG_REGISTER ||
				msg.len > PTU_MAX_PREFIXLEN) {
			*remove = 1;
			return; 
		}
		buffer_consume(c->buf, &(c->prefix), msg.len);	
		c->prefix[msg.len] = 0;
		c->registered = 1;

		/* for some prefixes sources cannot be mixed and as such
		   return a unique id for them */
		if (!strcmp(c->prefix, "pcap") ||
			!strcmp(c->prefix, "term")) {

			/* find pfxid if it exists */
			hash = djb_hash(c->prefix, strlen(c->prefix),
				DJB_HASH_MAGIC);
			pfxid = prefixids[hash % HASHTABLE_SIZE];
			while (pfxid && strcmp(c->prefix, pfxid->prefix)) {
				pfxid = pfxid->next;
			}

			/* new prefix so add it to prefixids */
			if (!pfxid) {
				debug("new prefix %s added", c->prefix);
				pfxid = xmalloc(sizeof(struct prefixid));
				pfxid->next = prefixids[hash % HASHTABLE_SIZE];
				prefixids[hash % HASHTABLE_SIZE] = pfxid;
				pfxid->id = 0;	
			}
			/* update the prefix id */
			else pfxid->id++;
			
			debug("prefix %s has been handed out id=%x",
				c->prefix, pfxid->id);

			c->id = pfxid->id;
		}
		msg.type = PTU_MSG_OK;
		msg.len = 4;
		fd_write(c->fd, &msg, sizeof(msg));
		fd_write(c->fd, &c->id, 4);
		return;
	}

	/* handle all other message types */
	switch (msg.type) {
	case PTU_MSG_LOG:
		/* breaks buffer encapsulation; ugly! */
		ret = write_log(c->prefix, c->id,
			c->buf->data + c->buf->roff, msg.len);
		buffer_consume(c->buf, NULL, msg.len);

		/* notify logging client if an error occured, if the logs
		   were cycled or if the entry was successfully logged */
		msg.type = (ret < 0 ? PTU_MSG_ERR : 
			(ret ? PTU_MSG_OK : PTU_MSG_CYCLE));
		msg.len = 0;
		ret = send(c->fd, &msg, sizeof(struct ptu_msg), 0);
		if (ret < 0) /* err ret */ return;
		break;
	default:
		/* invalid message type */
		debug("invalid message type: %u\n", msg.type);
		*remove = 1;
		break;
	}
	return;
}

static int
save_idx_file(const char * filename, struct idx_entry * e)
{
	char t0_pack[TAIA_PACK], t1_pack[TAIA_PACK];
	char t0_hex[TAIA_PACK*2+1], t1_hex[TAIA_PACK*2+1];
	char buf[PTU_MAX_IDXLINELEN+1];
	int fd, ret;

	if (!filename) fatal("save_idx_file: filename not set");

	debug("saving idx file...");

	fd = open(filename, O_TRUNC|O_CREAT|O_WRONLY,
		S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH); /* rw-r--r-- */
	if (fd < 0) return -1;

	while (e) {

		taia_pack(t0_pack, &e->t0);
		taia_pack(t1_pack, &e->t1);

		bin2hex(t0_pack, sizeof(t0_pack), t0_hex, TAIA_PACK*2+1);
		bin2hex(t1_pack, sizeof(t1_pack), t1_hex, TAIA_PACK*2+1);

		ret = snprintf(buf, PTU_MAX_IDXLINELEN,
			"%s,%s,%s-%x-%.4u,%u,%x,%u,%x\n", 
			t0_hex, t1_hex,
			e->prefix, e->id, e->no,
			e->ts_filesz, e->ts_hash,
			e->lg_filesz, e->lg_hash);
		fd_write(fd, buf, ret);

		e = e->next;
	}
	fd_close(fd);

	taia_now(&last_idx_save);
	return 0;
}

static int
close_logdir()
{
	int ret;

	ret = save_idx_file(idx_filename, first_idx_entry);
	if (ret < 0) fatal("cannot save index file");

	free(idx_filename);

	idx_filename = NULL;
	memset(logs, 0, sizeof(logs));
	memset(clients, 0, sizeof(clients));
	memset(prefixids, 0, sizeof(prefixids));

	return ret;
}

static int
open_logdir()
{
	struct prefixid * pfxid;
	struct idx_entry * e;
	struct log * log;
	size_t idx_fnlen;
	uint32_t hash;
	int ret;

	memset(logs, 0, sizeof(logs));
	memset(&last_idx_save, 0, sizeof(last_idx_save));

	idx_fnlen = strlen(logdir) + strlen("/ptu.idx"); 
	idx_filename = xmalloc(idx_fnlen + 1);
	strcpy(idx_filename, logdir);
	strcat(idx_filename, "/ptu.idx");

	ret = ptu_load_idxfile(logdir, &e);
	if (ret < 0) {
		//fatal("error while loading index file in logdir");
		ret = save_idx_file(idx_filename, NULL);
		if (ret < 0) fatal("cannot save index file");
		e = NULL;
	}

	first_idx_entry = e;
	while (e) {
		log = xmalloc(sizeof(struct log));
		log->idx = e;
		log->ts_fd = -1;
		log->lg_fd = -1; 
		hash = djb_hash(e->prefix, strlen(e->prefix), DJB_HASH_MAGIC);

		/* build up the list of available prefixes */
		pfxid = prefixids[hash % HASHTABLE_SIZE];
		while (pfxid && strcmp(pfxid->prefix, e->prefix)) {
			pfxid = pfxid->next;
		}
		/* save the highest found id */
		if (pfxid && e->id > pfxid->id) {
			debug("updated prefix for %s with id=%x (old=%x)",
				e->prefix, e->id, pfxid->id);
			pfxid->id = e->id;
		}
		/* new prefix */
		else {
			debug("added new prefix for %s with id=%x",
				e->prefix, e->id);
			pfxid = xmalloc(sizeof(struct prefixid));
			strcpy(pfxid->prefix, e->prefix);
			pfxid->id = e->id;
		}

		/* insert to front of the hash table */
		pfxid->next = prefixids[hash % HASHTABLE_SIZE];
		prefixids[hash % HASHTABLE_SIZE]=pfxid;

		/* for the log table index mix in the id for the hash */
		hash = djb_hash((char *)&e->id, sizeof(e->id), hash);

		/* insert to front of the hash table */
		log->next = logs[hash % HASHTABLE_SIZE];
		logs[hash % HASHTABLE_SIZE] = log;

		last_idx_entry = e;
		e = e->next;
	}

	return 0;
}

static void
handle_sigterm(int sig)
{
	signal_received = sig;
}

static void
handle_sigint(int sig)
{
	signal_received = sig;
}

static void
usage(const char * arg0)
{
	fprintf(stderr, "ptlogd - %s\n\n",  ptu_version);
	fprintf(stderr, "%s <options>\n\n", arg0);
	fprintf(stderr, "This is the main logging daemon which should be");
	fprintf(stderr, " running so\nthe other utilities can connect");
	fprintf(stderr, " to it. The default logdir\nis $HOME/ptulogs");
	fprintf(stderr, " but it can be changed by setting PTU_LOGDIR\n");
	fprintf(stderr, "in the shell's environment.\n\n");
	fprintf(stderr, "-f                  stay in foreground\n");
	fprintf(stderr, "-h                  this screen\n");
	fprintf(stderr, "\n");
	fflush(stderr);
	exit(EXIT_FAILURE);
}

int
main(int argc, char ** argv)
{
	struct sigaction sa;
	struct taia now, res;
	struct pollfd fds[MAX_NRCLIENTS+1];
	struct client * c, * prev;
	struct sockaddr_un sun;
	size_t avail;
	socklen_t len;
	int fd, cfd, ret, off, i, remove, foreground;

	foreground = 0;
	while ((i=getopt(argc, argv, "h")) != -1) {
		switch(i) {
		case 'f':
			foreground = 1;
			break;
		case 'h':
		default:
			usage(argc > 0 ? argv[0] : "(unknown)");
		}
	}

	/* XXX: if we're going to the background we need to
	   make sure that stdin, stdout and stderr are opened
	   so we can be sure fd's for anytihng else >= 3 or else
	   we run into problems with f.e. the debug output */

	/* install signal handlers */
	signal_received = 0;
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = &handle_sigterm;
	if (sigaction(SIGTERM, &sa, NULL) < 0) pfatal("sigaction");
	sa.sa_handler = &handle_sigint;
	if (sigaction(SIGINT, &sa, NULL) < 0) pfatal("sigaction");

	/* reset global static variables */
	memset(logs, 0, sizeof(logs));
	memset(clients, 0, sizeof(clients));
	memset(prefixids, 0, sizeof(prefixids));
	first_idx_entry = last_idx_entry = NULL;

	logdir = xstrdup(ptu_logdir());
	ret = open_logdir();
	if (ret < 0) fatal("error while trying to open logdir");

	/* acquire and listen on UNIX socket */
	if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
		fatal("can't acquire socket: already running?");
	}
	sun.sun_family = AF_UNIX;
	strcpy(sun.sun_path, PTU_SOCKET);
	len = strlen(sun.sun_path) + sizeof(sun.sun_family);
	sun.sun_path[0]=0;
	if (bind(fd, (struct sockaddr *)&sun, len) < 0) {
		fatal("can't bind to socket: already running?");
	}
	if (listen(fd, 1) < 0) {
		fatal("can't listen to socket: already running?");
	}

	if (!foreground) {
		/* XXX: daemonize into background here */
	}

	fds[0].fd = fd;
	fds[0].events = POLLIN;
	off = 1;
	client_cnt = 0;

	/* main event loop */
	while (1) {
		ret = poll(fds, off, 1000);

		taia_now(&now);
		taia_diff(&last_idx_save, &now, &res);
		if (res.sec.x > IDX_SAVETIMEOUT) {
			ret = save_idx_file(idx_filename, first_idx_entry);
			if (ret < 0) pfatal("error while saving idx file");
		}
		
			

		/* bail out */
		if (signal_received) {
			ret = close_logdir();
			if (ret < 0) fatal("error while closing logdir");
			break;
		}

		/* handle the clients */
		for (i=1;i<off;i++) {
			fd = fds[i].fd;
			if (fd == -1 || !(fds[i].revents & POLLIN))
				continue;

			/* find client reference in hash table */
			prev = NULL;
			c = clients[fd % HASHTABLE_SIZE];
			while (c && c->fd != fd) {
				c = c->next;
				prev = c;
			}
			if (!c) fatal("cannot find client");

			/* If there's data to be read handle it. Remove the
			   client if there's no data available to be read 
			   or if the client misbehaved or simply
			   disconnected. */
			avail = fd_ravail(fd);
			if (avail) {
				remove = 0;
				buffer_fd_append(c->buf, fd, avail);
				handle_msg(c, &remove);
			}

			/* Remove the client if it disconnected or if it
			   misbehaved. */
			if (!avail || remove) {
				debug("removing client");
				fd_close(fds[i].fd);
				fds[i].fd = -1;
				fds[i].events = 0;
				client_cnt--;
				buffer_free(c->buf);	
				if (prev) {
					prev->next = c->next;
				}
				else {
					clients[fd % HASHTABLE_SIZE] = NULL;
				}
				free(c);
				continue;
			}
		}

		/* new connection */
		if (fds[0].revents == POLLIN && client_cnt < MAX_NRCLIENTS) {	
			len = sizeof(sun);
			cfd = accept(fds[0].fd, (struct sockaddr *)&sun, &len);
			client_cnt++;

			c = xmalloc(sizeof(struct client));
			
			/* insert client to front of hash table entry */
			c->next = clients[cfd % HASHTABLE_SIZE];
			clients[cfd % HASHTABLE_SIZE] = c;
			c->fd = cfd;
			c->buf = buffer_new();

			if (off < MAX_NRCLIENTS) i = off++;
			else {
				/* find a free pollfd */
				for (i=1;i<off;i++) {
					if (fds[i].fd == -1) break;
				}
			}
			fds[i].fd = cfd;
			fds[i].events = POLLIN;
			client_cnt++;
		}
	}

	/* cleanup */
	exit(EXIT_SUCCESS);
}
