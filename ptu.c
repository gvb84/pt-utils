#include "ptu.h"
#include "buffer.h"
#include "utils.h"

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <sys/un.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>

char * ptu_version = "pt-utils v" PTU_VERSION " <gvb@santarago.org>";

int
ptu_log(struct ptu_ctx * ctx, void * buf, size_t len, int notify_cycle)
{
	size_t attempts;
	struct ptu_msg msg;

	if (!ctx || !buf || !len) return -1;
	
	attempts = 0;
again:
	attempts++;
	msg.type = PTU_MSG_LOG;
	msg.len = len;
	if (send(ctx->fd, &msg, sizeof(struct ptu_msg), 0) < 0)
		return -1;
	if (send(ctx->fd, buf, len, 0) < 0)
		return -1;
	if (recv(ctx->fd, &msg, sizeof(struct ptu_msg), 0) < 0)
		return -1;
	if (!notify_cycle && attempts <= 1 && msg.type == PTU_MSG_CYCLE) {
		debug("logs cycled so resend the log entry");
		goto again;
	}
	return msg.type;
}

int
ptu_register(const char * prefix, struct ptu_ctx * ctx)
{
	char buf[PTU_MAX_PREFIXLEN + sizeof(struct ptu_msg)];
	struct ptu_msg * msg;
	struct sockaddr_un sun;
	size_t pfxlen;
	socklen_t len;
	uint32_t id;
	int fd;
	
	if (!prefix || !ctx || (pfxlen = strlen(prefix)) > PTU_MAX_PREFIXLEN)
		 return -1;

	if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0)
		return -1;

	sun.sun_family = AF_UNIX;
	strcpy(sun.sun_path, PTU_SOCKET);
	len = strlen(sun.sun_path) + sizeof(sun.sun_family);
	sun.sun_path[0]=0;

	if (connect(fd, (struct sockaddr *)&sun, len) < 0)
		return -1;

	msg = (struct ptu_msg *)buf;
	msg->type = PTU_MSG_REGISTER;
	msg->len = pfxlen;
	memcpy(buf+sizeof(struct ptu_msg), prefix, pfxlen);

	if (send(fd, msg, sizeof(struct ptu_msg)+pfxlen, 0) < 0)
		return -1;

	if (recv(fd, msg, sizeof(struct ptu_msg), 0) < 0)
		return -1;
	if (msg->type != PTU_MSG_OK || msg->len != sizeof(uint32_t)) return -1;
	if (recv(fd, &id, msg->len, 0) < 0)
		return -1;

	ctx->id = id;
	ctx->fd = fd;
	
	return 0;
}

inline static int
parse_idx_line(const char * line, struct idx_entry * e)
{
	char t0_hex[TAIA_PACK*2+1], t1_hex[TAIA_PACK*2+1];
	char filename[PTU_MAX_IDXLINELEN], prefix[PTU_MAX_PREFIXLEN+1];
	uint32_t ts_filesz, lg_filesz, ts_hash, lg_hash, id, no;
	int ret;

	if (!line || !e || strlen(line) > PTU_MAX_IDXLINELEN)
		return -1;

	ret = sscanf(line, "%32[^,],%32[^,],%[^,],%u,%x,%u,%x", 
		t0_hex, t1_hex,
		filename,
		&ts_filesz, &ts_hash,
		&lg_filesz, &lg_hash);
	if (ret != 7) return -1;

	if (hex2bin_inplace(t0_hex, TAIA_PACK<<1) < 0) return -1;
	if (hex2bin_inplace(t1_hex, TAIA_PACK<<1) < 0) return -1;

	ret = sscanf(filename, "%16[^-]-%x-%u", prefix, &id, &no);
	if (ret != 3) return -1;

	strncpy(e->prefix, prefix, PTU_MAX_PREFIXLEN);
	e->id = id;
	e->no = no;
	e->ts_filesz = ts_filesz;
	e->lg_filesz = lg_filesz;
	e->ts_hash = ts_hash;
	e->lg_hash = lg_hash;
	taia_unpack(t0_hex, &e->t0);
	taia_unpack(t1_hex, &e->t1);
	
	return 0;
}


int
ptu_load_idxfile(char * logdir, struct idx_entry ** res)
{
	struct idx_entry * e, *first, *last;
	struct stat st;
	char linebuf[PTU_MAX_IDXLINELEN+1];
	char * filename;
	struct buffer * buf;
	size_t off;
	int fd, ret;

	filename = xmalloc(strlen(logdir)+2+strlen(PTU_INDEXNAME));
	snprintf(filename, strlen(logdir)+2+strlen(PTU_INDEXNAME), "%s/%s",
		logdir, PTU_INDEXNAME);

	fd = open(filename, O_RDONLY);
	free(filename);
	if (fd < 0) return -1;

	if (fstat(fd, &st) < 0) {
		fd_close(fd);
		return -1;
	}

	if (st.st_size == 0) {
		fd_close(fd);
		*res = NULL;
		return 0;
	}

	buf = buffer_new();
	buffer_fd_append(buf, fd, st.st_size);

	first = last = NULL;
	do {
		ret = buffer_findchar(buf, '\n', &off);
		if (ret < 0 || off > PTU_MAX_IDXLINELEN) {
			buffer_free(buf);
			fd_close(fd);
			return -1;
		}

		buffer_consume(buf, linebuf, off+1);
		linebuf[off] = 0;

		e = xmalloc(sizeof(struct idx_entry));
		ret = parse_idx_line(linebuf, e);
		if (ret < 0) {
			free(e);
			e = first;
			/* clean up all previously allocated entries */
			while (e) {
				last = e;
				e = e->next;
				free(last);
			}
			buffer_free(buf);
			fd_close(fd);
			return -1;
		}
		e->next = NULL;
		if (!first) {
			first = last = e;
		}
		else {
			last->next = e;
			last = e;
		}	
	} while (buffer_avail(buf) > 0);

	buffer_free(buf);
	*res = first;
		
	fd_close(fd);
	return 0;
}

void
ptu_free_idxfile(struct idx_entry * idx)
{
	struct idx_entry * tmp;

	if (!idx) fatal("ptu_free_idxfile");

	while (idx) {
		tmp = idx->next;
		free(idx);
		idx = tmp;
	}
}

int
ptu_open_logfile(const char * logdir, struct idx_entry * idx)
{
	size_t fnlen;
	char * fn;
	int fd;

	if (!idx) return -1;
	if (!logdir) logdir = ptu_logdir();

	/* construct filename of logfile */
	fnlen = strlen(idx->prefix) + strlen("/_00000000_0000.log") + strlen(logdir) + 1;
	fn = xmalloc(fnlen);
	snprintf(fn, fnlen, "%s/%s_%.8x_%.4u.log",
		logdir,
		idx->prefix, 
		idx->id, idx->no);	

	fd = open(fn, O_RDONLY);
	if (fd < 0) {
		free(fn);
		return -1;
	}
	free(fn);
	fd_set_cloexec(fd);
	return fd;
}

int
ptu_open_tsdfile(const char * logdir, struct idx_entry * idx)
{
	size_t fnlen;
	char * fn;
	int fd;

	if (!idx) return -1;
	if (!logdir) logdir = ptu_logdir();

	/* construct filename of logfile */
	fnlen = strlen(idx->prefix) + strlen("/_00000000_0000.log") + strlen(logdir) + 1;
	fn = xmalloc(fnlen);
	snprintf(fn, fnlen, "%s/%s_%.8x_%.4u.tsd",
		logdir,
		idx->prefix, 
		idx->id, idx->no);	

	fd = open(fn, O_RDONLY);
	if (fd < 0) {
		free(fn);
		return -1;
	}
	free(fn);
	fd_set_cloexec(fd);
	return fd;
}

char *
ptu_logdir(void)
{
	static char buf[4096];
	const char * logdir, * home;
	size_t len;
	int ret;

	logdir = getenv("PTU_LOGDIR");
	if (logdir) {
		len = strlen(logdir);
		if (len >= sizeof(buf)) {
			fatal("PTU_LOGDIR too long");
		}
		memcpy(buf, logdir, len); 
		buf[len] = 0;
	}
	else {
		home = getenv("HOME");
		if (!home) pfatal("$HOME not set");
		ret = snprintf(buf, sizeof(buf)-1, "%s/%s",
			home, PTU_LOGDIR);
		if ((size_t)ret >= sizeof(buf)) fatal("$HOME too long");
	}
	return buf;
}

int
ptu_open_files(const char * logdir, struct idx_entry * idx,
	int * logfd, int * tsfd)
{
	int l, t;

	if (!idx || !logfd || !tsfd) return -1;	

	l = ptu_open_logfile(logdir, idx);
	if (l == -1) return -1;	

	t = ptu_open_tsdfile(logdir, idx);
	if (t == -1) return -1;

	*logfd = l;
	*tsfd = t;

	return 0;	
}

int
ptu_filter(struct idx_entry * idx, char * logdir, char * prefix,
	struct taia * start, struct taia * end,
	int (*cb)(int, struct taia *, uint32_t, uint32_t, uint32_t))
{
	int tsfd, logfd, ret;
	uint32_t tsdoff, tsdlen;
	size_t bread;
	char tsdbuf[TAIA_PACK + 8];
	struct taia t;
	
	if (!idx || !prefix) return -1;	

	while (idx) {

		/* if the prefix doesn't match ignore the entry */
		if (strcmp(idx->prefix, prefix)) {
			idx = idx->next;
			continue;
		}

		/* if there's a start time supplied and the start time is
 		   not less than or equal to the start time of the entry
		   ignore it */
		if (start && !taia_leq(start, &idx->t0)) {
			idx = idx->next;
			continue;
		}
		/* if there's an end time supplied and the end time is
		   less than or equal to the end time of the entry ignore
		   it. */
		if (end && taia_leq(end, &idx->t1)) {
			idx = idx->next;
			continue;
		}

		ret = ptu_open_files(logdir, idx, &logfd, &tsfd);
		if (ret < 0) fatal("cannot open log or tsd file");

		while (1) {
			bread = fd_read(tsfd, tsdbuf, TAIA_PACK+8);
			if (!bread) break;	

			// XXX need to check the timestamp here too

			taia_unpack(tsdbuf, &t);

			tsdlen = ntohl(
				*(uint32_t *)(tsdbuf + TAIA_PACK)
			);
			tsdoff = ntohl(
				*(uint32_t *)(tsdbuf + TAIA_PACK + 4)
			);

			cb(logfd, &t, tsdoff, tsdlen, idx->id);
		}

		fd_close(logfd);
		fd_close(tsfd);

		idx = idx->next;
	}
	return 0;
}
