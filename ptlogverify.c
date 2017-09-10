#include "ptu.h"
#include "buffer.h"
#include "utils.h"
#include "time.h"
#include "hash.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

static void
usage(const char * arg0)
{
	fprintf(stderr, "ptlogverify - %s\n\n",  ptu_version);
	fprintf(stderr, "%s [logdir]\n\n", arg0);
	fprintf(stderr, "Verifies the supplied logdir or the default ");
	fprintf(stderr, "logdir if no argument is supplied\n");
	fprintf(stderr, "by checking logfile checksums against ");
	fprintf(stderr, "the index and by checking timestamps\nfor ");
	fprintf(stderr, "internal consistency.\n");
	fprintf(stderr, "\n");
	fflush(stderr);
	exit(EXIT_FAILURE);
}

static inline uint32_t 
hash_logfile(int fd)
{
	char buf[4096];
	uint32_t hash = DJB_HASH_MAGIC;
	size_t ret;

	if (lseek(fd, 0, SEEK_SET) < 0) pfatal("lseek");
	do {
		ret = fd_read(fd, buf, sizeof(buf));
		if (ret > 0) hash = djb_hash(buf, ret, hash);
	} while (ret > 0);
	return hash;
}

static inline uint32_t
check_tsdfile(const char * fn, int fd, size_t filesz,
	struct taia * t0, struct taia * t1)
{
	struct taia t;
	uint32_t hash = DJB_HASH_MAGIC;
	uint32_t off, size;
	char buf[TAIA_PACK + 8];
	size_t ret, i;

	if (lseek(fd, 0, SEEK_SET) < 0) pfatal("lseek");
	i = 0;
	do {
		ret = fd_read(fd, buf, sizeof(buf));
		if (ret && ret < sizeof(buf))
			fatal("unexpected return from fd_read)");


		hash = djb_hash(buf, ret, hash);

		/* check size and offset entries */
		size = ntohl(*(uint32_t *)(buf+TAIA_PACK));
		off = ntohl(*(uint32_t *)(buf+TAIA_PACK+4));
		if (off > filesz) {
			fatal("entry #%u in %s, off:%u,sz:%u has offset "
				"bigger than file\n", i, fn, off, size);
		}
		else if (off+size < off || off+size < size) {
			fatal("entry #%u in %s, (off:%u,sz:%u) has "
				"int overflow",
				i, fn, off, size);
		}
		else if (off+size > filesz) {
			fatal("entry #%u in %s (off:%u, sz:%u) has "
				"offset bigger than file\n",
				i, fn, off, size);
		}

		/* check timestamp data */
		taia_unpack(buf, &t);
		if (!taia_leq(t0, &t))
			fatal("entry #%u in %s, off:%u,sz:%u has timestamp "
				"before index t0\n",
				i, fn, off, size);
		if (taia_less(t1, &t))
			fatal("entry #%u in %s, off:%u,sz:%u has timestamp "
				"before index t1\n",
				i, fn, off, size);
		i++;
	} while (ret > 0);
	return hash;	
}

int
main(int argc, char ** argv)
{
	struct idx_entry * idx, * idxnext;
	struct stat st;
	char * fn, * dir;
	size_t fnlen;
	uint32_t hash;
	int ret, fd;

	if (!argc || argc > 2) {
		usage(argc > 0 ? argv[0] : "(unknown)");
	}

	while ((ret=getopt(argc, argv, "h")) != -1) {
		switch(ret) {
		case 'h':
		default:
			usage(argc > 0 ? argv[0] : "(unknown)");
		}
	}

	dir = (argc == 1 ? ptu_logdir() : argv[1]);
	ret = ptu_load_idxfile(dir, &idx);
	if (ret < 0) fatal("cannot load index file");

	while (idx) {

		/* construct filename of logfile; needed for proper output
		   to alert user when and where in which files errors are
		   found otherwise we could just use ptu_open_logfile */
		fnlen = strlen(idx->prefix) + strlen("/_00000000_0000.log") 
			+ strlen(dir) + 1;
		fn = xmalloc(fnlen);
		snprintf(fn, fnlen, "%s/%s_%.8x_%.4u.log", dir,
			idx->prefix, 
			idx->id, idx->no);	

		/* open logfile */
		fd = ptu_open_logfile(dir, idx);

		/* check size of the log file */
		if (fstat(fd, &st) < 0) pfatal("fstat");
		if ((uint32_t)st.st_size != idx->lg_filesz)
			fatal("filesize mismatch for %s", fn);

		/* check hash of the log file */
		hash = hash_logfile(fd);
		if (hash != idx->lg_hash)
			fatal("hash mismatch for %s: 0x%x (expected: 0x%x)",
				fn, hash, idx->lg_hash);
		fd_close(fd);

		/* open the timestamp file */
		fd = ptu_open_tsdfile(dir, idx);

		/* check size of the timestamp file */
		if (fstat(fd, &st) < 0) pfatal("fstat");
		if ((uint32_t)st.st_size != idx->ts_filesz)
			fatal("filesize mismatch for %s", fn);
		if (idx->ts_filesz % (TAIA_PACK+8))
			fatal("incorrect filesize for %s (should be multiple "
				"of %u)\n", fn, (TAIA_PACK+8));

		hash = check_tsdfile(fn, fd, idx->lg_filesz, 
			&idx->t0, &idx->t1);
		if (hash != idx->ts_hash)
			fatal("hash mismatch for %s: 0x%x (expected: 0x%x)",
				fn, hash, idx->ts_hash);

		free(fn);
		fd_close(fd);
		idxnext = idx->next;
		free(idx);
		idx = idxnext;
	}	
}
