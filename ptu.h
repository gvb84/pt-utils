#ifndef PTU_H
  #define PTU_H

#define _GNU_SOURCE /* needed for getopt when compiling with -std=c99 */
#define _XOPEN_SOURCE	500
#define _POSIX_SOURCE

#define HAVE_PYTHON 1 /* XXX should come from config */

#include <stdint.h>
#include <stdlib.h>

#include "time.h"

#define PTU_SOCKET		"#blablablabla"
#define PTU_INDEXNAME		"ptu.idx"
#define PTU_LOGDIR		"ptulogs"
#define PTU_MAX_IDXLINELEN	4096
#define PTU_MAX_PREFIXLEN	16
#define PTU_MAX_LOGSIZE		(128 * 1024 * 1024)
#define PTU_MAX_MSGSIZE		(PTU_MAX_LOGSIZE >> 2)

struct ptu_ctx {
	int fd;
	uint32_t id;
};

struct ptu_msg {

#define PTU_MSG_REGISTER	1
#define PTU_MSG_LOG		2
#define PTU_MSG_OK		255
#define PTU_MSG_ERR		254
#define PTU_MSG_CYCLE		253

	uint8_t type;
	uint32_t len;
	unsigned char arg[0];
};

struct idx_entry {
	struct idx_entry * next;
	char prefix[PTU_MAX_PREFIXLEN+1];
	uint32_t id;
	uint32_t no;
	uint32_t ts_filesz;
	uint32_t lg_filesz;
	uint32_t ts_hash;
	uint32_t lg_hash;
	struct taia t0;
	struct taia t1;
};

extern char * ptu_version;

/* API function prototypes */

int ptu_log(struct ptu_ctx *, void *, size_t, int);
int ptu_register(const char *, struct ptu_ctx *);
char * ptu_logdir(void);
int ptu_load_idxfile(char *, struct idx_entry **);
void ptu_free_idxfile(struct idx_entry *);
int ptu_open_logfile(const char *, struct idx_entry *);
int ptu_open_tsdfile(const char *, struct idx_entry *);
int ptu_open_files(const char *, struct idx_entry *, int *, int *);
int ptu_filter(struct idx_entry *, char *, char *,
	struct taia *, struct taia *,
	int (*)(int, struct taia *, uint32_t, uint32_t, uint32_t)
);

#endif
