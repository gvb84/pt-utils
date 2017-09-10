#include "ptu.h"
#include "utils.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#include <pcap/pcap.h>

static int outfd;
static char * logdir;

static void
usage(const char * arg0)
{
	fprintf(stderr, "ptlogextract - %s\n\n",  ptu_version);
	fprintf(stderr, "%s [options] <time>\n\n", arg0);
	fprintf(stderr, "This utility extracts data of a certain type from");
	fprintf(stderr, " the logfiles. The time range\n");
	fprintf(stderr, "can be specified ...<todo>\n\n");
	fprintf(stderr, "-t <type>           ");
	fprintf(stderr, "type of data to extract (only \"pcap\" supported)\n");
	fprintf(stderr, "-l <logdir>         ");
	fprintf(stderr, "logdir to use if different from default logdir)\n");
	fprintf(stderr, "-o <output>         ");
	fprintf(stderr, "output filename (default is \"-\" for stdout)\n");
	fprintf(stderr, "-h                  this screen\n");
	fprintf(stderr, "\n");
	fflush(stderr);
	exit(EXIT_FAILURE);
}

int
pcap_filter_callback(int logfd, struct taia * t,
	uint32_t off, uint32_t len, uint32_t id)
{
	static int id_changed = -1;
	static uint32_t last_id;
	static uint32_t iface_id = 0;
	uint32_t origlen, paddinglen, blocklen, snaplen;
	uint16_t linktype;
	uint64_t ts;
	size_t toread, bread;
	char buf[65535];

	id_changed = (id_changed == -1 ? 1 : !(last_id == id));
	if (id_changed) {
		last_id = id;
		iface_id++;

	/* Interface Descrption Block (IBB)
	    0                   1                   2                   3
	    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	   +---------------------------------------------------------------+
	 0 |                    Block Type = 0x00000001                    |
	   +---------------------------------------------------------------+
	 4 |                      Block Total Length                       |
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 8 |           LinkType            |           Reserved            |
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	12 |                            SnapLen                            |
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	16 /                                                               /
	   /                      Options (variable)                       /
	   /                                                               /
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   |                      Block Total Length                       |
	   +---------------------------------------------------------------+
	*/

		fd_read(logfd, &snaplen, 4);
		fd_read(logfd, &linktype, 2);
		*(uint32_t *)buf = 0x1;
		*(uint32_t *)(buf + 4) = 20; 
		*(uint16_t *)(buf + 8) = ntohs(linktype);
		*(uint16_t *)(buf + 10) = 0x0;
		*(uint32_t *)(buf + 12) = ntohl(snaplen);
		*(uint32_t *)(buf + 16) = 20;

		id_changed = 0;

		fd_write(outfd, buf, 20);

		off += (sizeof(uint32_t) * 2);
		len -= (sizeof(uint32_t) * 2);
	}

	if (lseek(logfd, off, SEEK_SET) == -1) {
		pfatal("lseek");
	}

	if (len < 4) pfatal("invalid data");

	/* read original length of packet (captured length might be less) */
	len -= 4;
	fd_read(logfd, &origlen, 4);
	origlen = ntohl(origlen);

	/* Enhanced Packet Block (EPB) 
	  0                   1                   2                   3
	   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	   +---------------------------------------------------------------+
	 0 |                    Block Type = 0x00000006                    |
	   +---------------------------------------------------------------+
	 4 |                      Block Total Length                       |
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 8 |                         Interface ID                          |
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	12 |                        Timestamp (High)                       |
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	16 |                        Timestamp (Low)                        |
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	20 |                    Captured Packet Length                     |
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	24 |                    Original Packet Length                     |
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	28 /                                                               /
	   /                          Packet Data                          /
	   /              variable length, padded to 32 bits               /
	   /                                                               /
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   /                                                               /
	   /                      Options (variable)                       /
	   /                                                               /
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   |                      Block Total Length                       |
	   +---------------------------------------------------------------+
	*/

	paddinglen = 4-(len % 4);
	blocklen = 32 + len + paddinglen;
	*(uint32_t *)buf = 0x6;
	*(uint32_t *)(buf+4) = blocklen;
	*(uint32_t *)(buf+8) = iface_id-1;

	ts = t->sec.x - 4611686018427387914ULL;
	ts *= 1000000;
	ts += (t->nano/1000);

	*(uint32_t *)(buf+12) = ((uint32_t)((ts >> 32) & 0xffffffff));
	*(uint32_t *)(buf+16) = ((uint32_t)(ts & 0xffffffff));
	*(uint32_t *)(buf+20) = len;
	*(uint32_t *)(buf+24) = origlen;
	fd_write(outfd, buf, 28);

	do {
		if (len > sizeof(buf)) {
			toread = sizeof(buf);
		}
		else {
			toread = len;
		}

		bread = fd_read(logfd, buf, toread);
		fd_write(outfd, buf, bread);

		len -= bread;
	} while(len);

	*(uint32_t *)(buf) = 0;
	fd_write(outfd, buf, paddinglen);

	*(uint32_t *)(buf) = blocklen;
	fd_write(outfd, buf, 4);
	return 0;
}

void
pcap_extract(struct idx_entry * idx,
	struct taia * start, struct taia * end)
{
	char buf[28];

	/*
	    Section Header Block (SHB) 
	   0                   1                   2                   3
	   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	   +---------------------------------------------------------------+
	 0 |                   Block Type = 0x0A0D0D0A                     |
	   +---------------------------------------------------------------+
	 4 |                      Block Total Length                       |
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 8 |                      Byte-Order Magic                         |
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	12 |          Major Version        |         Minor Version         |
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	16 |                                                               |
	   |                          Section Length                       |
	   |                                                               |
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	24 /                                                               /
	   /                      Options (variable)                       /
	   /                                                               /
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   |                      Block Total Length                       |
	   +---------------------------------------------------------------+
	*/
	memset(buf, 0, sizeof(buf));
	*(uint32_t *)buf = 0x0a0d0d0a;
	*(uint32_t *)(buf + 4) = 28;
	*(uint32_t *)(buf + 24) = 28;
	*(uint32_t *)(buf + 8) = 0x1A2B3C4D;
	*(uint16_t *)(buf + 12) = 1;
	*(uint16_t *)(buf + 14) = 0;
	*(uint32_t *)(buf + 16) = 0xffffffff;
	*(uint32_t *)(buf + 20) = 0xffffffff;
	fd_write(outfd, buf, 28);

	ptu_filter(idx, logdir, "pcap", start, end, pcap_filter_callback);
}

int
main(int argc, char ** argv)
{
	struct idx_entry * idx;
	struct taia now, start, end;
	char * type = "pcap", * output = "-";
	const char * timestr = NULL;
	int c;

	while ((c=getopt(argc, argv, "hl:t:o:")) != -1) {
		switch (c) {
		case 'l':
			logdir = optarg;
			break;
		case 't':
			type = optarg;
			break;
		case 'o':
			output = optarg;
			break;
		case 'h':
		default:
			usage(argc > 0 ? argv[0] : "(unknown)");
		}
	}

	if (!type) {
		fprintf(stderr, "no log type specified\n");
		usage(argc > 0 ? argv[0] : "(unknown)");
	}
	else if (strcmp("pcap", type)) {
		fatal("only pcap extraction supported for now");
	}
	if (!output) {
		fprintf(stderr, "no output file specified\n");
		usage(argc > 0 ? argv[0] : "(unknown)");
	}

	if (optind == argc) {
		fprintf(stderr, "no time range specified\n");
		usage(argc > 0 ? argv[0] : "(unknown)");
	}
	else timestr = argv[optind++];

	if (!logdir) logdir = ptu_logdir();

	/* get start time on where to start filtering */
	taia_now(&now);
	taia_now(&end);
	if (timestr_parse(timestr, &start, &now) < 0) {
		fprintf(stderr, "error in time argument\n");
		usage(argc>0?argv[0]:"(unknown)");
	}

	/* open index file */
	if (ptu_load_idxfile(logdir, &idx) < 0) {
		fatal("cannot load index file");
	}

	/* open output file */
	if (strcmp(output, "-")) {
		outfd = open(output, O_CREAT|O_EXCL|O_WRONLY,
			S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH); /* rw-r--r-- */
		if (outfd < 0) pfatal("cannot open output file");
	}
	else {
		outfd = STDOUT_FILENO;
		setvbuf(stdout, NULL, _IONBF, 0);
	}

	if (!strcmp("pcap", type)) pcap_extract(idx, &start, &end);

	ptu_free_idxfile(idx);
	fd_close(outfd);
}
