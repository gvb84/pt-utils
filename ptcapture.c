#include "ptu.h"
#include "utils.h"
#include "buffer.h"

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <arpa/inet.h>

#include <pcap/pcap.h>

#define DEFAULT_SNAPLEN		65535
#define MAXSNAPLEN		262144	/* as in libpcap */

static pcap_t * pcap = NULL;
static int hex_output = 0;
static long int snaplen = 0;
static uint32_t linktype = 0;
static unsigned long long pkt_count = 0;
static struct ptu_ctx ctx;

static void
usage(const char * arg0)
{
	fprintf(stderr, "ptcapture - %s\n\n",  ptu_version);
	fprintf(stderr, "%s [options] -i <iface> [expression]\n\n", arg0);
	fprintf(stderr, "This tcpdump-like utility allows one to capture ");
	fprintf(stderr, "packets and log them. One can\nsupply ");
	fprintf(stderr, "a BPF expression to filter for specific packets.\n\n");
	fprintf(stderr, "-i <iface>          network interface\n");
	fprintf(stderr, "-p                  promiscuous mode\n");
	fprintf(stderr, "-x                  output packets in hex format\n");
	fprintf(stderr, "-s <snaplen>        max length of packets ");
	fprintf(stderr, "to capture\n");
	fprintf(stderr, "-h                  this screen\n");
	fprintf(stderr, "\n");
	fflush(stderr);
	exit(EXIT_FAILURE);
}

static void
packet_handler(unsigned char * user, const struct pcap_pkthdr * h,
	const unsigned char * bytes)
{
	char buf[MAXSNAPLEN + (sizeof(uint32_t) * 2)+sizeof(uint16_t)];
	char * p;
	size_t i, j;
	int ret;

	/* get rid of unused warning */
	if (user) {}
	if (h->caplen > MAXSNAPLEN) fatal("libpcap error: caplen too high");

	pkt_count++;

	/* Sadly we cannot avoid the memcpy's here since we need to log
	   the packet header and the packet contents in one go to avoid
	   storing the header in one file and the contents in another
	   when a log cycle occurs. */

	p = buf + (sizeof(uint32_t) + sizeof(uint16_t));
	*(uint32_t *)p = htonl(h->len);
	memcpy(p + sizeof(uint32_t), bytes, h->caplen);

	/* send packet to ptlogd */
	ret = ptu_log(&ctx, (void *)p, h->caplen + sizeof(uint32_t), 1);

	if (ret == PTU_MSG_CYCLE) {
		/* write out the snap length and the link type as
		   we need that for reconstructing proper pcap files */
		p = buf;

		*(uint32_t *)p = htonl(snaplen);
		*(uint16_t *)(buf+4) = htons(linktype);
		
		ret = ptu_log(&ctx, (void *)p,
			h->caplen + (sizeof(uint32_t)*2+sizeof(uint16_t)), 1);
		if (ret != PTU_MSG_OK) {
			fatal("after log cycle ptu_log failed");
		}
	}

	if (!hex_output) return;

	for (i=0;i<(h->caplen/16);i++) {
		printf("%.5zi  ", i*16);
		for (j=0;j<16&&i*16+j<h->caplen;j++) {
			if (j==8) printf(" ");
			printf("%.2x ", bytes[i*16+j]);
		}
		printf(" ");
		for (j=0;j<16&&i*16+j<h->caplen;j++) {
			printf("%c",
				isprint(bytes[i*16+j])
				?bytes[i*16+j]:'.');
		}
		printf("\n");
	}

	i*=16;
	j = i;
	printf("%.5zi  ", i);
	for(;i<h->caplen;i++) {
		if (!(i%8) && i>j) printf(" ");
		printf("%.2x ", bytes[i]);
	}
	printf(" ");
	for(i=0;i<16-(h->caplen%16);i++) {
		if (i==8) printf(" ");
		printf("   ");
	}
	for(i=j;i<h->caplen;i++) {
		printf("%c", isprint(bytes[i])?bytes[i]:'.');
	}
	printf("\n\n");
}

static void
handle_sig(int sig)
{
	sig = 0; /* get rid of unused warning */
	if (pcap) pcap_breakloop(pcap);	
}

int
main(int argc, char ** argv)
{
	struct buffer * buf;
	struct bpf_program bpf;
	struct sigaction sa;
	char errbuf[PCAP_ERRBUF_SIZE];
	char * interface = NULL, * filter = NULL;
	int c, promiscuous_mode = 0;

	/* install signal handlers */
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = &handle_sig;
	if (sigaction(SIGTERM, &sa, NULL) < 0) pfatal("sigaction");
	sa.sa_handler = &handle_sig;
	if (sigaction(SIGINT, &sa, NULL) < 0) pfatal("sigaction");

	snaplen = DEFAULT_SNAPLEN;

	while ((c=getopt(argc, argv, "hxpi:s:")) != -1) {
		switch (c) {
		case 'x':
			hex_output = 1;
			break;
		case 'p':
			promiscuous_mode = 1;
			break;
		case 's':
			errno = 0;
			snaplen = strtol(optarg, NULL, 10);
			if ((snaplen == LONG_MAX || snaplen == LONG_MIN) 
				&& (errno==ERANGE))
				pfatal("strtol");
			if (snaplen <= 0) fatal("snaplen cannot be <= 0");
			if (snaplen > MAXSNAPLEN)
				fatal("snaplen cannot be > %u", MAXSNAPLEN);
			break;
		case 'i':
			interface = optarg;
			break;
		case 'h':
			usage(argc > 0 ? argv[0] : "(unknown)");
			break;
		default:
			fprintf(stderr, "unknown option specified\n");
			usage(argc > 0 ? argv[0] : "(unknown)");
		}
	}


	/* built up the filter expression if one was supplied */
	if (optind < argc) {
		buf = buffer_new();
		buffer_append(buf, argv[optind], strlen(argv[optind]));
		for (c=optind+1;c<argc;c++) {
			buffer_append(buf, " ", 1);
			buffer_append(buf, argv[c], strlen(argv[c]));
		}
		filter = xmalloc(buffer_avail(buf));
		buffer_consume(buf, filter, buffer_avail(buf));
		buffer_free(buf);
	}

	if (!interface) {
		fprintf(stderr, "no interface specified\n");
		usage(argc > 0 ? argv[0] : "(unknown)");
	}

	if (ptu_register("pcap", &ctx) < 0)
		fatal("cannot register at ptlogd");


	/* open the pcap handle */
	memset(errbuf, 0, sizeof(errbuf));
	pcap = pcap_open_live(interface, snaplen, promiscuous_mode, 0, errbuf);
	if (!pcap) {
		fprintf(stderr, "%s\n", errbuf);
		fatal("error while calling pcap_open_live");
	}
	else if (strlen(errbuf) > 0) {
		/* modern libpcap versions might return warnings in errbuf so
		   just display it to the user */
		fprintf(stderr, "Warning: %s\n", errbuf);
	}

	/* If there's a filter specified compile it to an optimized
	   BPF representation and install it to the pcap handle. */
	if (filter) {
		if (pcap_compile(pcap, &bpf, filter,
			1, PCAP_NETMASK_UNKNOWN) < 0) {

			fprintf(stderr, "error while compiling BPF filter\n");
			fatal("pcap_compile: %s", pcap_geterr(pcap));
		}
		if (pcap_setfilter(pcap, &bpf) < 0) {
			fatal("pcap_setfilter: %s", pcap_geterr(pcap));
		}
		pcap_freecode(&bpf);
	}

	linktype = pcap_datalink(pcap);

	/* Infinite pcap_loop returns -2 when stopped by pcap_breakloop and
	   it will return -1 on error conditions */
	c = pcap_loop(pcap, -1, packet_handler, NULL);
	if (c == -1) {
		fatal("pcap_loop: %s", pcap_geterr(pcap));
	}
	else if (c != -2) {
		fatal("unexpected return value from pcap_loop: %i\n", c);
	}

	if (filter) free(filter);
	pcap_close(pcap);

	/* XXX: pcap_stats() ? */
	printf("%llu packet%s captured\n", 
		pkt_count, (pkt_count==1?"":"s"));

	exit(EXIT_SUCCESS);
}
