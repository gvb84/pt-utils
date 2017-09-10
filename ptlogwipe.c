#include "ptu.h"
#include "utils.h"

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

static void
usage(const char * arg0)
{
	fprintf(stderr, "ptlogwipe - %s\n\n",  ptu_version);
	fprintf(stderr, "%s [options] <time>\n\n", arg0);
	fprintf(stderr, "-h                  this screen\n");
	fprintf(stderr, "\n");
	fflush(stderr);
	exit(EXIT_FAILURE);
}

int
main(int argc, char ** argv)
{
	char * logdir = NULL;
	int c;

	while ((c=getopt(argc, argv, "hl:")) != -1) {
		switch (c) {
		case 'l':
			logdir = optarg;
			break;
		case 'h':
		default:
			usage(argc > 0 ? argv[0] : "(unknown)");
		}
	}

	if (!logdir) logdir = xstrdup(ptu_logdir());

	free(logdir);
}
