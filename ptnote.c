#include "ptu.h"
#include "buffer.h"
#include "utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void
usage(const char * arg0)
{
	fprintf(stderr, "ptnote - %s\n\n",  ptu_version);
	fprintf(stderr, "%s <argument>\n\n", arg0);
	fprintf(stderr, "Logs a note containing argument\n\n");
	fprintf(stderr, " Example: $ %s \"this is a note\"\n\n", arg0);
	fprintf(stderr, "If the first argument is set to - it will read from");
	fprintf(stderr, "\nstandard input until EOF is reached.\n\n");
	fprintf(stderr, " Example: $ cat input.txt | %s -\n", arg0);
	fprintf(stderr, "\n");
	fflush(stderr);
	exit(EXIT_FAILURE);
}

int
main(int argc, char ** argv)
{
	struct buffer * buf;
	char tmp[4096];
	struct ptu_ctx ctx;
	size_t ret;
	int c;
	
	if (argc != 2) {
		usage(argc > 0 ? argv[0] : "(unknown)");
	}

	while ((c=getopt(argc, argv, "h")) != -1) {
		switch(c) {
		case 'h':
		default:
			usage(argc > 0 ? argv[0] : "(unknown)");
		}
	}

	if (ptu_register("note", &ctx) < 0)
		fatal("cannot register at ptlogd");
	
	if (argv[1][0] == '-' && strlen(argv[1]) == 1) {
		buf = buffer_new();
		while (!feof(stdin)) {
			ret = fread(tmp, 1, sizeof(tmp), stdin);
			if (!ret) break;
			buffer_append(buf, tmp, ret);
		}
		ptu_log(&ctx, buf->data + buf->roff, buffer_avail(buf), 0);
		buffer_free(buf);
	}
	else {
		if (ptu_log(&ctx, argv[1], strlen(argv[1]), 0) < 0)
			fatal("error while logging");
	}
		
	exit(EXIT_SUCCESS);
}
