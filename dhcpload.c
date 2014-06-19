#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>

#include <getopt.h>



void usage(char *progname) {
	printf("Usage:  %s [options]\n", progname);
	printf("\t-h\t--help\tHelp (this message\n");
}


int main(int argc, char **argv) {


	int bflag, ch, fd;

	/* options descriptor */
	static struct option longopts[] = {
		{ "help",       no_argument,            NULL,           'h' },
		{ "fluoride",   required_argument,      NULL,           'f' },
		{ NULL,         0,                      NULL,           0 }
	};

	bflag = 0;
	while ((ch = getopt_long(argc, argv, "h", longopts, NULL)) != -1)
		switch (ch) {
		case 'h':
			usage(argv[0]);
			exit(0);
			break;
		default:
		     usage(argv[0]);
	}
	argc -= optind;
	argv += optind;
	

	return(0);
}

