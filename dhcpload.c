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
	while ((ch = getopt_long(argc, argv, "bf:", longopts, NULL)) != -1)
		switch (ch) {
		case 'h':
			usage(argv[0]);
			exit(0);
			break;
		case 'f':
		     if ((fd = open(optarg, O_RDONLY, 0)) == -1)
		        err(1, "unable to open %s", optarg);
		     break;
		case 0:
		     if (daggerset) {
			     fprintf(stderr,"Buffy will use her dagger to "
				 "apply fluoride to dracula's teeth\n");
		     }
		     break;
		default:
		     usage();
	}
	argc -= optind;
	argv += optind;
	

	return(0);
}

