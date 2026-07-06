#include "woody.h"

static struct option long_opts[] = {
    { "help",   no_argument, 0, 'h' },
    { "verbose", no_argument, 0, 'v' },
    { "antidebug",    required_argument, 0, 'd'  },
    { "int3trap",   required_argument, 0, 'i'   },
    { "lde", required_argument, 0, 'l'  },
    { 0, 0, 0, 0 }  // terminateur de tableau pour getopt_long
};

struct s_opts default_opts(void)
{
	struct s_opts opts;

	memset(&opts, 0, sizeof(opts));
	opts.verbose = 0;
	opts.use_antidebug = 1;
    opts.use_int3_trap = 1;
    opts.use_lde = 1;
	opts.file = NULL;
	return opts;
}

t_opts  parse_args(int argc, char **argv)
{
    t_opts  opts;
    int     opt;
    int     longindex;

	opts = default_opts();
	while ((opt = getopt_long(argc, argv, "vd:i:l:", long_opts, &longindex)) != -1)
    {
		switch (opt)
        {
            case 'v':
				opts.verbose = 1;
				break;
			case 'i':
				opts.use_int3_trap = atoi(optarg);
				if (opts.use_int3_trap != 0 && opts.use_int3_trap != 1)
				{
					fprintf(stderr, "%s: invalid argument: '%s' (0-1)\n", argv[0], optarg);
					exit(1);
				}
				break;
			case 'd':
				opts.use_antidebug = atoi(optarg);
				if (opts.use_antidebug != 0 && opts.use_antidebug != 1)
				{
					fprintf(stderr, "%s: invalid argument: '%s' (0-1)\n", argv[0], optarg);
					exit(1);
				}
				break;
			case 'l':
				opts.use_lde = atoi(optarg);
				if (opts.use_lde != 0 && opts.use_lde != 1)
				{
					fprintf(stderr, "%s: invalid argument: '%s' (0-1)\n", argv[0], optarg);
					exit(1);
				}
				break;
			case '?':
				usage(argv[0]);
				exit(1);
				break;
        }
    }
    if (optind >= argc)
        return opts;
    opts.file = argv[optind];
    return opts;
}
