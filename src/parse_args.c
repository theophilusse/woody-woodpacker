#include "woody.h"

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
    while ((opt = getopt_long(argc, argv, "vi:m:p:s:q:N:t:l:?", long_opts, &longindex)) != -1)
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
					fprintf(stderr, "woody-woodpacker: invalid argument: '%s' (0-1)\n", optarg);
					exit(1);
				}
				break;
			case 'd':
				opts.use_antidebug = atoi(optarg);
				if (opts.use_antidebug != 0 && opts.use_antidebug != 1)
				{
					fprintf(stderr, "woody-woodpacker: invalid argument: '%s' (0-1)\n", optarg);
					exit(1);
				}
				break;
			case 'l':
				opts.use_lde = atoi(optarg);
				if (opts.use_lde != 0 && opts.use_lde != 1)
				{
					fprintf(stderr, "woody-woodpacker: invalid argument: '%s' (0-1)\n", optarg);
					exit(1);
				}
				break;
			case '?':
				print_usage();
				exit(0);
				break;
        }
    }
    if (optind >= argc)
        return opts;
    opts.file = argv[optind];
    return opts;
}
