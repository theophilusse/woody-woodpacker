#include "woody.h"

static struct option long_opts[] = {
    { "help",   no_argument, 0, 'h' },
    { "verbose", no_argument, 0, 'v' },
    { "antidebug",    required_argument, 0, 'd'  },
    { "int3trap",   required_argument, 0, 'i'   },
    { "lde", required_argument, 0, 'l'  },
	{ "debug_display", required_argument, 0, 'p'  },
	{ "custom_key", required_argument, 0, 'k'  },
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
	opts.debug_display = 0;
	opts.file = NULL;
	return opts;
}

static struct s_opts copy_pattern(struct s_opts opts)
{
	char key[32];

	if (strlen(optarg) != 32 || strlen(optarg) % 2 != 0) // verify length hex
	{
		fprintf(stderr, "error: invalid custom_key: '%s'\n", optarg);
		exit(1);
	}
	for (int i = 0; optarg[i]; i++) // verify hex symbols
	{
		if (!((optarg[i] >= '0' && optarg[i] <= '9') ||
			(optarg[i] >= 'a' && optarg[i] <= 'f') ||
			(optarg[i] >= 'A' && optarg[i] <= 'F')))
		{
			fprintf(stderr, "error: invalid custom_key: '%s'\n", optarg);
			exit(1);
		}
	}
	strncpy(key, optarg, sizeof(key) - 1);
	key[sizeof(key) - 1] = '\0';
	
	size_t plen = strlen(key) / 2;
	for (size_t j = 0; j < plen; j++)
	{
		char byte[3] = {key[j * 2], key[j * 2 + 1], '\0'};
		opts->custom_key[j] = (uint8_t)strtol(byte, NULL, 16);
	}
	return opts;
}

t_opts  parse_args(int argc, char **argv)
{
    t_opts  opts;
    int     opt;
    int     longindex;

	opts = default_opts();
	while ((opt = getopt_long(argc, argv, "vd:i:l:p:k:", long_opts, &longindex)) != -1)
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
			case 'p':
				opts.debug_display = atoi(optarg);
				if (opts.debug_display != 0 && opts.debug_display != 1)
				{
					fprintf(stderr, "%s: invalid argument: '%s' (0-1)\n", argv[0], optarg);
					exit(1);
				}
				break;
			case 'k':
				opts = copy_pattern(opts);
				opts.use_custom_key = 1;
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
