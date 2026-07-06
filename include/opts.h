#ifndef OPTS_H
# define OPTS_H

# include "woody.h"
# include <getopt.h>

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

struct option long_opts[] = {
    { "help",   no_argument, 0, '?' },
    { "verbose", no_argument, 0, 'v' },
    { "antidebug",    required_argument, 0, 'd'  },
    { "int3trap",   required_argument, 0, 'i'   },
    { "lde", required_argument, 0, 'l'  },
    { 0, 0, 0, 0 }  // terminateur de tableau pour getopt_long
};

t_opts  parse_args(int argc, char **argv);

#endif
