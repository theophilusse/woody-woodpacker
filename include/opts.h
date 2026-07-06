#ifndef OPTS_H
# define OPTS_H

# include "woody.h"
# include <getopt.h>

static struct option long_opts[] = {
    { "help",   no_argument, 0, '?' },
    { "verbose", no_argument, 0, 'v' },
    { "antidebug",    required_argument, 0, 'd'  },
    { "int3trap",   required_argument, 0, 'i'   },
    { "lde", required_argument, 0, 'l'  },
    { 0, 0, 0, 0 }  // terminateur de tableau pour getopt_long
};

t_opts  parse_args(int argc, char **argv);

#endif
