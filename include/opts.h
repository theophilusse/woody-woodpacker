#ifndef OPTS_H
# define OPTS_H

# include "woody.h"
# include <getopt.h>

typedef struct s_opts
{
    int     verbose;
    int     use_antidebug;
    int     use_int3_trap;
    int     use_lde;
    char    *file;
}   t_opts;

struct option long_opts[] = {
    { "help",   no_argument, 0, '?' },
    { "verbose", no_argument, 0, 'v' },
    { "antidebug",    required_argument, 0, 'd'  },
    { "int3trap",   required_argument, 0, 'i'   },
    { "lde", required_argument, 0, 'l'  },
    { 0, 0, 0, 0 }  // terminateur de tableau pour getopt_long
};

#endif
