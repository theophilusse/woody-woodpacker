#ifndef OPTS_H
# define OPTS_H

#include <getopt.h>

typedef struct s_opts {
    int     verbose;      // -v
    char    *iface;       // -i
    int     max_ttl;      // -m
    int     port;         // -p
    char    *src_addr;    // -s
    int     n_queries;    // -q
    int     s_queries;    // -N
    int     tos;          // -t
    int     flow_label;   // -l
    char    *hostname;    // hostname
    struct in_addr local_ip; // adresse IP locale
    char    *iface_name;
} t_opts;

typedef struct s_opts
{
    int     verbose;
    int     use_antidebug;
    int     use_int3_trap;
    int     use_lde;
    char    *file;
}   s_opts;

static struct option long_opts[] = {
    { "help",   no_argument, 0, '?' },
    { "verbose", no_argument, 0, 'v' },
    { "iface",    required_argument, 0, 'i'  },
    { "max_ttl",   required_argument, 0, 'm'   },
    { "port", required_argument, 0, 'p'  },
    { "src_addr", required_argument, 0, 's'  },
    { "n_queries", required_argument, 0, 'q'  },
    { "s_queries", required_argument, 0, 'N'  },
    { "tos", required_argument, 0, 't'  },
    { "flow_label", required_argument, 0, 'l'  },
    { 0, 0, 0, 0 }  // terminateur de tableau pour getopt_long
};

#endif
