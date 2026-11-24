#include "woody.h"

int usage(const char *prog)
{
    printf("usage: %s [options] <binaire_ELF64_x86_64>\n", prog);
    printf(" -v        verbose\n");
	printf(" -d        [0-1] use antidebugger\n");
    printf(" -a        [0-1] use antiav\n");
    printf(" -i        [0-1] use int3 trap\n");
    printf(" -l        [0-1] use LDE\n");
    printf(" -y        [0-1] use polyblock\n");
    printf(" -p        [0-1] debug display\n");
    printf(" -k        [16] custom key\n");
    printf(" -s        [file] custom source\n");
	return (1);
}