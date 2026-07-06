#include "woody.h"

int usage(const char *prog)
{
    printf("usage: %s [options] <binaire_ELF64_x86_64>\n", prog);
    printf(" -v        verbose\n");
	printf(" -d        use antidebugger\n");
    printf(" -i        use int3 trap\n");
    printf(" -l        use LDE\n");
	return (1);
}