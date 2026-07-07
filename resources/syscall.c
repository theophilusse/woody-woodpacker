#include <sys/syscall.h>
#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>

int main(void)
{
    long fd = syscall(SYS_open, "/proc", O_RDONLY, 0);
    printf("fd=%ld\n", fd);

    char buf[4096];
    long n = syscall(SYS_getdents64, fd, buf, 4096);
    printf("getdents64=%ld\n", n);
    if (n < 0)
        perror("getdents64");
    return 0;
}
