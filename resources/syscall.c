#include <stdio.h>
#include <fcntl.h>

int main(void)
{
    long fd;
    asm volatile (
        "mov $2, %%rax\n"
        "lea proc_path(%%rip), %%rdi\n"
        "mov $0, %%rsi\n"
        "syscall\n"
        : "=a"(fd)
        :
        : "rdi", "rsi"
    );
    printf("fd=%ld\n", fd);

    char buf[4096];
    long n;
    asm volatile (
        "mov $78, %%rax\n"
        "mov %1, %%rdi\n"
        "mov %2, %%rsi\n"
        "mov $4096, %%rdx\n"
        "syscall\n"
        : "=a"(n)
        : "r"(fd), "r"(buf)
        : "rdi", "rsi", "rdx"
    );
    printf("getdents64=%ld\n", n);

    return 0;
}
static const char proc_path[] = "/proc";
