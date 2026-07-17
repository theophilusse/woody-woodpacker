#include "woody.h"
#include "format_backend.h"

static const char *elf_emit_make_writable_asm(t_reg addr_reg, t_reg len_reg)
{
    static char buf[256];
    snprintf(buf, sizeof(buf),
        "push rax\npush rdi\npush rsi\npush rdx\n"
        "_SET rdi, %s\n"
        "_SET rsi, %s\n"
        "_SET edx, 7\n"
        "_SET eax, 10\n"
        "syscall\n"
        "pop rdx\npop rsi\npop rdi\npop rax\n",
        reg_name(addr_reg, 64), reg_name(len_reg, 64));
    return (buf);
}

static const char *elf_emit_make_executable_asm(t_reg addr_reg, t_reg len_reg)
{
    static char buf[256];
    snprintf(buf, sizeof(buf),
        "push rax\npush rdi\npush rsi\npush rdx\n"
        "_SET rdi, %s\n"
        "_SET rsi, %s\n"
        "_SET edx, 5\n"       /* PROT_READ|PROT_EXEC, sans W */
        "_SET eax, 10\n"
        "syscall\n"
        "pop rdx\npop rsi\npop rdi\npop rax\n",
        reg_name(addr_reg, 64), reg_name(len_reg, 64));
    return (buf);
}

t_format_backend g_elf_backend = {
    .format = FORMAT_ELF,
    .emit_make_writable_asm = elf_emit_make_writable_asm,
    .emit_make_executable_asm = elf_emit_make_executable_asm,
};