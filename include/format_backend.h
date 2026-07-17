#ifndef FORMAT_BACKEND_H
# define FORMAT_BACKEND_H

# include "woody.h"

typedef struct s_format_backend
{
    t_target_format format;
    const char      *(*emit_make_writable_asm)(t_reg addr_reg, t_reg len_reg);
    const char      *(*emit_make_executable_asm)(t_reg addr_reg, t_reg len_reg);
}   t_format_backend;

extern t_format_backend g_elf_backend;
/* extern t_format_backend g_pe_backend;    -- future */
/* extern t_format_backend g_macho_backend; -- future */

#endif