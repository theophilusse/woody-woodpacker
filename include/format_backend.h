#ifndef FORMAT_BACKEND_H
# define FORMAT_BACKEND_H

# include "asm.h"
# include "woody.h"

typedef enum e_target_format
{
    FORMAT_ELF,
    FORMAT_PE,
    FORMAT_MACHO
}   t_target_format;

typedef struct s_format_backend
{
    t_target_format format;

    /* Detection et parsing */
    int     (*detect)(const uint8_t *raw, size_t size);
    void   *(*load)(const uint8_t *raw, size_t size);

    /* Localisation du point d'injection */
    int     (*find_injection_point)(void *ctx);
    size_t  (*padding_available)(void *ctx);

    /* Injection : padding existant OU nouveau segment/section */
    int     (*patch_existing)(void *ctx, t_stub *stub);
    int     (*patch_new_segment)(void *ctx, t_stub *stub);

    /* Ecriture finale */
    int     (*write)(void *ctx, const char *out_path);

    /* Genere le texte assembleur de la primitive "rendre memoire modifiable"
    ** specifique a ce format, injecte dans le stub avant chaque DECRYPT */
    const char *(*emit_make_writable_asm)(size_t addr_reg, size_t len_reg);
    const char *(*emit_make_executable_asm)(size_t addr_reg, size_t len_reg);
}   t_format_backend;

extern t_format_backend g_elf_backend;
/* extern t_format_backend g_pe_backend;    -- future */
/* extern t_format_backend g_macho_backend; -- future */

#endif