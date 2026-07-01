#ifndef ASM_H
# define ASM_H

# include <ctype.h>
# include "emit.h"
# include "woody.h"

typedef struct s_asm_result
{
	t_emitter	e;
	size_t		patch_jmp_oep;
}	t_asm_result;

int	asm_build(const char *src, t_crypto_ctx *crypto, t_asm_result *out);

#endif
