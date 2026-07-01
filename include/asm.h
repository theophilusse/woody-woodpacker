#ifndef ASM_H
# define ASM_H

# include <ctype.h>
# include "emit.h"
# include "woody.h"

#define MAX_LABELS 32
#define MAX_FIXUPS 16

typedef struct
{
	char name[64];
	size_t off;
}	t_lbl;

typedef struct
{
	size_t off;
	size_t end;
	char name[64];
	int is_rel8;
}	t_fix;

typedef struct s_asm_result
{
	t_emitter	e;
	size_t		patch_jmp_oep;
}	t_asm_result;

typedef struct
{
	t_asm_result    *out;
	t_crypto_ctx    *crypto;
	t_lbl            labels[MAX_LABELS];
	int              nlabels;
	t_fix            fixups[MAX_FIXUPS];
	int              nfixups;
}	t_asm;

int	asm_build(const char *src, t_crypto_ctx *crypto, t_asm_result *out);

#endif
