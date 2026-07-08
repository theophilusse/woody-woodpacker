#ifndef ASM_H
# define ASM_H

# include <ctype.h>
# include "emit.h"
# include "opts.h"
# include "polyblock.h"
# include "woody.h"

#define MAX_LABELS 512
#define MAX_FIXUPS 512

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

int asm_build(const char *src, t_crypto_ctx *crypto, t_asm_result *out, const t_opts *opts);
int	ainstr(t_asm *a, char toks[][64], int n);

#endif
