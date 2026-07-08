#ifndef ASM_H
# define ASM_H

# include <ctype.h>
# include "emit.h"
# include "opts.h"
# include "polyblock.h"
# include "woody.h"

#define MAX_LABELS 512
#define MAX_FIXUPS 512

typedef struct s_polyctx t_polyctx;

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

typedef struct s_asm
{
	t_asm_result    *out;
	t_crypto_ctx    *crypto;
	t_lbl           labels[MAX_LABELS];
	int             nlabels;
	t_fix           fixups[MAX_FIXUPS];
	int             nfixups;
	size_t			key_index;
	size_t          label_base_offset;
	t_polyctx       *polyctx;          /* contexte polyblock global, NULL si stub principal */
    int             current_variant_is_cipher;
	int				key_sync_enabled;
}	t_asm;

int asm_build(const char *src, t_crypto_ctx *crypto, t_asm_result *out, const t_opts *opts);
int	ainstr(t_asm *a, char toks[][64], int n);
void deflabel(t_asm *a, const char *name);
int assemble_source(t_asm *a, const char *src);

#endif
