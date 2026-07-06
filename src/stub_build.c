#include "woody.h"

t_stub	*stub_build(t_elf_ctx *ctx, t_crypto_ctx *crypto, const t_opts *opts)
{
	t_asm_result	res;
	t_stub			*stub;

    char *src;
    src = build_stub_source(opts);
    if (!src)
    {
        return (NULL);
    }

	memset(&res, 0, sizeof(res));
	if (asm_build(src, crypto, &res, opts) < 0)
	{
        free(src);
		free(res.e.buf);
		return (NULL);
	}
    free(src);
	stub = malloc(sizeof(t_stub));
	if (!stub)
	{
		free(res.e.buf);
		return (NULL);
	}
	stub->bytes         = res.e.buf;
	stub->len           = res.e.len;
	stub->load_vaddr    = 0;
	stub->original_oep  = ctx->ehdr->e_entry;
	stub->patch_jmp_oep = res.patch_jmp_oep;
	return (stub);
}

void	stub_free(t_stub *stub)
{
	if (!stub)
		return ;
	free(stub->bytes);
	free(stub);
}
