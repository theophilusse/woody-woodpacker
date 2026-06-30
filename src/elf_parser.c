#include <stdlib.h>
#include "woody.h"

t_elf_ctx	*elf_load(const char *path)
{
	(void)path;
	/* TODO: lire le fichier entier en mémoire (malloc + read),
	 * remplir ctx->raw / ctx->size, puis faire pointer
	 * ctx->ehdr et ctx->phdrs sur les bons offsets dans ctx->raw */
	return (NULL);
}

int	elf_validate(t_elf_ctx *ctx)
{
	(void)ctx;
	/* TODO: vérifier magic \x7f ELF, EI_CLASS == ELFCLASS64,
	 * e_machine == EM_X86_64 */
	return (-1);
}

void	elf_free(t_elf_ctx *ctx)
{
	if (!ctx)
		return ;
	free(ctx->raw);
	free(ctx);
}
