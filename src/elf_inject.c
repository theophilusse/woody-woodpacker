#include "woody.h"

int	elf_find_injection_point(t_elf_ctx *ctx)
{
	(void)ctx;
	/* TODO: trouver le PT_LOAD exécutable contenant e_entry,
	 * vérifier le padding disponible jusqu'au prochain p_align */
	return (-1);
}

int	elf_patch(t_elf_ctx *ctx, t_stub *stub, t_crypto_ctx *crypto)
{
	(void)ctx;
	(void)stub;
	(void)crypto;
	/* TODO: e_entry -> adresse du stub, étendre p_filesz/p_memsz
	 * du segment cible */
	return (-1);
}

int	elf_write(t_elf_ctx *ctx, const char *out_path)
{
	(void)ctx;
	(void)out_path;
	/* TODO: écrire ctx->raw (mis à jour) dans out_path, chmod 0755 */
	return (-1);
}
