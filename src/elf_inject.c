#include "woody.h"

int	elf_find_injection_point(t_elf_ctx *ctx)
{
	/* trouver le PT_LOAD exécutable contenant e_entry */
	Elf64_Half ph;

	ph = 0;
	while (ph < ctx->ehdr->e_phnum)
	{
		Elf64_Phdr *p;

		p = &ctx->phdrs[ph];
		if (p->p_type == PT_LOAD &&
			p->p_flags & PF_X &&
			ctx->ehdr->e_entry >= p->p_vaddr && ctx->ehdr->e_entry < p->p_vaddr + p->p_memsz)
		{
			ctx->target_phdr_idx = ph;
			return (0);
		}
		ph++;
	}
	return (1);
}

size_t	padding_available(Elf64_Phdr *p)
{
	size_t	used;

	used = p->p_filesz % p->p_align;
	if (used == 0)
		return (0);          // déjà parfaitement aligné, pas de padding gratuit
	return (p->p_align - used);
}

int	elf_patch(t_elf_ctx *ctx, t_stub *stub, t_crypto_ctx *crypto)
{
	Elf64_Phdr	*p;
	size_t		stub_offset;
	uint8_t		*tmp;

	(void)crypto;
	p = &ctx->phdrs[ctx->target_phdr_idx];

	if (stub->len > padding_available(p))
	{
		fprintf(stderr, "error: stub too large for available padding "
			"(%zu bytes needed, %zu available)\n",
			stub->len, padding_available(p));
		return (-1);
	}

	stub_offset = p->p_offset + p->p_filesz;

	tmp = realloc(ctx->raw, ctx->size + stub->len);
	if (!tmp)
		return (-1);
	ctx->raw = tmp;
	ctx->ehdr = (Elf64_Ehdr *)ctx->raw;
	ctx->phdrs = (Elf64_Phdr *)(ctx->raw + ctx->ehdr->e_phoff);
	p = &ctx->phdrs[ctx->target_phdr_idx];

	memmove(ctx->raw + stub_offset, stub->bytes, stub->len);

	stub->load_vaddr = p->p_vaddr + p->p_filesz;
	stub->original_oep = ctx->ehdr->e_entry;

	p->p_filesz += stub->len;
	p->p_memsz  += stub->len;

	ctx->ehdr->e_entry = stub->load_vaddr;
	ctx->size += stub->len;

	return (0);
}

int	elf_write(t_elf_ctx *ctx, const char *out_path)
{
	(void)ctx;
	(void)out_path;
	/* TODO: écrire ctx->raw (mis à jour) dans out_path, chmod 0755 */
		/* TODO: lire le fichier entier en mémoire (malloc + read),
	 * remplir ctx->raw / ctx->size, puis faire pointer
	 * ctx->ehdr et ctx->phdrs sur les bons offsets dans ctx->raw */
	FILE *f;

	if (!out_path)
		return (1);
	f = fopen(out_path, "wb");
	if (f == NULL)
	{
		printf("Error writing %s\n", out_path);
		return (1);
	}
	if (fwrite(ctx->raw, 1, ctx->size, f) != ctx->size)
	{
		printf("Error writing %s\n", out_path);
		fclose(f);
		return (1);
	}
	fclose(f);
	if (chmod(out_path, 0755) != 0)
	{
		fprintf(stderr, "Error setting permissions on %s\n", out_path);
		return (1);
	}
	return (0);
}
