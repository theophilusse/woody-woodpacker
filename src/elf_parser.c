#include "woody.h"

t_elf_ctx	*elf_load(const char *path)
{
	/* lire le fichier entier en mémoire (malloc + read),
	 * remplir ctx->raw / ctx->size, puis faire pointer
	 * ctx->ehdr et ctx->phdrs sur les bons offsets dans ctx->raw */
	t_elf_ctx *ctx;
	FILE *f;
	long current_position;
	char *buf;

	if (!path)
		return (NULL);
	if (!(ctx = malloc(sizeof(t_elf_ctx))))
	{
		printf("Error allocating memory\n");
		return (NULL);
	}
	f = fopen(path, "r");
	if (f == NULL)
	{
		printf("Error reading %s\n", path);
		free(ctx);
		return (NULL);
	}
	current_position = ftell(f);
	if (fseek(f, 0, SEEK_END) == -1)
	{
		printf("Error reading %s\n", path);
		fclose(f);
		free(ctx);
		return (NULL);
	{
	ctx->size = (size_t)ftell(f);
	fseek(f, current_position, SEEK_SET);
	if (!(ctx->raw = malloc(ctx->size)))
	{
		printf("Error allocating memory\n");
		fclose(f);
		return (NULL);
	}
	memset(ctx->raw, 0, ctx->size);
	if (fread(ctx->raw, 1, ctx->size, f) != ctx->size)
	{
		printf("Error reading %s\n" path);
		fclose(f);
		free(ctx->raw);
		return (NULL);
	}
	fclose(f);
	ctx->ehdr = (Elf64_Ehdr *)ctx->raw;
	ctx->phdrs = (Elf64_Phdr *)(ctx->raw + ctx->ehdr->e_phoff);
	ctx->target_phdr_idx = -1;
	return (ctx);
}

int	elf_validate(t_elf_ctx *ctx)
{
	/* vérifier magic \x7f ELF, EI_CLASS == ELFCLASS64,
	 * e_machine == EM_X86_64 */
	if (!ctx)
		return (1);
	if (ctx->size < sizeof(Elf64_Ehdr))
		return (2);
	/*
	if (ctx->ehdr->e_ident[EI_MAG0] != ELFMAG0 ||
		ctx->ehdr->e_ident[EI_MAG1] != ELFMAG1 ||
		ctx->ehdr->e_ident[EI_MAG2] != ELFMAG2 ||
		ctx->ehdr->e_ident[EI_MAG3] != ELFMAG3)
	*/
	if (memcmp(ctx->ehdr->e_ident, ELFMAG, SELFMAG) != 0)
		return (3);
	if (ctx->ehdr->e_ident[EI_CLASS] != ELFCLASS64)
		return (4);
	if (ctx->ehdr->e_machine != EM_X86_64) // 62
		return (5);
	if ((size_t)ctx->ehdr->e_phoff + (size_t)ctx->ehdr->e_phnum * sizeof(Elf64_Phdr) > ctx->size)
		return (6);
	return (0);
}

void	elf_free(t_elf_ctx *ctx)
{
	if (!ctx)
		return ;
	free(ctx->raw);
	free(ctx);
}
