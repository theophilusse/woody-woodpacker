#include "woody.h"

static int	usage(const char *prog)
{
	fprintf(stderr, "usage: %s <binaire_ELF64_x86_64>\n", prog);
	return (1);
}

int	main(int argc, char **argv)
{
	int		debug;
	t_elf_ctx		*ctx;
	t_crypto_ctx	crypto;
	t_stub			*stub;

	if (argc != 2)
		return (usage(argv[0]));

	/* 1. Parsing + validation */
	ctx = elf_load(argv[1]);
	if (!ctx)
	{
		fprintf(stderr, "error: cannot load %s\n", argv[1]);
		return (1);
	}
	if ((debug = elf_validate(ctx)) != 0)
	{
		fprintf(stderr, "Filr architecture not supported. x86_64 only (error %d)\n", debug);
		elf_free(ctx);
		return (1);
	}

	/* 2. Localisation du point d'injection */
	if (elf_find_injection_point(ctx) != 0)
	{
		fprintf(stderr, "error: no suitable injection point found\n");
		elf_free(ctx);
		return (1);
	}

	/* 3. Clé + chiffrement RC4 de .text */
	if (crypto_generate_key(&crypto) != 0)
	{
		fprintf(stderr, "error: key generation failed\n");
		elf_free(ctx);
		return (1);
	}
	// remplir crypto.text_vaddr / crypto.text_len depuis ctx,
	// copier .text dans crypto.encrypted_text, puis rc4_apply() en place
	// localiser .text dans le segment cible
	/*
	Elf64_Shdr *shdrs = (Elf64_Shdr *)(ctx->raw + ctx->ehdr->e_shoff);
	for (int i = 0; i < ctx->ehdr->e_shnum; i++)
	{
		if (shdrs[i].sh_flags & SHF_EXECINSTR)
		{
			crypto.text_vaddr = shdrs[i].sh_addr;
			crypto.text_len   = shdrs[i].sh_size;
			crypto.encrypted_text = ctx->raw + shdrs[i].sh_offset;
			rc4_apply(crypto.encrypted_text, crypto.text_len, crypto.key, crypto.key_len);
		}
	}
	*/
	Elf64_Phdr *p = &ctx->phdrs[ctx->target_phdr_idx];

	crypto.text_vaddr = p->p_vaddr;
	crypto.text_len   = p->p_filesz;       /* p_filesz ORIGINAL, avant injection */

	/* chiffrement EN PLACE dans ctx->raw */
	rc4_apply(ctx->raw + p->p_offset, crypto.text_len,
		crypto.key, crypto.key_len);

	printf("chiffrement : vaddr=0x%lx len=%zu key[0]=%02X\n",
		crypto.text_vaddr, crypto.text_len, crypto.key[0]);

	/* 4. Construction du stub (forme unique) */
	stub = stub_build(ctx, &crypto);
	if (!stub)
	{
		fprintf(stderr, "error: stub generation failed\n");
		elf_free(ctx);
		return (1);
	}

	{
		FILE *meta = fopen("./woody_meta.txt", "w");
		if (meta)
		{
			fprintf(meta, "patch_jmp_oep=%zu\n", stub->patch_jmp_oep);
			fprintf(meta, "load_vaddr=%lu\n", stub->load_vaddr);
			fclose(meta);
		}
	}

	/* 5. Patch des Phdr / e_entry */
	if (elf_patch(ctx, stub, &crypto) != 0)
	{
		fprintf(stderr, "error: patching failed\n");
		stub_free(stub);
		elf_free(ctx);
		return (1);
	}

	/* 6. Écriture de woody */
	if (elf_write(ctx, "woody") != 0)
	{
		fprintf(stderr, "error: write failed\n");
		stub_free(stub);
		elf_free(ctx);
		return (1);
	}

	printf("key_value: ");
	for (size_t i = 0; i < crypto.key_len; i++)
		printf("%02X", crypto.key[i]);
	printf("\n");

	stub_free(stub);
	elf_free(ctx);
	return (0);
}
