#include "woody.h"

/* Étape 1 : chargement + validation + localisation du point d'injection */
static t_elf_ctx *load_and_validate(const char *path)
{
    t_elf_ctx *ctx;
    int err;

    ctx = elf_load(path);
    if (!ctx)
    {
        fprintf(stderr, "error: cannot load %s\n", path);
        return (NULL);
    }
    if ((err = elf_validate(ctx)) != 0)
    {
        fprintf(stderr, "error: file architecture not supported, "
                "x86_64 only (error %d)\n", err);
        elf_free(ctx);
        return (NULL);
    }
    if (elf_find_injection_point(ctx) != 0)
    {
        fprintf(stderr, "error: no suitable injection point found\n");
        elf_free(ctx);
        return (NULL);
    }
    return (ctx);
}

/* Étape 2 : génération de la clé + chiffrement RC4 en place dans ctx->raw */
static int setup_crypto(t_elf_ctx *ctx, t_crypto_ctx *crypto, t_opts *opts)
{
    Elf64_Phdr *p;

	if (opts->use_custom_key)
	{
		memcpy(crypto->key, opts->custom_key, KEY_LEN + 1);
		crypto->key_len = KEY_LEN;
	}
	else
	{
		if (crypto_generate_key(crypto) != 0)
		{
			fprintf(stderr, "error: key generation failed\n");
			return (-1);
		}
	}
	for (size_t i = 0; i < crypto->key_len; i++)
        printf("%02X", crypto->key[i]);
    printf("\n");
	exit(0);
    p = &ctx->phdrs[ctx->target_phdr_idx];
    crypto->text_vaddr = p->p_vaddr;
    crypto->text_len   = p->p_filesz;       /* p_filesz ORIGINAL, avant injection */
    crypto->stub_load_vaddr = p->p_vaddr + p->p_filesz;

    rc4_apply(ctx->raw + p->p_offset, crypto->text_len,
        crypto->key, crypto->key_len);

	if (opts->verbose)
	    printf("chiffrement : vaddr=0x%lx len=%zu key[0]=%02X\n",
    	    crypto->text_vaddr, crypto->text_len, crypto->key[0]);
    return (0);
}

/* Étape 3 : construction du stub + patch ELF + écriture du binaire final */
static int build_and_patch(t_elf_ctx *ctx, t_crypto_ctx *crypto,
        const char *out_path, t_opts *opts)
{
    t_stub *stub;

    stub = stub_build(ctx, crypto, opts);
    if (!stub)
    {
        fprintf(stderr, "error: stub generation failed\n");
        return (-1);
    }
    if (elf_patch(ctx, stub, crypto, opts) != 0)
    {
        fprintf(stderr, "error: patching failed\n");
        stub_free(stub);
        return (-1);
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
    if (elf_write(ctx, out_path) != 0)
    {
        fprintf(stderr, "error: write failed\n");
        stub_free(stub);
        return (-1);
    }
    stub_free(stub);
    return (0);
}

/* Étape 4 : affichage final de la clé */
static void print_key(t_crypto_ctx *crypto)
{
    //printf("key_value: ");
    for (size_t i = 0; i < crypto->key_len; i++)
        printf("%02X", crypto->key[i]);
    printf("\n");
}

int main(int argc, char **argv)
{
    t_elf_ctx       *ctx;
    t_crypto_ctx    crypto;
	struct s_opts	opts;

    if (argc < 2)
	{
        return (usage(argv[0]));
	}
	opts = parse_args(argc, argv);

    ctx = load_and_validate(opts.file);
    if (!ctx)
        return (1);

    memset(&crypto, 0, sizeof(crypto));
    if (setup_crypto(ctx, &crypto, &opts) != 0)
    {
        elf_free(ctx);
        return (1);
    }

    if (build_and_patch(ctx, &crypto, "woody", &opts) != 0)
    {
        elf_free(ctx);
        return (1);
    }

    print_key(&crypto);
    elf_free(ctx);
    return (0);
}