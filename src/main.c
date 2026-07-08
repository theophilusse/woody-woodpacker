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
		memcpy(crypto->key, opts->custom_key, KEY_LEN);
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

/* test_polyblock.c, ou directement dans main.c en mode debug */
void test_polyblock_parsing(void)
{
    const char *source =
"%POLYBLOCK_START anti_debug\n"
"%CIPHERTEXT SYNC\n"
"    %DECRYPT secret_cipher SUB, ADD\n"
"    jmp secret_cipher\n"
"%PLAINTEXT SYNC\n"
"    ; anti debug code\n"
"    %DECRYPT anti_debug XOR\n"
"%POLYBLOCK_END\n"
"%POLYBLOCK_START secret_cipher\n"
"%CIPHERTEXT NOSYNC\n"
"    ; contenu chiffre place ici a la generation\n"
"%PLAINTEXT SYNC\n"
"    write(\"fuck you\")\n"
"    exit(0)\n"
"%POLYBLOCK_END\n";

    t_polyctx *ctx = polyblock_parse_all(source);
    if (!ctx)
    {
        fprintf(stderr, "ECHEC du parsing\n");
        return;
    }
    polyblock_dump(ctx);

    t_polyblock *order[MAX_POLYBLOCKS];
    int n_order = 0;
    if (polyblock_topo_sort(ctx, order, &n_order) < 0)
    {
        fprintf(stderr, "ECHEC: cycle detecte\n");
        return;
    }
    fprintf(stderr, "=== ORDRE TOPOLOGIQUE ===\n");
    for (int i = 0; i < n_order; i++)
        fprintf(stderr, "%d: %s\n", i, order[i]->identifier);
}

void test_polyblock_cycle_detection(void)
{
    const char *source =
"%POLYBLOCK_START a\n"
"%CIPHERTEXT\n"
"    %DECRYPT b XOR\n"
"%PLAINTEXT\n"
"%POLYBLOCK_END\n"
"%POLYBLOCK_START b\n"
"%CIPHERTEXT\n"
"    %DECRYPT a XOR\n"
"%PLAINTEXT\n"
"%POLYBLOCK_END\n";

    t_polyctx *ctx = polyblock_parse_all(source);
    t_polyblock *order[MAX_POLYBLOCKS];
    int n_order = 0;

    if (polyblock_topo_sort(ctx, order, &n_order) < 0)
        fprintf(stderr, "OK: cycle correctement detecte\n");
    else
        fprintf(stderr, "ECHEC: cycle NON detecte (bug!)\n");
}

void test_polyblock_resolve_sizes(void)
{
    const char *source =
"%POLYBLOCK_START anti_debug\n"
"%CIPHERTEXT SYNC\n"
"    _SET eax, 1\n"
"    _SET edi, 2\n"
"%PLAINTEXT SYNC\n"
"    _ZERO eax\n"
"    _INC eax\n"
"    _INC eax\n"
"%POLYBLOCK_END\n";

    t_polyctx *ctx = polyblock_parse_all(source);
    if (!ctx)
    {
        fprintf(stderr, "ECHEC parsing\n");
        return;
    }

    t_asm a;
    t_asm_result out;
    t_crypto_ctx crypto;

    memset(&a, 0, sizeof(a));
    memset(&out, 0, sizeof(out));
    memset(&crypto, 0, sizeof(crypto));
	crypto.key_len = 16;
	memset(crypto.key, 0x55, 16);
    a.out = &out;
    a.crypto = &crypto;
    a.key_sync_enabled = 1;
    a.label_base_offset = 0;

    if (polyblock_resolve_sizes(&a, ctx) < 0)
    {
        fprintf(stderr, "ECHEC resolve_sizes\n");
        return;
    }

    int i;
    for (i = 0; i < ctx->n_blocks; i++)
    {
        t_polyblock *blk = &ctx->blocks[i];
        fprintf(stderr, "=== BLOCK '%s' ===\n", blk->identifier);
        fprintf(stderr, "  final_offset=%zu final_size=%zu\n",
                blk->final_offset, blk->final_size);
        fprintf(stderr, "  ciphertext: len=%zu bytes=",
                blk->ciphertext.bytecode_len);
        for (size_t k = 0; k < blk->ciphertext.bytecode_len; k++)
            fprintf(stderr, "%02x ", blk->ciphertext.bytecode[k]);
        fprintf(stderr, "\n");
        fprintf(stderr, "  plaintext:  len=%zu bytes=",
                blk->plaintext.bytecode_len);
        for (size_t k = 0; k < blk->plaintext.bytecode_len; k++)
            fprintf(stderr, "%02x ", blk->plaintext.bytecode[k]);
        fprintf(stderr, "\n");
    }
}

const char *source_ref =
"%POLYBLOCK_START secret_cipher\n"
"%CIPHERTEXT NOSYNC\n"
"    _SET eax, 99\n"
"%PLAINTEXT SYNC\n"
"    _ZERO eax\n"
"%POLYBLOCK_END\n"
"%POLYBLOCK_START anti_debug\n"
"%CIPHERTEXT SYNC\n"
"    _SET edi, 1\n"
"%PLAINTEXT SYNC\n"
"    _ZERO edi\n"
"%POLYBLOCK_END\n";

const char *source_nested =
"%POLYBLOCK_START outer\n"
"%CIPHERTEXT SYNC\n"
"%POLYBLOCK_START inner\n"
"%CIPHERTEXT NOSYNC\n"
"    _SET eax, 5\n"
"%PLAINTEXT SYNC\n"
"    _ZERO eax\n"
"%POLYBLOCK_END\n"
"    _SET edi, 1\n"
"%PLAINTEXT SYNC\n"
"    _ZERO edi\n"
"%POLYBLOCK_END\n";

static void run_polyblock_test(const char *source, const char *label)
{
    fprintf(stderr, "\n########## TEST: %s ##########\n", label);

    t_polyctx *ctx = polyblock_parse_all(source);
    if (!ctx)
    {
        fprintf(stderr, "ECHEC parsing\n");
        return;
    }

    t_asm a;
    t_asm_result out;
    t_crypto_ctx crypto;

    memset(&a, 0, sizeof(a));
    memset(&out, 0, sizeof(out));
    memset(&crypto, 0, sizeof(crypto));
    crypto.key_len = 16;
    a.out = &out;
    a.crypto = &crypto;
    a.key_sync_enabled = 1;
    a.label_base_offset = 0;

    if (polyblock_resolve_sizes(&a, ctx) < 0)
    {
        fprintf(stderr, "ECHEC resolve_sizes\n");
        return;
    }

    for (int i = 0; i < ctx->n_blocks; i++)
    {
        t_polyblock *blk = &ctx->blocks[i];
        fprintf(stderr, "=== BLOCK '%s' ===\n", blk->identifier);
        fprintf(stderr, "  final_offset=%zu final_size=%zu\n",
                blk->final_offset, blk->final_size);
        fprintf(stderr, "  ciphertext len=%zu: ", blk->ciphertext.bytecode_len);
        for (size_t k = 0; k < blk->ciphertext.bytecode_len; k++)
            fprintf(stderr, "%02x ", blk->ciphertext.bytecode[k]);
        fprintf(stderr, "\n  plaintext  len=%zu: ", blk->plaintext.bytecode_len);
        for (size_t k = 0; k < blk->plaintext.bytecode_len; k++)
            fprintf(stderr, "%02x ", blk->plaintext.bytecode[k]);
        fprintf(stderr, "\n");
    }
}

void test_polyblock_final(void)
{
    run_polyblock_test(source_ref, "REFERENCE SIMPLE");
    run_polyblock_test(source_nested, "IMBRICATION SYNTAXIQUE");
}

int main(int argc, char **argv)
{
    t_elf_ctx       *ctx;
    t_crypto_ctx    crypto;
	struct s_opts	opts;

	//test_polyblock_parsing();
	//test_polyblock_cycle_detection();
	//test_polyblock_resolve_sizes();
	test_polyblock_final();
	return 0;
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