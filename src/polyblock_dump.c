#include "polyblock.h"

static const char *method_name(t_decrypt_method m)
{
    switch (m)
    {
        case METHOD_ADD: return ("ADD");
        case METHOD_SUB: return ("SUB");
        case METHOD_XOR: return ("XOR");
        case METHOD_MOV: return ("MOV");
        case METHOD_LEA: return ("LEA");
        default: return ("?");
    }
}

static const char *sync_name(t_sync_mode s)
{
    return (s == SYNC_ON ? "SYNC" : "NOSYNC");
}

static void dump_decrypts(t_block_variant *variant, const char *variant_name, int depth)
{
    int i, j;
    char pad[64];

    memset(pad, ' ', (size_t)(depth * 2));
    pad[depth * 2] = '\0';

    for (i = 0; i < variant->n_decrypts; i++)
    {
        t_decrypt_spec *spec = &variant->decrypts[i];
        fprintf(stderr, "%s  [%s] DECRYPT -> target='%s' methods=[",
                pad, variant_name, spec->target_identifier);
        for (j = 0; j < spec->n_methods; j++)
            fprintf(stderr, "%s%s", method_name(spec->methods[j]),
                    j + 1 < spec->n_methods ? "," : "");
        fprintf(stderr, "]");
        if (spec->n_breakpoints > 0)
        {
            fprintf(stderr, " breakpoints=[");
            for (j = 0; j < spec->n_breakpoints; j++)
                fprintf(stderr, "%zu:%s%s", spec->breakpoints[j].byte_index,
                        spec->breakpoints[j].label,
                        j + 1 < spec->n_breakpoints ? "," : "");
            fprintf(stderr, "]");
        }
        fprintf(stderr, "\n");
    }
}

static void dump_polyblock(t_polyblock *blk, int depth)
{
    int i;
    char pad[64];

    memset(pad, ' ', (size_t)(depth * 2));
    pad[depth * 2] = '\0';

    fprintf(stderr, "%sPOLYBLOCK '%s' (children=%d, depends_on=%d)\n",
            pad, blk->identifier, blk->n_children, blk->n_depends);

    fprintf(stderr, "%s  CIPHERTEXT [%s] (%zu octets source):\n",
            pad, sync_name(blk->ciphertext.sync), blk->ciphertext.src_len);
    if (blk->ciphertext.src)
        fprintf(stderr, "%s    ---\n%s%s    ---\n", pad, blk->ciphertext.src, pad);
    dump_decrypts(&blk->ciphertext, "CIPHERTEXT", depth);

    fprintf(stderr, "%s  PLAINTEXT [%s] (%zu octets source):\n",
            pad, sync_name(blk->plaintext.sync), blk->plaintext.src_len);
    if (blk->plaintext.src)
        fprintf(stderr, "%s    ---\n%s%s    ---\n", pad, blk->plaintext.src, pad);
    dump_decrypts(&blk->plaintext, "PLAINTEXT", depth);

    if (blk->n_depends > 0)
    {
        fprintf(stderr, "%s  depends_on: ", pad);
        for (i = 0; i < blk->n_depends; i++)
            fprintf(stderr, "%s%s", blk->depends_on[i], i + 1 < blk->n_depends ? ", " : "");
        fprintf(stderr, "\n");
    }

    for (i = 0; i < blk->n_children; i++)
        dump_polyblock(blk->children[i], depth + 1);
}

void polyblock_dump(t_polyctx *ctx)
{
    int i;

    fprintf(stderr, "=== POLYBLOCK CONTEXT DUMP (%d blocks total) ===\n", ctx->n_blocks);
    for (i = 0; i < ctx->n_blocks; i++)
        if (!ctx->blocks[i].parent)
            dump_polyblock(&ctx->blocks[i], 0);
    fprintf(stderr, "=== END DUMP ===\n");
}