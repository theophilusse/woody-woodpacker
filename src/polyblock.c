/* polyblock.c */
#include "polyblock.h"

/*
static int is_directive(const char *line)
{
    while (*line == ' ' || *line == '\t')
        line++;
    return (*line == '%');
}
*/

t_polyblock *find_block(t_polyctx *ctx, const char *name)
{
    int i;

    for (i = 0; i < ctx->n_blocks; i++)
        if (!strcmp(ctx->blocks[i].identifier, name))
            return (&ctx->blocks[i]);
    return (NULL);
}

/* Extrait le mot-cle de directive (POLYBLOCK_START, CIPHERTEXT, etc.)
** et le reste de la ligne dans `rest`. Retourne le mot-cle. */
/*
static void split_directive(const char *line, char *keyword, char *rest)
{
    const char *p = line;
    int i;

    while (*p == ' ' || *p == '\t')
        p++;
    p++; // saute le '%'
    i = 0;
    while (*p && *p != ' ' && *p != '\t' && *p != '\n' && i < 63)
        keyword[i++] = *p++;
    keyword[i] = '\0';
    while (*p == ' ' || *p == '\t')
        p++;
    i = 0;
    while (*p && *p != '\n' && i < 255)
        rest[i++] = *p++;
    rest[i] = '\0';
}
*/

static int equalize_sizes(t_asm *a, t_polyctx *ctx, t_polyblock *blk)
{
    size_t max_len;
    t_block_variant *shorter;
    int is_cipher_shorter;
    char junk_directive[64];
    char *new_src;
    size_t pad;

    if (blk->ciphertext.bytecode_len == blk->plaintext.bytecode_len)
    {
        blk->final_size = blk->ciphertext.bytecode_len;
        return (0);
    }

    if (blk->ciphertext.bytecode_len < blk->plaintext.bytecode_len)
    {
        shorter = &blk->ciphertext;
        is_cipher_shorter = 1;
        max_len = blk->plaintext.bytecode_len;
    }
    else
    {
        shorter = &blk->plaintext;
        is_cipher_shorter = 0;
        max_len = blk->ciphertext.bytecode_len;
    }
    pad = max_len - shorter->bytecode_len;

    /* Reconstruit le texte source du variant le plus court avec _JUNK ajoute a la fin */
    snprintf(junk_directive, sizeof(junk_directive), "_junk %zu\n", pad);
    new_src = malloc(strlen(shorter->src) + strlen(junk_directive) + 1);
    if (!new_src)
        return (-1);
    strcpy(new_src, shorter->src);
    strcat(new_src, junk_directive);
    free(shorter->src);
    shorter->src = new_src;

    /* Re-assemble ce variant avec le _JUNK inclus.
    ** Attention : il faut d'abord "annuler" les labels/fixups de l'ancien
    ** assemblage (puisqu'on va tout refaire), en les retirant du pool global. */
    a->nlabels = shorter->label_range_start;
    a->nfixups = shorter->fixup_range_start;
    free(shorter->bytecode);
    shorter->bytecode = NULL;

    if (resolve_variant(a, ctx, shorter, is_cipher_shorter) < 0)
        return (-1);

    if (shorter->bytecode_len != max_len)
    {
        fprintf(stderr, "polyblock: _JUNK n'a pas produit la taille exacte attendue "
                "(%zu vs %zu) pour '%s'\n", shorter->bytecode_len, max_len, blk->identifier);
        return (-1);
    }

    blk->final_size = max_len;
    return (0);
}

/* Retourne un ordre topologique (dependances d'abord), ou -1 si cycle */
int polyblock_topo_sort(t_polyctx *ctx, t_polyblock **order, int *n_order)
{
    int i;

    *n_order = 0;
    for (i = 0; i < ctx->n_blocks; i++)
        ctx->blocks[i].resolved = 0;
    for (i = 0; i < ctx->n_blocks; i++)
    {
        if (!ctx->blocks[i].resolved)
        {
            if (visit_block(ctx, &ctx->blocks[i], order, n_order) < 0)
                return (-1);
        }
    }
    return (0);
}