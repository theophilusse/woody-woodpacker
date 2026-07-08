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

static int equalize_sizes(t_polyblock *blk)
{
    size_t max_len = blk->ciphertext.bytecode_len > blk->plaintext.bytecode_len
                    ? blk->ciphertext.bytecode_len : blk->plaintext.bytecode_len;
    t_block_variant *shorter = blk->ciphertext.bytecode_len < max_len
                              ? &blk->ciphertext : &blk->plaintext;

    if (blk->ciphertext.bytecode_len == blk->plaintext.bytecode_len)
    {
        blk->final_size = max_len;
        return (0);
    }

    size_t pad = max_len - shorter->bytecode_len;
    uint8_t *padded = realloc(shorter->bytecode, max_len);
    if (!padded)
        return (-1);
    memset(padded + shorter->bytecode_len, 0x90, pad);   /* NOP filler */
    shorter->bytecode = padded;
    shorter->bytecode_len = max_len;
    blk->final_size = max_len;
    return (0);
}

/* DFS avec marquage 3 couleurs (blanc/gris/noir) pour detecter les cycles */
static int visit_block(t_polyctx *ctx, t_polyblock *b, t_polyblock **order, int *n_order)
{
    int i;
    t_polyblock *dep;

    if (b->resolved)
        return (0);
    if (b->visiting)
    {
        fprintf(stderr, "polyblock: dependance cyclique detectee sur '%s'\n", b->identifier);
        return (-1);
    }
    b->visiting = 1;
    for (i = 0; i < b->n_depends; i++)
    {
        dep = find_block(ctx, b->depends_on[i]);
        if (!dep)
        {
            fprintf(stderr, "polyblock: '%s' depend de '%s', introuvable\n",
                    b->identifier, b->depends_on[i]);
            b->visiting = 0;
            return (-1);
        }
        if (visit_block(ctx, dep, order, n_order) < 0)
        {
            b->visiting = 0;
            return (-1);
        }
    }
    b->visiting = 0;
    b->resolved = 1;
    order[(*n_order)++] = b;
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