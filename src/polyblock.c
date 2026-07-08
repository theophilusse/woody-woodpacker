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