/* polyblock.c */
#include "polyblock.h"

t_polyblock *find_block(t_polyctx *ctx, const char *name)
{
    int i;

    for (i = 0; i < ctx->n_blocks; i++)
        if (!strcmp(ctx->blocks[i].identifier, name))
            return (&ctx->blocks[i]);
    return (NULL);
}

static int visit_block(t_polyctx *ctx, t_polyblock *b, t_polyblock **order, int *n_order)
{
    int         i;
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
    for (i = 0; i < b->n_children; i++)
    {
        if (visit_block(ctx, b->children[i], order, n_order) < 0)
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

int polyblock_topo_sort(t_polyctx *ctx, t_polyblock **order, int *n_order)
{
    int i;

    *n_order = 0;
    for (i = 0; i < ctx->n_blocks; i++)
        ctx->blocks[i].resolved = 0;
    for (i = 0; i < ctx->n_blocks; i++)
    {
        if (!ctx->blocks[i].parent && !ctx->blocks[i].resolved)
        {
            if (visit_block(ctx, &ctx->blocks[i], order, n_order) < 0)
                return (-1);
        }
    }
    return (0);
}