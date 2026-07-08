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

static int compute_diff(t_block_variant *cipher, t_block_variant *plain, t_diff_result *diff)
{
    size_t i;

    if (cipher->bytecode_len != plain->bytecode_len)
    {
        fprintf(stderr, "polyblock: diff impossible, tailles differentes (%zu vs %zu)\n",
                cipher->bytecode_len, plain->bytecode_len);
        return (-1);
    }
    if (cipher->bytecode_len > 8192)
    {
        fprintf(stderr, "polyblock: bloc trop grand pour le diff (%zu > 8192)\n",
                cipher->bytecode_len);
        return (-1);
    }

    diff->n_entries = 0;
    for (i = 0; i < cipher->bytecode_len; i++)
    {
        uint8_t c = cipher->bytecode[i];
        uint8_t p = plain->bytecode[i];

        if (c == p)
            continue;   /* octet deja identique, aucune transformation necessaire */

        diff->entries[diff->n_entries].offset = i;
        diff->entries[diff->n_entries].cipher_byte = c;
        diff->entries[diff->n_entries].plain_byte = p;
        diff->entries[diff->n_entries].delta = (uint8_t)(p - c);   /* wraparound naturel sur uint8_t */
        diff->n_entries++;
    }
    return (0);
}

static char *generate_decrypt_stub(t_polyblock *target_blk, t_diff_result *diff,
        t_decrypt_method method, const char *target_label)
{
    char    *out_src;
    char    line[128];
    size_t  cap = 8192;
    size_t  i;

    (void)target_blk;
    out_src = malloc(cap);
    if (!out_src)
        return (NULL);
    out_src[0] = '\0';

    if (diff->n_entries == 0)
        return (out_src);   /* rien a patcher, bloc deja identique */

    snprintf(line, sizeof(line), "lea rdi, [%s]\n", target_label);
    strcat(out_src, line);

    for (i = 0; i < diff->n_entries; i++)
    {
        size_t off = diff->entries[i].offset;
        size_t prev_off = (i > 0) ? diff->entries[i - 1].offset : (size_t)-1;

        if (off != prev_off + 1)
        {
            if (off == 0)
                snprintf(line, sizeof(line), "lea rdi, [%s]\n", target_label);
            else
                snprintf(line, sizeof(line), "lea rdi, [%s+%zu]\n", target_label, off);
            strcat(out_src, line);
        }

        switch (method)
        {
            case METHOD_XOR:
            {
                uint8_t k = diff->entries[i].cipher_byte ^ diff->entries[i].plain_byte;
                snprintf(line, sizeof(line), "xor byte [rdi], %u\n", k);
                break;
            }
            case METHOD_ADD:
            {
                if (diff->entries[i].delta == 1)
                {
                    uint8_t k = diff->entries[i].cipher_byte ^ diff->entries[i].plain_byte;
                    snprintf(line, sizeof(line), "xor byte [rdi], %u\n", k);
                }
                else
                    snprintf(line, sizeof(line), "add byte [rdi], %u\n", diff->entries[i].delta);
                break;
            }
            case METHOD_SUB:
            {
                uint8_t neg = (uint8_t)(-(int)diff->entries[i].delta);
                if (neg == 1)
                {
                    uint8_t k = diff->entries[i].cipher_byte ^ diff->entries[i].plain_byte;
                    snprintf(line, sizeof(line), "xor byte [rdi], %u\n", k);
                }
                else
                    snprintf(line, sizeof(line), "sub byte [rdi], %u\n", neg);
                break;
            }
            case METHOD_MOV:
            {
                snprintf(line, sizeof(line), "mov byte [rdi], %u\n", diff->entries[i].plain_byte);
                break;
            }
            default:
                fprintf(stderr, "polyblock: methode %d non geree pour patch octet-a-octet\n", method);
                free(out_src);
                return (NULL);
        }
        strcat(out_src, line);
        strcat(out_src, "_INC rdi\n");
    }
    return (out_src);
}

int polyblock_generate_decrypts(t_asm *a, t_polyctx *ctx)
{
    t_polyblock *order[MAX_POLYBLOCKS];
    int         n_order;
    int         i, j;

    if (polyblock_topo_sort(ctx, order, &n_order) < 0)
        return (-1);

    for (i = 0; i < n_order; i++)
    {
        t_polyblock *blk = order[i];
        t_block_variant *variants[2] = { &blk->ciphertext, &blk->plaintext };

        for (int v = 0; v < 2; v++)
        {
            t_block_variant *variant = variants[v];

            for (j = 0; j < variant->n_decrypts; j++)
            {
                t_decrypt_spec *spec = &variant->decrypts[j];
                t_polyblock *target = find_block(ctx, spec->target_identifier);
                t_diff_result diff;
                t_decrypt_method chosen;
                char *stub_src;

                if (!target)
                {
                    fprintf(stderr, "polyblock: DECRYPT cible '%s' introuvable\n",
                            spec->target_identifier);
                    return (-1);
                }
                if (compute_diff(&target->ciphertext, &target->plaintext, &diff) < 0)
                    return (-1);

                chosen = spec->methods[rand() % spec->n_methods];
                stub_src = generate_decrypt_stub(target, &diff, chosen, target->identifier);
                if (!stub_src)
                    return (-1);

                spec->chosen_method = chosen;
                /* TODO: injecter stub_src dans le bytecode final a la position
                ** du %DECRYPT (necessite de re-assembler ou d'injecter apres coup) */
                free(stub_src);
            }
        }
    }
    return (0);
}