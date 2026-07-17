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

int compute_diff(t_block_variant *plain, t_block_variant *cipher, t_diff_result *diff)
{
    size_t i;

    if (plain->bytecode_len != cipher->bytecode_len)
    {
        fprintf(stderr, "polyblock: diff impossible, tailles differentes (%zu vs %zu)\n",
                plain->bytecode_len, cipher->bytecode_len);
        return (-1);
    }
    if (plain->bytecode_len > 8192)
    {
        fprintf(stderr, "polyblock: bloc trop grand pour le diff (%zu > 8192)\n",
                plain->bytecode_len);
        return (-1);
    }

    diff->n_entries = 0;
    for (i = 0; i < plain->bytecode_len; i++)
    {
        uint8_t p = plain->bytecode[i];
        uint8_t c = cipher->bytecode[i];

        if (p == c)
            continue;

        diff->entries[diff->n_entries].offset = i;
        diff->entries[diff->n_entries].cipher_byte = c;
        diff->entries[diff->n_entries].plain_byte = p;
        diff->entries[diff->n_entries].delta = (uint8_t)(c - p);   /* INVERSE : cipher - plain */
        diff->n_entries++;
    }
    return (0);
}

static int append_line(char **buf, size_t *cap, size_t *len, const char *line)
{
    size_t linelen = strlen(line);
    if (*len + linelen + 1 > *cap)
    {
        *cap = (*len + linelen + 1) * 2;
        char *new_buf = realloc(*buf, *cap);
        if (!new_buf)
            return (-1);
        *buf = new_buf;
    }
    strcpy(*buf + *len, line);
    *len += linelen;
    return (0);
}

char *generate_decrypt_stub(t_polyblock *target_blk, t_diff_result *diff,
    t_decrypt_method method, const char *target_label, t_format_backend *backend)
{
    char    *out_src;
    size_t  cap = 1024;
    size_t  len = 0;
    char    line[256];
    size_t  i;

    out_src = malloc(cap);
    if (!out_src)
        return (NULL);
    out_src[0] = '\0';

    if (diff->n_entries == 0)
        return (out_src);

    /* ── Rend la zone writable AVANT tout patch ── */
    snprintf(line, sizeof(line), "lea rdi, [%s]\n", target_label);
    if (append_line(&out_src, &cap, &len, line) < 0) { free(out_src); return (NULL); }
    snprintf(line, sizeof(line), "_SET rsi, %zu\n", target_blk->final_size);
    if (append_line(&out_src, &cap, &len, line) < 0) { free(out_src); return (NULL); }
    if (backend && backend->emit_make_writable_asm)
    {
        if (append_line(&out_src, &cap, &len,
                backend->emit_make_writable_asm(REG_RDI, REG_RSI)) < 0)
        {
            free(out_src);
            return (NULL);
        }
    }

    /* ── Recharge rdi (ecrase par le mprotect) avant de patcher ── */
    snprintf(line, sizeof(line), "lea rdi, [%s]\n", target_label);
    if (append_line(&out_src, &cap, &len, line) < 0) { free(out_src); return (NULL); }

    for (i = 0; i < diff->n_entries; i++)
    {
        size_t off = diff->entries[i].offset;
        size_t prev_off = (i > 0) ? diff->entries[i - 1].offset : (size_t)-1;

        if (off != prev_off + 1)
        {
            if (off != 0)
            {
                snprintf(line, sizeof(line), "lea rdi, [%s]\n", target_label);
                if (append_line(&out_src, &cap, &len, line) < 0)
                {
                    free(out_src);
                    return (NULL);
                }
                snprintf(line, sizeof(line), "add rdi, %zu\n", off);
            }
            else
                snprintf(line, sizeof(line), "lea rdi, [%s]\n", target_label);
            if (append_line(&out_src, &cap, &len, line) < 0)
            {
                free(out_src);
                return (NULL);
            }
        }

        switch (method)
        {
            case METHOD_XOR:
            {
                uint8_t k = diff->entries[i].plain_byte ^ diff->entries[i].cipher_byte;
                snprintf(line, sizeof(line), "xor [rdi], %u\n", k);
                break;
            }
            case METHOD_ADD:
            {
                if (diff->entries[i].delta == 1)
                {
                    uint8_t k = diff->entries[i].plain_byte ^ diff->entries[i].cipher_byte;
                    snprintf(line, sizeof(line), "xor [rdi], %u\n", k);
                }
                else
                    snprintf(line, sizeof(line), "add [rdi], %u\n", diff->entries[i].delta);
                break;
            }
            case METHOD_SUB:
            {
                uint8_t neg = (uint8_t)(-(int)diff->entries[i].delta);
                if (neg == 1)
                {
                    uint8_t k = diff->entries[i].plain_byte ^ diff->entries[i].cipher_byte;
                    snprintf(line, sizeof(line), "xor [rdi], %u\n", k);
                }
                else
                    snprintf(line, sizeof(line), "sub [rdi], %u\n", neg);
                break;
            }
            case METHOD_MOV:
            {
                snprintf(line, sizeof(line), "mov [rdi], %u\n", diff->entries[i].cipher_byte);
                break;
            }
            default:
                fprintf(stderr, "polyblock: methode %d non geree pour patch octet-a-octet\n", method);
                free(out_src);
                return (NULL);
        }
        if (append_line(&out_src, &cap, &len, line) < 0)
        {
            free(out_src);
            return (NULL);
        }
        if (append_line(&out_src, &cap, &len, "_INC rdi\n") < 0)
        {
            free(out_src);
            return (NULL);
        }
    }

    /* ── Rend la zone executable a nouveau APRES le patch ── */
    snprintf(line, sizeof(line), "lea rdi, [%s]\n", target_label);
    if (append_line(&out_src, &cap, &len, line) < 0) { free(out_src); return (NULL); }
    snprintf(line, sizeof(line), "_SET rsi, %zu\n", target_blk->final_size);
    if (append_line(&out_src, &cap, &len, line) < 0) { free(out_src); return (NULL); }
    if (backend && backend->emit_make_executable_asm)
    {
        if (append_line(&out_src, &cap, &len,
                backend->emit_make_executable_asm(REG_RDI, REG_RSI)) < 0)
        {
            free(out_src);
            return (NULL);
        }
    }

    return (out_src);
}

static char *replace_placeholder(const char *src, const char *placeholder, const char *replacement)
{
    char    *result;
    char    *pos;
    size_t  before_len;
    size_t  after_len;
    size_t  new_len;

    pos = strstr(src, placeholder);
    if (!pos)
        return (strdup(src));

    before_len = (size_t)(pos - src);
    after_len = strlen(pos + strlen(placeholder));
    new_len = before_len + strlen(replacement) + after_len + 1;

    result = malloc(new_len);
    if (!result)
        return (NULL);

    memcpy(result, src, before_len);
    result[before_len] = '\0';
    strcat(result, replacement);
    strcat(result, pos + strlen(placeholder));

    return (result);
}

int substitute_decrypt_slots(t_polyctx *ctx, t_block_variant *variant, t_format_backend *backend)
{
    int     i;
    char    *new_src;

    for (i = 0; i < variant->n_decrypts; i++)
    {
        t_decrypt_spec  *spec = &variant->decrypts[i];
        t_polyblock     *target;
        t_diff_result   diff;
        t_decrypt_method chosen;
        char            *stub_src;
        char            *wrapped;
        char            placeholder[64];

        target = find_block(ctx, spec->target_identifier);
        if (!target)
        {
            fprintf(stderr, "polyblock: DECRYPT cible '%s' introuvable\n",
                    spec->target_identifier);
            return (-1);
        }
        if (!target->ciphertext.bytecode || !target->plaintext.bytecode)
        {
            fprintf(stderr, "polyblock: DECRYPT cible '%s' pas encore resolue\n",
                    spec->target_identifier);
            return (-1);
        }
        if (compute_diff(&target->plaintext, &target->ciphertext, &diff) < 0)
            return (-1);

        chosen = spec->methods[rand() % spec->n_methods];
        spec->chosen_method = chosen;
        stub_src = generate_decrypt_stub(target, &diff, chosen, target->identifier, backend);
        if (!stub_src)
            return (-1);

        wrapped = malloc(strlen(stub_src) + 64);
        if (!wrapped)
        {
            free(stub_src);
            return (-1);
        }
        snprintf(wrapped, strlen(stub_src) + 64, "%%sync_push %d\n%s%%sync_pop\n",
                spec->sync == SYNC_ON ? 1 : 0, stub_src);
        free(stub_src);

        snprintf(placeholder, sizeof(placeholder), "%%decrypt_slot %d", i);
        new_src = replace_placeholder(variant->src, placeholder, wrapped);
        free(wrapped);
        if (!new_src)
            return (-1);
        free(variant->src);
        variant->src = new_src;
    }
    return (0);
}

int resolve_variant(t_asm *a, t_polyctx *ctx, t_polyblock *blk,
        t_block_variant *variant, int is_cipher)
{
    t_emitter   local_e;
    t_emitter   saved_e;
    int         label_start;
    int         fixup_start;
    int         bitlog_start;
    t_polyctx   *saved_polyctx;
    int         saved_is_cipher;
    int         saved_sync;

    variant->key_index_before = a->key_index;

    memset(&local_e, 0, sizeof(local_e));
    saved_e = a->out->e;
    a->out->e = local_e;

    saved_polyctx = a->polyctx;
    saved_is_cipher = a->current_variant_is_cipher;
    saved_sync = a->key_sync_enabled;
    a->polyctx = ctx;
    a->current_variant_is_cipher = is_cipher;
    a->key_sync_enabled = (variant->sync == SYNC_ON);

    label_start = a->nlabels;
    fixup_start = a->nfixups;
    bitlog_start = g_bit_log_len;

    if (is_cipher)
        deflabel(a, blk->identifier);

    if (assemble_source(a, variant->src) < 0)
    {
        a->out->e = saved_e;
        a->polyctx = saved_polyctx;
        a->current_variant_is_cipher = saved_is_cipher;
        a->key_sync_enabled = saved_sync;
        return (-1);
    }

    variant->bytecode = a->out->e.buf;
    variant->bytecode_len = a->out->e.len;
    variant->label_range_start = label_start;
    variant->label_range_end = a->nlabels;
    variant->fixup_range_start = fixup_start;
    variant->fixup_range_end = a->nfixups;
    variant->bitlog_range_start = bitlog_start;
    variant->bitlog_range_end = g_bit_log_len;

    a->out->e = saved_e;
    a->polyctx = saved_polyctx;
    a->current_variant_is_cipher = saved_is_cipher;
    a->key_sync_enabled = saved_sync;
    return (0);
}

static int substitute_root_decrypt_slots(t_asm *a, t_polyctx *ctx, t_format_backend *backend)
{
    int     i;
    char    *new_src;

    (void)a;
    for (i = 0; i < ctx->n_root_decrypts; i++)
    {
        t_decrypt_spec  *spec = &ctx->root_decrypts[i];
        t_polyblock     *target;
        t_diff_result   diff;
        t_decrypt_method chosen;
        char            *stub_src;
        char            placeholder[64];

        target = find_block(ctx, spec->target_identifier);
        if (!target)
        {
            fprintf(stderr, "polyblock: DECRYPT (racine) cible '%s' introuvable\n",
                    spec->target_identifier);
            return (-1);
        }
        if (!target->ciphertext.bytecode || !target->plaintext.bytecode)
        {
            fprintf(stderr, "polyblock: DECRYPT (racine) cible '%s' pas encore resolue\n",
                    spec->target_identifier);
            return (-1);
        }
        if (compute_diff(&target->plaintext, &target->ciphertext, &diff) < 0)
            return (-1);

        fprintf(stderr, "[DEBUG] diff.n_entries=%zu target->ciphertext.bytecode_len=%zu\n",
            diff.n_entries, target->ciphertext.bytecode_len);

        chosen = spec->methods[rand() % spec->n_methods];
        spec->chosen_method = chosen;
        stub_src = generate_decrypt_stub(target, &diff, chosen, target->identifier, backend);
        if (!stub_src)
            return (-1);

        snprintf(placeholder, sizeof(placeholder), "%%decrypt_slot_root %d", i);
        new_src = replace_placeholder(ctx->root_src, placeholder, stub_src);
        free(stub_src);
        if (!new_src)
            return (-1);
        free(ctx->root_src);
        ctx->root_src = new_src;
    }
    return (0);
}

int polyblock_assemble(t_asm *a, t_polyctx *ctx, t_format_backend *backend)
{
    if (polyblock_resolve_sizes(a, ctx, 0, backend) < 0)
        return (-1);

    if (substitute_root_decrypt_slots(a, ctx, backend) < 0)
        return (-1);

    fprintf(stderr, "[DEBUG] root_src apres substitution:\n---\n%s\n---\n", ctx->root_src);

    if (!ctx->root_src)
    {
        fprintf(stderr, "polyblock: aucun texte racine a assembler\n");
        return (-1);
    }

    a->polyctx = ctx;
    if (assemble_source(a, ctx->root_src) < 0)
    {
        a->polyctx = NULL;
        return (-1);
    }
    a->polyctx = NULL;

    return (0);
}