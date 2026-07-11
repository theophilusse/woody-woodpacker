/* polyblock_parse.c */
#include "polyblock.h"

typedef struct s_line_iter
{
    const char  *src;
    size_t      pos;
    size_t      len;
}   t_line_iter;

static t_sync_mode parse_sync_flag(const char *line)
{
    if (strstr(line, "SYNC") && !strstr(line, "NOSYNC"))
        return (SYNC_ON);
    return (SYNC_NONE);
}

static int iter_next_line(t_line_iter *it, char *out, size_t maxlen)
{
    size_t i = 0;

    if (it->pos >= it->len)
        return (0);
    while (it->pos < it->len && it->src[it->pos] != '\n' && i < maxlen - 1)
        out[i++] = it->src[it->pos++];
    if (it->pos < it->len && it->src[it->pos] == '\n')
        it->pos++;
    out[i] = '\0';
    return (1);
}

static int line_is_directive(const char *line, const char *keyword)
{
    const char *p = line;

    while (*p == ' ' || *p == '\t')
        p++;
    if (*p != '%')
        return (0);
    p++;
    return (!strncmp(p, keyword, strlen(keyword)));
}

/* Extrait l'argument principal (l'identifier) d'une directive a un seul mot */
static void extract_id(const char *line, const char *keyword, char *out)
{
    const char *p = strstr(line, keyword);
    int i = 0;

    out[0] = '\0';
    if (!p)
    {
        fprintf(stderr, "polyblock: mot-cle '%s' introuvable dans la ligne\n", keyword);
        return;
    }
    p += strlen(keyword);
    while (*p == ' ' || *p == '\t')
        p++;
    while (*p && *p != ' ' && *p != '\t' && *p != '\n' && i < MAX_POLYBLOCK_NAME - 1)
        out[i++] = *p++;
    out[i] = '\0';
}

/* Buffer de travail pour accumuler le texte source d'un variant en cours */
typedef struct s_accum
{
    char    buf[8192];
    size_t  len;
}   t_accum;

static void accum_line(t_accum *acc, const char *line)
{
    size_t linelen = strlen(line);

    if (acc->len + linelen + 2 >= sizeof(acc->buf))
        return; /* TODO: gerer overflow proprement, erreur explicite */
    memcpy(acc->buf + acc->len, line, linelen);
    acc->len += linelen;
    acc->buf[acc->len++] = '\n';
    acc->buf[acc->len] = '\0';
}

static t_decrypt_method method_from_str(const char *s)
{
    if (!strcmp(s, "ADD")) return (METHOD_ADD);
    if (!strcmp(s, "SUB")) return (METHOD_SUB);
    if (!strcmp(s, "XOR")) return (METHOD_XOR);
    if (!strcmp(s, "MOV")) return (METHOD_MOV);
    if (!strcmp(s, "LEA")) return (METHOD_LEA);
    return (-1);
}

static int parse_decrypt_directive(t_polyctx *ctx, t_polyblock *blk,
        const char *line, t_block_variant *variant)
{
    char        target_id[MAX_POLYBLOCK_NAME];
    char        rest[256];
    char        *qmark;
    char        methods_part[128];
    char        breakpoints_part[128];
    t_decrypt_spec *spec;
    char        *tok;
    (void)ctx; (void)blk;

    fprintf(stderr, "[DEBUG] parse_decrypt_directive line='%s'\n", line);

    extract_id(line, "DECRYPT", target_id);
    if (target_id[0] == '\0')
    {
        fprintf(stderr, "polyblock: %%DECRYPT sans identifiant cible\n");
        return (-1);
    }
    /* rest = tout ce qui suit target_id */
    {
        const char *p = strstr(line, target_id);
        if (!p)
        {
            fprintf(stderr, "polyblock: incoherence interne, target_id introuvable dans la ligne\n");
            return (-1);
        }
        p += strlen(target_id);
        while (*p == ' ' || *p == '\t') p++;
        strncpy(rest, p, sizeof(rest) - 1);
        rest[sizeof(rest) - 1] = '\0';
    }

    if (variant->n_decrypts >= MAX_DECRYPT_SPECS)
    {
        fprintf(stderr, "polyblock: MAX_DECRYPT_SPECS depasse\n");
        return (-1);
    }
    spec = &variant->decrypts[variant->n_decrypts++];
    memset(spec, 0, sizeof(*spec));
    strncpy(spec->target_identifier, target_id, MAX_POLYBLOCK_NAME - 1);

    qmark = strchr(rest, '?');
    if (qmark)
    {
        size_t mlen = (size_t)(qmark - rest);
        strncpy(methods_part, rest, mlen);
        methods_part[mlen] = '\0';
        strncpy(breakpoints_part, qmark + 1, sizeof(breakpoints_part) - 1);
        breakpoints_part[sizeof(breakpoints_part) - 1] = '\0';
    }
    else
    {
        strncpy(methods_part, rest, sizeof(methods_part) - 1);
        methods_part[sizeof(methods_part) - 1] = '\0';
        breakpoints_part[0] = '\0';
    }

    tok = strtok(methods_part, ", \t");
    while (tok && spec->n_methods < MAX_DECRYPT_METHODS)
    {
        int m = method_from_str(tok);
        if (m < 0)
        {
            fprintf(stderr, "polyblock: methode DECRYPT inconnue '%s'\n", tok);
            return (-1);
        }
        spec->methods[spec->n_methods++] = (t_decrypt_method)m;
        tok = strtok(NULL, ", \t");
    }
    if (spec->n_methods == 0)
    {
        fprintf(stderr, "polyblock: aucune methode DECRYPT specifiee pour '%s'\n", target_id);
        return (-1);
    }

    if (breakpoints_part[0])
    {
        tok = strtok(breakpoints_part, ", \t");
        while (tok && spec->n_breakpoints < MAX_BREAKPOINTS)
        {
            char *colon = strchr(tok, ':');
            if (!colon)
            {
                fprintf(stderr, "polyblock: breakpoint DECRYPT mal forme '%s'\n", tok);
                return (-1);
            }
            *colon = '\0';
            spec->breakpoints[spec->n_breakpoints].byte_index = (size_t)strtoull(tok, NULL, 0);
            strncpy(spec->breakpoints[spec->n_breakpoints].label, colon + 1,
                    MAX_POLYBLOCK_NAME - 1);
            spec->n_breakpoints++;
            tok = strtok(NULL, ", \t");
        }
    }
    return (0);
}

/* Parse recursivement un %POLYBLOCK_START ... %POLYBLOCK_END.
** `it` doit etre positionne juste APRES la ligne %POLYBLOCK_START.
** Retourne le bloc alloue dans ctx->blocks[], ou NULL en cas d'erreur. */
static t_polyblock *parse_polyblock(t_polyctx *ctx, t_line_iter *it,
        const char *identifier, t_polyblock *parent)
{
    t_polyblock *blk;
    char        line[512];
    t_accum     *current_accum = NULL;
    int         in_ciphertext = 0;
    //int         in_plaintext = 0;
    t_accum     cipher_acc;
    t_accum     plain_acc;
    t_sync_mode cipher_sync = SYNC_NONE;   /* DECLARE ICI, une seule fois */
    t_sync_mode plain_sync = SYNC_NONE;

    fprintf(stderr, "[DEBUG] parse_polyblock('%s')\n", identifier);

    if (ctx->n_blocks >= MAX_POLYBLOCKS)
    {
        fprintf(stderr, "polyblock: MAX_POLYBLOCKS depasse\n");
        return (NULL);
    }
    blk = &ctx->blocks[ctx->n_blocks++];
    memset(blk, 0, sizeof(*blk));
    strncpy(blk->identifier, identifier, MAX_POLYBLOCK_NAME - 1);
    blk->parent = parent;
    cipher_acc.len = 0; cipher_acc.buf[0] = '\0';
    plain_acc.len = 0; plain_acc.buf[0] = '\0';

    while (iter_next_line(it, line, sizeof(line)))
    {
        if (line_is_directive(line, "POLYBLOCK_END"))
            break;

        if (line_is_directive(line, "CIPHERTEXT"))
        {
            in_ciphertext = 1;
            //in_plaintext = 0;
            cipher_sync = parse_sync_flag(line);   /* AFFECTE, pas redeclare */
            current_accum = &cipher_acc;
            continue;
        }
        if (line_is_directive(line, "PLAINTEXT"))
        {
            in_ciphertext = 0;
            //in_plaintext = 1;
            plain_sync = parse_sync_flag(line);
            current_accum = &plain_acc;
            continue;
        }
        if (line_is_directive(line, "POLYBLOCK_START"))
        {
            char child_id[MAX_POLYBLOCK_NAME];
            t_polyblock *child;

            extract_id(line, "POLYBLOCK_START", child_id);
            child = parse_polyblock(ctx, it, child_id, blk);
            if (!child)
                return (NULL);
            if (blk->n_children >= MAX_CHILDREN)
            {
                fprintf(stderr, "polyblock: MAX_CHILDREN depasse dans '%s'\n", blk->identifier);
                return (NULL);
            }
            blk->children[blk->n_children++] = child;
            if (current_accum)
            {
                char ref[128];
                snprintf(ref, sizeof(ref), "%%polyblock_ref %s", child_id);   /* minuscules, fix precedent */
                accum_line(current_accum, ref);
            }
            continue;
        }
        if (line_is_directive(line, "DECRYPT"))
        {
            int decrypt_index;

            if (parse_decrypt_directive(ctx, blk, line,
                    in_ciphertext ? &blk->ciphertext : &blk->plaintext) < 0)
                return (NULL);
            decrypt_index = (in_ciphertext ? blk->ciphertext.n_decrypts : blk->plaintext.n_decrypts) - 1;
            if (current_accum)
            {
                char ref[64];
                snprintf(ref, sizeof(ref), "%%decrypt_slot %d", decrypt_index);
                accum_line(current_accum, ref);
            }
            continue;
        }
        /* ligne normale (instruction _SET/_ZERO/etc ou label) */
        if (current_accum)
            accum_line(current_accum, line);
    }

    /* Fige les textes source ET les flags sync, UNE SEULE FOIS, apres la boucle */
    blk->ciphertext.src = strdup(cipher_acc.buf);
    blk->ciphertext.src_len = cipher_acc.len;
    blk->ciphertext.sync = cipher_sync;
    blk->plaintext.src = strdup(plain_acc.buf);
    blk->plaintext.src_len = plain_acc.len;
    blk->plaintext.sync = plain_sync;

    strncpy(ctx->block_names[ctx->n_blocks - 1], identifier, MAX_POLYBLOCK_NAME - 1);
    return (blk);
}

static int is_direct_child(t_polyblock *blk, const char *target_id)
{
    int i;

    for (i = 0; i < blk->n_children; i++)
        if (!strcmp(blk->children[i]->identifier, target_id))
            return (1);
    return (0);
}

static void collect_depends_from_variant(t_polyblock *blk, t_block_variant *variant)
{
    int i;
    int j;
    int already;

    for (i = 0; i < variant->n_decrypts; i++)
    {
        const char *target = variant->decrypts[i].target_identifier;

        if (is_direct_child(blk, target))
            continue;
        if (!strcmp(target, blk->identifier))
            continue; /* un bloc ne depend pas de lui-meme au sens topologique ici */
        already = 0;
        for (j = 0; j < blk->n_depends; j++)
            if (!strcmp(blk->depends_on[j], target))
                already = 1;
        if (!already)
        {
            if (blk->n_depends >= MAX_CHILDREN)
            {
                fprintf(stderr, "polyblock: trop de dependances pour '%s'\n", blk->identifier);
                continue;
            }
            blk->depends_on[blk->n_depends++] = strdup(target);
        }
    }
}

/* Parcourt tout l'arbre (recursif) et peuple depends_on pour chaque bloc */
static void build_dependencies(t_polyblock *blk)
{
    int i;

    collect_depends_from_variant(blk, &blk->ciphertext);
    collect_depends_from_variant(blk, &blk->plaintext);
    for (i = 0; i < blk->n_children; i++)
        build_dependencies(blk->children[i]);
}

t_polyctx *polyblock_parse_all(const char *source)
{
    t_polyctx   *ctx;
    t_line_iter it;
    char        line[512];
    t_accum     trailing;

    ctx = calloc(1, sizeof(t_polyctx));
    if (!ctx)
        return (NULL);
    trailing.len = 0;
    trailing.buf[0] = '\0';

    it.src = source;
    it.pos = 0;
    it.len = strlen(source);

    while (iter_next_line(&it, line, sizeof(line)))
    {
        if (line_is_directive(line, "POLYBLOCK_START"))
        {
            char id[MAX_POLYBLOCK_NAME];
            extract_id(line, "POLYBLOCK_START", id);
            if (!parse_polyblock(ctx, &it, id, NULL))
            {
                free(ctx);
                return (NULL);
            }
        }
        else
            accum_line(&trailing, line);   /* donnees globales / labels hors bloc */
    }

    ctx->trailing_data_src = strdup(trailing.buf);

    {
        int i;
        for (i = 0; i < ctx->n_blocks; i++)
            if (!ctx->blocks[i].parent)
                build_dependencies(&ctx->blocks[i]);
    }
    return (ctx);
}