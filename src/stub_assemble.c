#include "woody.h"

char *build_stub_source(const t_opts *opts)
{
    size_t      total_len;
    char        *result;
    const char  *blocks[32];
    int         n;
    int         i;

    n = 0;
    blocks[n++] = STUB_HEADER;

    /* ── Anti-debug (ptrace) ── */
    if (opts->use_antidebug)
    {
        blocks[n++] = STUB_ANTIDEBUG_1;
        blocks[n++] = STUB_ANTIDEBUG_PROLOGUE;
        blocks[n++] = STUB_DEBUGGER_DETECTED;
        blocks[n++] = STUB_EVASION_FAIL;
    }
    blocks[n++] = STUB_NO_ANTIDEBUG;
    blocks[n++] = STUB_EVASION_COMPLETE;

    /* ── Source de la clé : LDE ou copie directe en clair ── */
    if (opts->use_lde)
        blocks[n++] = STUB_ZERO_KEY;
    else
        blocks[n++] = STUB_ZERO_KEY_NOLDE;

    /* ── Corps du LDE : actif (scan complet) ou bypass (rbp deja rempli) ── */
    if (opts->use_lde)
    {
        blocks[n++] = STUB_RUN_LDE_ACTIVE;
        /* Piege anti-debug par corruption silencieuse (0xCC).
        ** Si desactive : on omet simplement ce bloc, l'execution tombe
        ** en fallthrough directement dans STUB_LDE_CORE_EPILOGUE (@o_24). */
        if (opts->use_int3_trap)
            blocks[n++] = STUB_LDE_INT3_TRAP;
        blocks[n++] = STUB_LDE_CORE_EPILOGUE;
    }
    else
    {
        blocks[n++] = STUB_RUN_LDE_BYPASS;
        /* Le dispatch complet doit rester present car @lde_done/@after_lde
        ** sont references par jmp @oep et d'autres blocs, meme si ce code
        ** n'est jamais execute en pratique (bypass saute direct a @lde_done). */
    }
    blocks[n++] = STUB_LDE_DONE;

    blocks[n++] = STUB_WRITE_WOODY;
    blocks[n++] = STUB_AFTER_LDE;
    //
    //blocks[n++] = STUB_WRITE_KEY;
    blocks[n++] = STUB_MPROTECT_KSA_PRGA;
    blocks[n++] = STUB_FREE;
    blocks[n++] = STUB_FOOTER;

    /* ── Données embarquées ── */
    if (opts->use_antidebug)
        blocks[n++] = STUB_DATA_EVAMSG;
    blocks[n++] = STUB_DATA_WOODYMSG;
    if (!opts->use_lde)
        blocks[n++] = STUB_DATA_CLEARKEY;

    /* ── Calcul de la taille totale et concatenation ── */
    total_len = 0;
    for (i = 0; i < n; i++)
        total_len += strlen(blocks[i]);

    result = malloc(total_len + 1);
    if (!result)
        return (NULL);
    result[0] = '\0';
    for (i = 0; i < n; i++)
        strcat(result, blocks[i]);

    return (result);
}