#include "woody.h"

static char	*src_load(const char *path)
{
	FILE *f;
	long current_position;
    size_t size;
    char *raw;

	if (!path)
		return (NULL);
	f = fopen(path, "r");
	if (f == NULL)
	{
		printf("Error reading %s\n", path);
		return (NULL);
	}
	current_position = ftell(f);
	if (fseek(f, 0, SEEK_END) == -1)
	{
		printf("Error reading %s\n", path);
		fclose(f);
		return (NULL);
	}
	size = (size_t)ftell(f);
	fseek(f, current_position, SEEK_SET);
	if (!(raw = malloc(size)))
	{
		printf("Error allocating memory\n");
		fclose(f);
		return (NULL);
	}
	memset(raw, 0, size);
	if (fread(raw, 1, size, f) != size)
	{
		printf("Error reading %s\n", path);
		fclose(f);
		free(raw);
		return (NULL);
	}
	fclose(f);
    return (raw);
}

char *build_stub_source(const t_opts *opts)
{
    size_t      total_len;
    char        *result;
    const char  *blocks[32];
    int         n;
    int         i;

    n = 0;
    if (1)
    {
        blocks[n++] = STUB_SCAN_START;
        blocks[n++] = STUB_POLY_DEMO_BLOCKS;
        blocks[n++] = STUB_SCAN_END;
        blocks[n++] = STUB_POLY_DEMO_DATA;
    }
    if (0)
    {
        blocks[n++] = STUB_AV_DETECT;
        blocks[n++] = STUB_FOOTER;
        blocks[n++] = STUB_AV_DATA;
    }
    if (0)
    {
        if (opts->source != NULL)
        {
            return (src_load(opts->source));
        }
        else
        {
            blocks[n++] = STUB_SCAN_START;
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
            
            if (opts->debug_display)
            {
                blocks[n++] = STUB_DEBUG_HEXBUF_SETUP;
                blocks[n++] = STUB_DEBUG_HEXBUF_WRITE;
                blocks[n++] = STUB_DEBUG_HEXBUF_TEARDOWN;
            }
            blocks[n++] = STUB_PIE_BASE_CALC;
            blocks[n++] = STUB_MPROTECT;
            blocks[n++] = STUB_KSA;
            blocks[n++] = STUB_PRGA;
            blocks[n++] = STUB_SCAN_END;
            blocks[n++] = STUB_FOOTER;

            /* ── Données embarquées ── */
            if (opts->use_antidebug)
                blocks[n++] = STUB_DATA_EVAMSG;
            blocks[n++] = STUB_DATA_WOODYMSG;
            if (!opts->use_lde)
                blocks[n++] = STUB_DATA_CLEARKEY;
        }
    }

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