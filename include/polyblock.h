#ifndef POLYBLOCK_H
# define POLYBLOCK_H

# include "asm.h"
# include "woody.h"
# define MAX_POLYBLOCK_NAME 64
# define MAX_DECRYPT_METHODS 8
# define MAX_BREAKPOINTS 16
# define MAX_CHILDREN 32
# define MAX_POLYBLOCKS 128
# define MAX_DECRYPT_SPECS 128

typedef struct s_asm t_asm;

typedef enum e_decrypt_method
{
    METHOD_ADD,
    METHOD_SUB,
    METHOD_XOR,
    METHOD_MOV,
    METHOD_LEA
}   t_decrypt_method;

typedef enum e_sync_mode
{
    SYNC_NONE,      /* bloc jamais compte dans key_index */
    SYNC_ON         /* bloc compte dans key_index (canal par defaut) */
    /* futur: SYNC_CHANNEL(n) pour plusieurs flux LDE */
}   t_sync_mode;

/* Un point d'interruption dans un DECRYPT : apres avoir patche
** l'octet a `byte_index`, saute vers `label`, le developpeur
** est responsable d'ecrire le jmp de retour vers
** ret_decrypt_<identifier>_<byte_index> */
typedef struct s_breakpoint
{
    size_t  byte_index;
    char    label[MAX_POLYBLOCK_NAME];   /* label externe cible */
}   t_breakpoint;

/* Specification d'un %DECRYPT : quel bloc il transforme, avec
** quelles methodes (choix aleatoire parmi celles listees),
** et ses points d'interruption eventuels */
typedef struct s_decrypt_spec
{
    char            target_identifier[MAX_POLYBLOCK_NAME];
    t_decrypt_method methods[MAX_DECRYPT_METHODS];
    int             n_methods;
    t_breakpoint    breakpoints[MAX_BREAKPOINTS];
    int             n_breakpoints;
    t_decrypt_method chosen_method;   /* resolu apres tirage aleatoire */
    size_t          emitted_offset;   /* position dans le buffer final, une fois assemble */
    size_t          emitted_len;
}   t_decrypt_spec;

/* Un bloc CIPHERTEXT ou PLAINTEXT : une des deux representations
** alternatives d'un meme espace memoire polymorphe */
typedef struct s_block_variant
{
    char        *src;
    size_t      src_len;
    uint8_t     *bytecode;
    size_t      bytecode_len;
    t_sync_mode sync;
    t_decrypt_spec decrypts[MAX_DECRYPT_SPECS];   /* tableau, pas pointeur */
    int         n_decrypts;
    int         label_range_start;
    int         label_range_end;
    int         fixup_range_start;
    int         fixup_range_end;
    size_t      key_index_before;
}   t_block_variant;

/* Un bloc polymorphe complet : le noeud de l'arbre/DAG */
typedef struct s_polyblock
{
    char            identifier[MAX_POLYBLOCK_NAME];
    t_block_variant ciphertext;
    t_block_variant plaintext;

    struct s_polyblock *parent;                    /* NULL si racine */
    struct s_polyblock *children[MAX_CHILDREN];     /* polyblocks imbriques */
    int             n_children;

    /* graphe de dependances explicites (pas l'imbrication syntaxique,
    ** mais les references croisees via %DECRYPT <other_identifier>) */
    char            *depends_on[MAX_CHILDREN];
    int             n_depends;

    /* resolu en phase de topological sort, avant assemblage final */
    int             resolved;       /* deja assemble ? evite double-traitement */
    int             visiting;       /* pour detection de cycle (DFS marquage) */

    size_t          final_offset;   /* adresse de base une fois placee dans le buffer final */
    size_t          final_size;     /* max(ciphertext.bytecode_len, plaintext.bytecode_len) */
}   t_polyblock;

/* Contexte global du preprocesseur, une instance par assemblage */
typedef struct s_polyctx
{
    t_polyblock blocks[MAX_POLYBLOCKS];
    int         n_blocks;
    char        block_names[MAX_POLYBLOCKS][MAX_POLYBLOCK_NAME];
    char        *root_src;   /* AJOUT : remplace trailing_data_src */
}   t_polyctx;

typedef struct s_diff_entry
{
    size_t  offset;         /* position dans le bloc (0-indexed) */
    uint8_t cipher_byte;
    uint8_t plain_byte;
    uint8_t delta;          /* plain_byte - cipher_byte, modulo 256 */
}   t_diff_entry;

typedef struct s_diff_result
{
    t_diff_entry    entries[8192];   /* borne large, ajustable */
    size_t          n_entries;
}   t_diff_result;

t_polyblock *find_block(t_polyctx *ctx, const char *name);
int polyblock_topo_sort(t_polyctx *ctx, t_polyblock **order, int *n_order);
t_polyctx *polyblock_parse_all(const char *source);
void polyblock_dump(t_polyctx *ctx);
int polyblock_generate_decrypts(t_asm *a, t_polyctx *ctx);
int compute_diff(t_block_variant *plain, t_block_variant *cipher, t_diff_result *diff);
char *generate_decrypt_stub(t_polyblock *target_blk, t_diff_result *diff, t_decrypt_method method, const char *target_label);
int substitute_decrypt_slots(t_polyctx *ctx, t_block_variant *variant);
int resolve_variant(t_asm *a, t_polyctx *ctx, t_polyblock *blk, t_block_variant *variant, int is_cipher);
int polyblock_resolve_sizes(t_asm *a, t_polyctx *ctx, size_t initial_position);
int polyblock_assemble(t_asm *a, t_polyctx *ctx);

#endif