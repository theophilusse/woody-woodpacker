#ifndef POLYBLOCK_H
# define POLYBLOCK_H

# define MAX_POLYBLOCK_NAME 64
# define MAX_DECRYPT_METHODS 8
# define MAX_BREAKPOINTS 16
# define MAX_CHILDREN 32
# define MAX_POLYBLOCKS 128
# define MAX_DECRYPT_SPECS 128

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
    char        *src;              /* texte source de ce variant (avant expansion macro) */
    size_t      src_len;
    uint8_t     *bytecode;         /* bytecode assemble (rempli en phase de resolution) */
    size_t      bytecode_len;
    t_sync_mode sync;
    t_decrypt_spec *decrypts;      /* %DECRYPT trouves DANS ce variant */
    int         n_decrypts;
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
    t_polyblock     blocks[MAX_POLYBLOCKS];
    int             n_blocks;
    t_polyblock     *root;          /* point d'entree, si un seul bloc racine */

    /* table de correspondance identifier -> index dans blocks[],
    ** pour resolution rapide de %DECRYPT <identifier> */
    char            block_names[MAX_POLYBLOCKS][MAX_POLYBLOCK_NAME];
}   t_polyctx;

int polyblock_topo_sort(t_polyctx *ctx, t_polyblock **order, int *n_order);
t_polyctx *polyblock_parse_all(const char *source);

#endif