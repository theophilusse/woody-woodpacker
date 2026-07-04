#include "woody.h"

typedef struct {
    const uint8_t *buf;
    size_t         pos;
    size_t         end;
} t_dec;

static int fetch(t_dec *d, int off)
{
    if (d->pos + off >= d->end) return -1;
    return d->buf[d->pos + off];
}

/* Retourne : 1 si REX présent, met *w=REX.W, avance implicitement via *rex_len */
static int decode_rex(t_dec *d, int *rex_len, int *w)
{
    int b = fetch(d, 0);
    if (b >= 0x40 && b <= 0x4F) {
        *rex_len = 1;
        *w = (b & 0x08) ? 1 : 0;
        return 1;
    }
    *rex_len = 0;
    *w = 0;
    return 0;
}

/*
 * Simule un pas du LDE : lit une instruction à d->pos, renvoie :
 *   -1  si aucun pattern reconnu (fallback, avance de 1 — DOIT ETRE RARE)
 *    0  si pattern reconnu mais ne code pas de bit (juste avance)
 *    1  bit=0 extrait
 *    2  bit=1 extrait
 * met a jour *ilen = longueur totale de l'instruction consommee
 */
static int lde_step(t_dec *d, int *ilen)
{
    int rex_len, w, opoff;
    decode_rex(d, &rex_len, &w);
    opoff = rex_len;
    int op = fetch(d, opoff);
    if (op < 0) return -1;

    /* XOR r32/r64, r32/r64 (même registre) : 31 /r mod=11 -> bit=0 */
    if (op == 0x31) {
        int modrm = fetch(d, opoff+1);
        if (modrm >= 0 && (modrm & 0xC0) == 0xC0) {
            *ilen = rex_len + 2;
            return 1; /* bit=0 */
        }
    }
    /* AND r32/r64, imm8 : 83 /4 mod=11 -> bit=1 */
    if (op == 0x83) {
        int modrm = fetch(d, opoff+1);
        if (modrm >= 0 && (modrm & 0xF8) == 0xE0) {
            *ilen = rex_len + 3;
            return 2; /* bit=1 */
        }
        /* SUB r32/r64, 1 : 83 /5 mod=11, imm==1 -> bit=0 (variante DEC) */
        if (modrm >= 0 && (modrm & 0xF8) == 0xE8) {
            int imm = fetch(d, opoff+2);
            if (imm == 1) { *ilen = rex_len + 3; return 1; }
        }
        /* CMP r32, imm8 : 83 /7 -> pas un bit de cle, juste passe */
        if (modrm >= 0 && (modrm & 0xF8) == 0xF8) {
            *ilen = rex_len + 3;
            return 0;
        }
    }
    /* MOV r32/r64, r32/r64 : 89 /r mod=11 -> bit=1 */
    if (op == 0x89) {
        int modrm = fetch(d, opoff+1);
        if (modrm >= 0 && (modrm & 0xC0) == 0xC0) {
            *ilen = rex_len + 2;
            return 2;
        }
    }
    /* LEA r32/r64, [reg+0] : 8D mod=01 disp8=0 -> bit=0 */
    if (op == 0x8D) {
        int modrm = fetch(d, opoff+1);
        if (modrm >= 0 && (modrm & 0xC0) == 0x40) {
            int rm = modrm & 0x07;
            int has_sib = (rm == 4);
            *ilen = rex_len + 2 + (has_sib ? 1 : 0) + 1 /*disp8*/;
            return 1;
        }
    }
    /* MOV r8, imm8 : B0-B7 -> bit=1 */
    if (op >= 0xB0 && op <= 0xB7) { *ilen = rex_len + 2; return 2; }
    /* MOV r32/r64, imm32/imm64 : B8-BF -> bit=1 (zero-extend) ou variante _SET immediate bit=1 */
    if (op >= 0xB8 && op <= 0xBF) { *ilen = rex_len + (w ? 9 : 5); return 2; }
    /* MOVZX r32, r/m8 : 0F B6 -> bit=0 */
    if (op == 0x0F) {
        int op2 = fetch(d, opoff+1);
        if (op2 == 0xB6) {
            int modrm = fetch(d, opoff+2);
            int mod = (modrm >> 6) & 3, rm = modrm & 7;
            int extra = (mod == 0 && rm == 4) ? 1 : (mod == 1 ? (rm==4?2:1) : 0);
            *ilen = rex_len + 3 + extra;
            return 1;
        }
    }
    /* INC/DEC r8/r32/r64 : FE,FF /0 ou /1 -> bit=1 */
    if (op == 0xFE || op == 0xFF) {
        int modrm = fetch(d, opoff+1);
        if (modrm >= 0 && ((modrm & 0xF8) == 0xC0 || (modrm & 0xF8) == 0xC8)) {
            *ilen = rex_len + 2;
            return 2;
        }
    }
    /* ADD r8/r32, 1 : 80/0 ou 81/0 -> bit=0 (variante INC) */
    if (op == 0x80) {
        int modrm = fetch(d, opoff+1);
        if (modrm >= 0 && (modrm & 0xF8) == 0xC0) {
            int imm = fetch(d, opoff+2);
            if (imm == 1) { *ilen = rex_len + 3; return 1; }
        }
        /* SUB r8, 1 -> bit=0 (variante DEC) */
        if (modrm >= 0 && (modrm & 0xF8) == 0xE8) {
            int imm = fetch(d, opoff+2);
            if (imm == 1) { *ilen = rex_len + 3; return 1; }
        }
    }
    if (op == 0x81) {
        int modrm = fetch(d, opoff+1);
        if (modrm >= 0 && (modrm & 0xF8) == 0xC0) {
            /* ADD r32, imm32 (forme longue 6o) -> bit=0 (variante INC) */
            *ilen = rex_len + 6;
            return 1;
        }
    }
    /* fallback : rien reconnu */
    *ilen = 1;
    return -1;
}

/*
 * Simule le LDE complet, extrait jusqu'à 128 bits, les compare a expected_key.
 * Retourne 0 si ca matche, -1 sinon (avec diagnostic sur stderr).
 */
int lde_verify(const uint8_t *buf, size_t start, size_t end,
               const uint8_t *expected_key, size_t key_len)
{
    t_dec d = { buf, start, end };
    uint8_t extracted[32] = {0};
    int bitcount = 0;
    int fallback_streak = 0;
    (void)key_len;

    while (d.pos < d.end && bitcount < 128)
    {
        int ilen;
        int r = lde_step(&d, &ilen);
        if (r == -1) {
            fallback_streak++;
            if (fallback_streak > 8) {
                fprintf(stderr,
                    "lde_verify: desync suspecte @ offset %zu (opcode=0x%02x), "
                    "%d fallbacks consecutifs\n",
                    d.pos, buf[d.pos], fallback_streak);
            }
            d.pos += ilen;
            continue;
        }
        fallback_streak = 0;
        if (r == 1 || r == 2) {
            int bit = (r == 2) ? 1 : 0;
            if (bit)
                extracted[bitcount/8] |= (1 << (bitcount % 8));
            bitcount++;
        }
        d.pos += ilen;
    }

    if (bitcount < 128) {
        fprintf(stderr, "lde_verify: seulement %d bits extraits (128 attendus), "
                "scan termine trop tot (fin de buffer atteinte)\n", bitcount);
        return -1;
    }

    if (memcmp(extracted, expected_key, 16) != 0) {
        fprintf(stderr, "lde_verify: MISMATCH\n  attendu : ");
        for (int i = 0; i < 16; i++) fprintf(stderr, "%02X", expected_key[i]);
        fprintf(stderr, "\n  simule  : ");
        for (int i = 0; i < 16; i++) fprintf(stderr, "%02X", extracted[i]);
        fprintf(stderr, "\n");
        return -1;
    }

    fprintf(stderr, "lde_verify: OK, cle correctement extractible par le LDE\n");
    return 0;
}