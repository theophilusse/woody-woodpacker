#include "woody.h"
#include "lde.h"

static int fetch(const uint8_t *buf, size_t len, size_t pos, int off)
{
    long p = (long)pos + off;
    if (p < 0 || (size_t)p >= len) return (-1);
    return (buf[(size_t)p]);
}

/*
** Retourne : -1 fallback, 0 pattern sans bit, 1 bit=0, 2 bit=1.
** *ilen = longueur totale consommée (REX inclus).
** Traduction 1:1 des blocs o_24/o_80/.../o_fe du stub.h réécrit.
*/
static int lde_step_c(const uint8_t *buf, size_t len, size_t pos, int *ilen, int verbose)
{
	int rex_len = 0;
	int op0 = fetch(buf, len, pos, 0);
	int op, modrm, mod, reg, rm, imm, sib;

	if (op0 >= 0x40 && op0 <= 0x4f)
		rex_len = 1;
	op = fetch(buf, len, pos, rex_len);
	if (op < 0) return (-1);

	/* 0x24 ib : AND AL,0 -> bit=1 */
	if (op == 0x24)
	{
		imm = fetch(buf, len, pos, rex_len + 1);
		if (imm == 0x0) { *ilen = rex_len + 2; return (2); }
	}

	/* 0x80 /r ib : AND r8,0(bit1) / ADD r8,1(bit0) / SUB r8,1(bit0) */
	if (op == 0x80)
	{
		modrm = fetch(buf, len, pos, rex_len + 1);
		if (modrm < 0) goto fallback;
		mod = (modrm >> 6) & 3; reg = (modrm >> 3) & 7;
		if (mod == 3)
		{
			imm = fetch(buf, len, pos, rex_len + 2);
			if (reg == 4 && imm == 0x0) { *ilen = rex_len + 3; return (2); }
			if (reg == 0 && imm == 0x1) { *ilen = rex_len + 3; return (1); }
			if (reg == 5 && imm == 0x1) { *ilen = rex_len + 3; return (1); }
		}
	}

	/* 0x81 /r id : ADD r32,1 long(bit0) / AND r32,imm32(bit0) / CMP(skip) */
	if (op == 0x81)
    {
        modrm = fetch(buf, len, pos, rex_len + 1);
        if (modrm < 0) goto fallback;
        mod = (modrm >> 6) & 3; reg = (modrm >> 3) & 7;
        if (mod == 3)
        {
            if (reg == 0)
            {
                int i0 = fetch(buf, len, pos, rex_len+2);
                int i1 = fetch(buf, len, pos, rex_len+3);
                int i2 = fetch(buf, len, pos, rex_len+4);
                int i3 = fetch(buf, len, pos, rex_len+5);
                if (i0==1 && i1==0 && i2==0 && i3==0)
                    { *ilen = rex_len + 6; return (1); }
            }
            if (reg == 4)
            {
                int i0 = fetch(buf, len, pos, rex_len+2);
                int i1 = fetch(buf, len, pos, rex_len+3);
                int i2 = fetch(buf, len, pos, rex_len+4);
                int i3 = fetch(buf, len, pos, rex_len+5);
                if (i0==0xff && i1==0 && i2==0 && i3==0)   /* NOUVEAU : vérifie imm==0xFF */
                    { *ilen = rex_len + 6; return (1); }
            }
            if (reg == 7) { *ilen = rex_len + 6; return (0); }
        }
    }

	/* 0x83 /r ib : AND r32/64,0(bit1) / SUB r32/64,1(bit0) / CMP(skip) */
	if (op == 0x83)
	{
		modrm = fetch(buf, len, pos, rex_len + 1);
		if (modrm < 0) goto fallback;
		mod = (modrm >> 6) & 3; reg = (modrm >> 3) & 7;
		if (mod == 3)
		{
			imm = fetch(buf, len, pos, rex_len + 2);
			if (reg == 4) { *ilen = rex_len + 3; return (2); }
			if (reg == 5 && imm == 1) { *ilen = rex_len + 3; return (1); }
			if (reg == 7) { *ilen = rex_len + 3; return (0); }
		}
	}

	/* 0x31 /r mod=11 meme registre : XOR reg,reg -> bit=0 */
	if (op == 0x31)
	{
		modrm = fetch(buf, len, pos, rex_len + 1);
		if (modrm < 0) goto fallback;
		mod = (modrm >> 6) & 3; reg = (modrm >> 3) & 7; rm = modrm & 7;
		if (mod == 3 && reg == rm) { *ilen = rex_len + 2; return (1); }
	}

	/* 0x89 /r mod=11 : MOV r32/64,r32/64 -> bit=1 */
	if (op == 0x89)
	{
		modrm = fetch(buf, len, pos, rex_len + 1);
		if (modrm < 0) goto fallback;
		mod = (modrm >> 6) & 3;
		if (mod == 3) { *ilen = rex_len + 2; return (2); }
	}

	/* 0x8A /r : MOV r8,r/m8 -> bit=1 */
	if (op == 0x8a)
	{
		modrm = fetch(buf, len, pos, rex_len + 1);
		if (modrm < 0) goto fallback;
		mod = (modrm >> 6) & 3; rm = modrm & 7;
		if (mod == 0) { *ilen = rex_len + 2 + (rm==4?1:0); return (2); }
		if (mod == 1) { *ilen = rex_len + 3 + (rm==4?1:0); return (2); }
	}

    /* 0x8B mod=01, pas de SIB, suivi de AND r32,0xFF forme longue (81/4)
    ** avec le MEME registre destination -> bit=1 (paire _SET bit=1) */
    if (op == 0x8b)
    {
        modrm = fetch(buf, len, pos, rex_len + 1);
        if (modrm < 0) goto fallback;
        mod = (modrm >> 6) & 3; rm = modrm & 7;

        if (mod == 0 || mod == 1)
        {
            int has_sib = (rm == 4);
            int base_len = rex_len + 2 + (has_sib ? 1 : 0) + (mod == 1 ? 1 : 0);
            int b0 = fetch(buf, len, pos, base_len);
            int rex2_len = (b0 >= 0x40 && b0 <= 0x4f) ? 1 : 0;
            int op2    = fetch(buf, len, pos, base_len + rex2_len);
            int modrm2 = fetch(buf, len, pos, base_len + rex2_len + 1);
            int i0 = fetch(buf, len, pos, base_len + rex2_len + 2);
            int i1 = fetch(buf, len, pos, base_len + rex2_len + 3);
            int i2 = fetch(buf, len, pos, base_len + rex2_len + 4);
            int i3 = fetch(buf, len, pos, base_len + rex2_len + 5);

            if (op2 == 0x81 && (modrm2 & 0xf8) == 0xe0 &&
                i0 == 0xff && i1 == 0 && i2 == 0 && i3 == 0)
            {
                *ilen = base_len + rex2_len + 6;
                return (2);
            }
            *ilen = base_len;
            return (2);
        }
    }

	/* 0x8D /r : LEA reg,[reg+0] mod01(bit0) / LEA abs mod00+SIB=0x25(bit0) */
	if (op == 0x8d)
    {
        modrm = fetch(buf, len, pos, rex_len + 1);
        if (modrm < 0) goto fallback;
        mod = (modrm >> 6) & 3; rm = modrm & 7;
        if (mod == 0 && rm == 4)
        {
            sib = fetch(buf, len, pos, rex_len + 2);
            if (sib == 0x25) { *ilen = rex_len + 7; return (1); }
        }
        if (mod == 0 && rm == 5)          /* NOUVEAU : RIP-relative, aucun bit */
        {
            *ilen = rex_len + 6;
            return (0);
        }
        if (mod == 1) { *ilen = rex_len + 3 + (rm==4?1:0); return (1); }
    }

	/* 0x0F 0xB6 /r : MOVZX -> bit=1(reg-reg) / bit=0(mem) */
	if (op == 0x0f)
	{
		int op2 = fetch(buf, len, pos, rex_len + 1);
		if (op2 == 0xb6)
		{
			modrm = fetch(buf, len, pos, rex_len + 2);
			if (modrm < 0) goto fallback;
			mod = (modrm >> 6) & 3; rm = modrm & 7;
			if (mod == 3) { *ilen = rex_len + 3; return (2); }
			if (mod == 0) { *ilen = rex_len + 3 + (rm==4?1:0); return (1); }
			if (mod == 1) { *ilen = rex_len + 4 + (rm==4?1:0); return (1); }
		}
	}

    /* 0xE9 : JMP rel32 -> structurel, aucun bit, 5 octets (opcode + rel32) */
    if (op == 0xe9)
    {
        *ilen = rex_len + 5;
        return (0);
    }

	/* 0xB8-0xBF : MOV r32,imm32 -> bit=1 */
	if (op >= 0xb8 && op <= 0xbf)
    {
        int prev = fetch(buf, len, pos, -1);   /* octet juste avant l'opcode courant */
        if (prev >= 0x48 && prev <= 0x4f && (prev & 0x08))
        {
            *ilen = rex_len + 9;   /* REX.W présent -> imm64 */
            return (2);
        }
        *ilen = rex_len + 5;       /* pas de REX.W -> imm32 */
        return (2);
    }

	/* 0xFE/0xFF /0(INC,bit1) /1(DEC,bit1) */
	if (op == 0xfe || op == 0xff)
	{
		modrm = fetch(buf, len, pos, rex_len + 1);
		if (modrm < 0) goto fallback;
		mod = (modrm >> 6) & 3; reg = (modrm >> 3) & 7;
		if (mod == 3 && (reg == 0 || reg == 1)) { *ilen = rex_len + 2; return (2); }
	}

fallback:
	if (verbose)
		fprintf(stderr, "  fallback @ %zu (op0=0x%02x rex_len=%d)\n", pos, op0, rex_len);
	*ilen = 1;
	return (-1);
}

int lde_bit_by_pos[8192];   /* -1 = pas de bit ici (fallback/structurel) */

int lde_bit_at_pos(size_t pos)
{
    if (pos >= 8192)
        return (-1);
    return (lde_bit_by_pos[pos]);
}

/*
** Simule le LDE sur buf[start..end), extrait 128 bits, remplit key_out[16].
** Retourne le nombre de bits extraits (128 = succès complet).
*/
int lde_run_c(const uint8_t *buf, size_t start, size_t end,
              uint8_t key_out[16], int verbose,
              int lde_bit_log[512], int *lde_bit_log_len)
{
    size_t pos = start;
    int bitcount = 0;
    int fallback_streak = 0;

    memset(key_out, 0, 16);
    memset(lde_bit_by_pos, -1, sizeof(lde_bit_by_pos));

    while (pos < end && bitcount < 128)
    {
        int ilen;
        int r = lde_step_c(buf, end, pos, &ilen, verbose);
        if (r == -1)
        {
            fallback_streak++;
            if (verbose)                                            /* RESTAURÉ */
                fprintf(stderr, "  fallback @ %zu (op0=0x%02x rex_len=0)\n",
                        pos, buf[pos]);
            pos += (size_t)ilen;
            continue;
        }
        if (fallback_streak > 0 && verbose)                          /* RESTAURÉ */
            fprintf(stderr, "  (resync apres %d fallback(s) @ %zu)\n",
                    fallback_streak, pos);
        fallback_streak = 0;
        if (verbose)                                                 /* RESTAURÉ */
            fprintf(stderr, "  step @ %zu: op0=0x%02x r=%d ilen=%d bitcount=%d\n",
                    pos, buf[pos], r, ilen, bitcount);
        if (r == 1 || r == 2)
        {
            int bit = (r == 2) ? 1 : 0;
            if (pos < 8192)
                lde_bit_by_pos[pos] = bit;
            if (bit)
                key_out[bitcount/8] |= (uint8_t)(1 << (bitcount % 8));
            lde_bit_log[*lde_bit_log_len] = bit;
            (*lde_bit_log_len)++;
            bitcount++;
        }
        pos += (size_t)ilen;
    }
    return bitcount;
}