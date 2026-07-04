#include "woody.h"

/* ══════════════════════════════════════════════════════════════
** lde_verify : simule fidèlement le LDE runtime pour valider,
** AU MOMENT DE L'ASSEMBLAGE, que le stub généré permettra une
** extraction correcte de la clé. Bloque la génération sinon.
** ══════════════════════════════════════════════════════════════ */

static int lde_fetch(t_lde_dec *d, int off)
{
	if (d->pos + (size_t)off >= d->end)
		return (-1);
	return (d->buf[d->pos + off]);
}

/*
** Simule un pas du LDE runtime. Retourne :
**   -1  aucun pattern reconnu (fallback runtime, avance de 1)
**    0  pattern reconnu, ne code pas de bit
**    1  bit=0 extrait
**    2  bit=1 extrait
** *ilen recoit la longueur totale consommee (REX inclus).
*/
static int lde_step(t_lde_dec *d, int *ilen)
{
	int rex_len = 0;
	int op0 = lde_fetch(d, 0);

	if (op0 >= 0x40 && op0 <= 0x4f)
		rex_len = 1;

	int op = lde_fetch(d, rex_len);
	if (op < 0)
		return (-1);

	/* 0x24 ib : AND AL, imm8 -> bit=1 */
	if (op == 0x24)
	{
		int imm = lde_fetch(d, rex_len + 1);
		if (imm == 0x0) { *ilen = rex_len + 2; return (2); }
	}
	/* 0x80 /r ib : AND r8,0(bit1) / ADD r8,1(bit0) / SUB r8,1(bit0) */
	if (op == 0x80)
	{
		int modrm = lde_fetch(d, rex_len + 1);
		if (modrm < 0) return (-1);
		int reg = (modrm >> 3) & 7;
		int mod = (modrm >> 6) & 3;
		if (mod == 3)
		{
			int imm = lde_fetch(d, rex_len + 2);
			if (reg == 4 && imm == 0x0) { *ilen = rex_len + 3; return (2); }
			if (reg == 0 && imm == 0x1) { *ilen = rex_len + 3; return (1); }
			if (reg == 5 && imm == 0x1) { *ilen = rex_len + 3; return (1); }
		}
	}
	/* 0x81 /r id : ADD r32,1(long, bit0) / AND r32,imm32(bit0) / CMP(skip) */
	if (op == 0x81)
	{
		int modrm = lde_fetch(d, rex_len + 1);
		if (modrm < 0) return (-1);
		int reg = (modrm >> 3) & 7;
		int mod = (modrm >> 6) & 3;
		if (mod == 3)
		{
			if (reg == 0)
			{
				int i0 = lde_fetch(d, rex_len + 2);
				int i1 = lde_fetch(d, rex_len + 3);
				int i2 = lde_fetch(d, rex_len + 4);
				int i3 = lde_fetch(d, rex_len + 5);
				if (i0 == 1 && i1 == 0 && i2 == 0 && i3 == 0)
					{ *ilen = rex_len + 6; return (1); }
			}
			if (reg == 4) { *ilen = rex_len + 6; return (1); }
			if (reg == 7) { *ilen = rex_len + 6; return (0); }
		}
	}
	/* 0x83 /r ib : AND r32/64,0(bit1) / SUB r32/64,1(bit0) / CMP(skip) */
	if (op == 0x83)
	{
		int modrm = lde_fetch(d, rex_len + 1);
		if (modrm < 0) return (-1);
		int reg = (modrm >> 3) & 7;
		int mod = (modrm >> 6) & 3;
		if (mod == 3)
		{
			int imm = lde_fetch(d, rex_len + 2);
			if (reg == 4) { *ilen = rex_len + 3; return (2); }
			if (reg == 5 && imm == 1) { *ilen = rex_len + 3; return (1); }
			if (reg == 7) { *ilen = rex_len + 3; return (0); }
		}
	}
	/* 0x31 /r mod=11 meme registre : XOR reg,reg -> bit=0 */
	if (op == 0x31)
	{
		int modrm = lde_fetch(d, rex_len + 1);
		if (modrm < 0) return (-1);
		int mod = (modrm >> 6) & 3;
		int reg = (modrm >> 3) & 7;
		int rm  = modrm & 7;
		if (mod == 3 && reg == rm) { *ilen = rex_len + 2; return (1); }
	}
	/* 0x89 /r mod=11 : MOV r32/64,r32/64 -> bit=1 */
	if (op == 0x89)
	{
		int modrm = lde_fetch(d, rex_len + 1);
		if (modrm < 0) return (-1);
		int mod = (modrm >> 6) & 3;
		if (mod == 3) { *ilen = rex_len + 2; return (2); }
	}
	/* 0x8A /r : MOV r8, r/m8 -> bit=1 (mod00/01 + SIB eventuel) */
	if (op == 0x8a)
	{
		int modrm = lde_fetch(d, rex_len + 1);
		if (modrm < 0) return (-1);
		int mod = (modrm >> 6) & 3;
		int rm  = modrm & 7;
		if (mod == 0)
			{ *ilen = rex_len + 2 + (rm == 4 ? 1 : 0); return (2); }
		if (mod == 1)
			{ *ilen = rex_len + 3 + (rm == 4 ? 1 : 0); return (2); }
	}
	/* 0x8B /r : MOV r32/64, r/m -> bit=1 (mod00/01 + SIB eventuel) */
	if (op == 0x8b)
	{
		int modrm = lde_fetch(d, rex_len + 1);
		if (modrm < 0) return (-1);
		int mod = (modrm >> 6) & 3;
		int rm  = modrm & 7;
		if (mod == 0)
			{ *ilen = rex_len + 2 + (rm == 4 ? 1 : 0); return (2); }
		if (mod == 1)
			{ *ilen = rex_len + 3 + (rm == 4 ? 1 : 0); return (2); }
	}
	/* 0x8D /r : LEA reg,[reg+0] mod01(bit0) / LEA abs mod00+SIB=0x25(bit0) */
	if (op == 0x8d)
	{
		int modrm = lde_fetch(d, rex_len + 1);
		if (modrm < 0) return (-1);
		int mod = (modrm >> 6) & 3;
		int rm  = modrm & 7;
		if (mod == 0 && rm == 4)
		{
			int sib = lde_fetch(d, rex_len + 2);
			if (sib == 0x25) { *ilen = rex_len + 7; return (1); }
		}
		if (mod == 1)
			{ *ilen = rex_len + 3 + (rm == 4 ? 1 : 0); return (1); }
	}
	/* 0x0F 0xB6 /r : MOVZX -> bit=1(reg-reg mod11) / bit=0(mem mod00/01) */
	if (op == 0x0f)
	{
		int op2 = lde_fetch(d, rex_len + 1);
		if (op2 == 0xb6)
		{
			int modrm = lde_fetch(d, rex_len + 2);
			if (modrm < 0) return (-1);
			int mod = (modrm >> 6) & 3;
			int rm  = modrm & 7;
			if (mod == 3) { *ilen = rex_len + 3; return (2); }
			if (mod == 0)
				{ *ilen = rex_len + 3 + (rm == 4 ? 1 : 0); return (1); }
			if (mod == 1)
				{ *ilen = rex_len + 4 + (rm == 4 ? 1 : 0); return (1); }
		}
	}
	/* 0xB8-0xBF : MOV r32,imm32 -> bit=1 */
	if (op >= 0xb8 && op <= 0xbf)
		{ *ilen = rex_len + 5; return (2); }
	/* 0xFE/0xFF /0(INC,bit1) ou /1(DEC,bit1) */
	if (op == 0xfe || op == 0xff)
	{
		int modrm = lde_fetch(d, rex_len + 1);
		if (modrm < 0) return (-1);
		int mod = (modrm >> 6) & 3;
		int reg = (modrm >> 3) & 7;
		if (mod == 3 && (reg == 0 || reg == 1))
			{ *ilen = rex_len + 2; return (2); }
	}
	*ilen = 1;
	return (-1);
}

/*
** Simule le LDE complet sur [start,end), compare a expected_key.
** Retourne 0 si ca matche, -1 sinon (diagnostic sur stderr).
*/
int lde_verify(const uint8_t *buf, size_t start, size_t end,
		const uint8_t *expected_key, size_t key_len)
{
	t_lde_dec d = { buf, start, end };
	uint8_t   extracted[32];
	int       bitcount = 0;
	int       fallback_streak = 0;

	memset(extracted, 0, sizeof(extracted));
	(void)key_len;
	while (d.pos < d.end && bitcount < 128)
	{
		int ilen;
		int r = lde_step(&d, &ilen);
		if (r == -1)
		{
			fallback_streak++;
			if (fallback_streak > 8)
				fprintf(stderr,
					"lde_verify: desync suspecte @ off %zu (op=0x%02x), "
					"%d fallbacks consecutifs\n",
					d.pos, buf[d.pos], fallback_streak);
			d.pos += (size_t)ilen;
			continue ;
		}
		fallback_streak = 0;
		if (r == 1 || r == 2)
		{
			if (r == 2)
				extracted[bitcount / 8] |= (uint8_t)(1 << (bitcount % 8));
			bitcount++;
		}
		d.pos += (size_t)ilen;
	}
	if (bitcount < 128)
	{
		fprintf(stderr, "lde_verify: %d/128 bits extraits, fin de zone atteinte\n",
			bitcount);
		return (-1);
	}
	if (memcmp(extracted, expected_key, 16) != 0)
	{
		int i;
		fprintf(stderr, "lde_verify: MISMATCH\n  attendu : ");
		for (i = 0; i < 16; i++) fprintf(stderr, "%02X", expected_key[i]);
		fprintf(stderr, "\n  simule  : ");
		for (i = 0; i < 16; i++) fprintf(stderr, "%02X", extracted[i]);
		fprintf(stderr, "\n");
		return (-1);
	}
	return (0);
}