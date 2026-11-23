#include "emit.h"

/* Encode ModR/M (rm=4 -> SIB) + SIB + disp8/disp32 optionnel.
** Contrainte LDE :
** - si has_disp == 0 et disp == 0 et (base & 7) != 5 -> mod = 00 (pas de disp8)
** - si has_disp != 0 ou disp != 0 ou (base & 7) == 5 -> mod = 01 (disp8) si dans [-128,127], sinon mod = 10 (disp32)
*/
static void emit_modrm_sib_disp(uint8_t *b, int *n, uint8_t reg_field,
                                t_reg base, t_reg idx, uint8_t scale,
                                int32_t disp, int force_disp8)
{
	int need_disp  = force_disp8 || (disp != 0) || ((base & 7) == 5);
	int use_disp32 = need_disp && (disp < -128 || disp > 127);
	uint8_t mod    = !need_disp ? 0 : (use_disp32 ? 2 : 1);

	b[(*n)++] = MODRM(mod, reg_field, 4);
	b[(*n)++] = SIB(scale, idx, base);
	if (need_disp)
	{
		if (use_disp32)
		{
			memcpy(b + (*n), &disp, 4);
			*n += 4;
		}
		else
		{
			b[(*n)++] = (uint8_t)(int8_t)disp;
		}
	}
}

/* ── prefixe REX ─────────────────────────────────────────────
** 0100 W R X B
**   W = operande 64 bits
**   R = extension bit 4 de ModRM.reg
**   X = extension bit 4 de SIB.idx
**   B = extension bit 4 de ModRM.rm / opcode+reg
** On n'emet le prefixe que s'il est different de 0x40 (vide)
** ──────────────────────────────────────────────────────────── */
static uint8_t mk_rex(int w, t_reg reg, t_reg rm)
{
	return (uint8_t)(0x40
		| (w       ? 0x08 : 0)
		| (reg >= 8 ? 0x04 : 0)
		| (rm  >= 8 ? 0x01 : 0));
}

static uint8_t mk_rex_sib(int w, t_reg reg, t_reg idx, t_reg base)
{
	return (uint8_t)(0x40
		| (w        ? 0x08 : 0)
		| (reg  >= 8 ? 0x04 : 0)
		| (idx  >= 8 ? 0x02 : 0)
		| (base >= 8 ? 0x01 : 0));
}

/* emet le REX seulement s'il est utile (evite le byte superflu 0x40) */
/*
static int emit_rex(t_emitter *e, uint8_t r)
{
	if (r != 0x40)
		return emit_raw(e, &r, 1);
	return 0;
}
*/

/* ── fondamentales ───────────────────────────────────────────── */
int	emit_raw(t_emitter *e, const uint8_t *bytes, size_t n)
{
	uint8_t	*tmp;
	size_t	new_cap;

	if (!e || !bytes) return (-1);
	if (e->len + n > e->cap)
	{
		new_cap = e->cap == 0 ? 64 : e->cap;
		while (new_cap < e->len + n) new_cap *= 2;
		tmp = realloc(e->buf, new_cap);
		if (!tmp) return (-1);
		e->buf = tmp; e->cap = new_cap;
	}
	memcpy(e->buf + e->len, bytes, n);
	e->len += n;
	return (0);
}

void	patch_disp32(t_emitter *e, size_t at, int32_t value)
	{ memcpy(e->buf + at, &value, 4); }
void	patch_disp32_buf(uint8_t *buf, size_t at, int32_t value)
	{ memcpy(buf + at, &value, 4); }

/* ── pile ────────────────────────────────────────────────────── */
int emit_push_r64(t_emitter *e, t_reg reg)
{
    uint8_t b[2]; int n = 0;
    uint8_t r = mk_rex(0, 0, reg);
    if (r != 0x40) b[n++] = r;
    b[n++] = 0x50 + (reg & 7);
    return emit_raw(e, b, n);
}

int	emit_pop_r64(t_emitter *e, t_reg reg)
{
	uint8_t b[2]; int n = 0;
	uint8_t r = mk_rex(0, 0, reg);
	if (r != 0x40) b[n++] = r;
	b[n++] = 0x58 + (reg & 7);
	return emit_raw(e, b, n);
}

int	emit_sub_rsp_imm32(t_emitter *e, uint32_t imm)
{
	uint8_t b[7] = {0x48, 0x81, MODRM11(5, REG_RSP)};
	memcpy(b + 3, &imm, 4);
	return emit_raw(e, b, 7);
}

int	emit_add_rsp_imm32(t_emitter *e, uint32_t imm)
{
	uint8_t b[7] = {0x48, 0x81, MODRM11(0, REG_RSP)};
	memcpy(b + 3, &imm, 4);
	return emit_raw(e, b, 7);
}

/* ── rip-relative ────────────────────────────────────────────── */
int	emit_lea_rip(t_emitter *e, t_reg dst, size_t *patch_offset)
{
	uint8_t b[7];
	b[0] = mk_rex(1, dst, 0);
	b[1] = 0x8D;
	b[2] = MODRM00(dst, 5);   /* rm=101 = RIP-relative */
	memset(b + 3, 0, 4);
	*patch_offset = e->len + 3;
	return emit_raw(e, b, 7);
}

/* ── mov ─────────────────────────────────────────────────────── */
int	emit_mov_r8_r8(t_emitter *e, t_reg dst, t_reg src)
{
	uint8_t b[3]; int n = 0;
	uint8_t r = mk_rex(0, src, dst);
	if (r != 0x40) b[n++] = r;
	b[n++] = 0x88;
	b[n++] = MODRM11(src, dst);
	return emit_raw(e, b, n);
}

int	emit_mov_r8_imm8(t_emitter *e, t_reg reg, uint8_t imm)
{
	uint8_t b[3]; int n = 0;
	uint8_t r = mk_rex(0, 0, reg);
	if (r != 0x40) b[n++] = r;
	b[n++] = 0xB0 + (reg & 7);
	b[n++] = imm;
	return emit_raw(e, b, n);
}

int	emit_mov_r32_r32(t_emitter *e, t_reg dst, t_reg src)
{
	uint8_t b[3]; int n = 0;
	uint8_t r = mk_rex(0, src, dst);
	if (r != 0x40) b[n++] = r;
	b[n++] = 0x89;
	b[n++] = MODRM11(src, dst);
	return emit_raw(e, b, n);
}

int	emit_mov_r32_imm32(t_emitter *e, t_reg dst, uint32_t imm)
{
	uint8_t b[6]; int n = 0;
	uint8_t r = mk_rex(0, 0, dst);
	if (r != 0x40) b[n++] = r;
	b[n++] = 0xB8 + (dst & 7);
	memcpy(b + n, &imm, 4); n += 4;
	return emit_raw(e, b, n);
}

int	emit_mov_r64_r64(t_emitter *e, t_reg dst, t_reg src)
{
	uint8_t b[3];
	b[0] = mk_rex(1, src, dst);
	b[1] = 0x89;
	b[2] = MODRM11(src, dst);
	return emit_raw(e, b, 3);
}

int	emit_mov_r64_imm64(t_emitter *e, t_reg dst, uint64_t imm)
{
	uint8_t b[10];
	b[0] = mk_rex(1, 0, dst);
	b[1] = 0xB8 + (dst & 7);
	memcpy(b + 2, &imm, 8);
	return emit_raw(e, b, 10);
}

/* MOV r8, [base] : 8A /r mod=00 */
int emit_mov_r8_mem_reg(t_emitter *e, t_reg reg_dest, t_reg base)
{
    uint8_t b[3]; int n = 0;
    uint8_t r = mk_rex(0, reg_dest, base);
    if (r != 0x40) b[n++] = r;
    b[n++] = 0x8A;
    b[n++] = MODRM00(reg_dest, base);
    return emit_raw(e, b, n);
}

/* MOV r32, [base] : 8B /r mod=00 */
int emit_mov_r32_mem_reg(t_emitter *e, t_reg dst, t_reg base)
{
    uint8_t b[3]; int n = 0;
    uint8_t r = mk_rex(0, dst, base);
    if (r != 0x40) b[n++] = r;
    b[n++] = 0x8B;
    b[n++] = MODRM00(dst, base);
    return emit_raw(e, b, n);
}

/* MOV r64, [base] : 8B /r mod=00 */
int emit_mov_r64_mem_reg(t_emitter *e, t_reg dst, t_reg base)
{
    uint8_t b[3]; int n = 0;
    uint8_t r = mk_rex(1, dst, base);
    if (r != 0x40) b[n++] = r;
    b[n++] = 0x8B;
    b[n++] = MODRM00(dst, base);
    return emit_raw(e, b, n);
}


/* MOV r32, [base+disp8] : 8B /r mod=01 */
int	emit_mov_r32_mem_disp8(t_emitter *e, t_reg dst, t_reg base, int8_t disp)
{
	uint8_t b[4]; int n = 0;
	uint8_t r = mk_rex(0, dst, base);
	if (r != 0x40) b[n++] = r;
	b[n++] = 0x8B;
	b[n++] = MODRM01(dst, base);
	b[n++] = (uint8_t)disp;
	return emit_raw(e, b, n);
}

/* ── xor ─────────────────────────────────────────────────────── */
int	emit_xor_r32_r32(t_emitter *e, t_reg dst, t_reg src)
{
	uint8_t b[3]; int n = 0;
	uint8_t r = mk_rex(0, src, dst);
	if (r != 0x40) b[n++] = r;
	b[n++] = 0x31;
	b[n++] = MODRM11(src, dst);
	return emit_raw(e, b, n);
}

int	emit_xor_r64_r64(t_emitter *e, t_reg dst, t_reg src)
{
	uint8_t b[3];
	b[0] = mk_rex(1, src, dst);
	b[1] = 0x31;
	b[2] = MODRM11(src, dst);
	return emit_raw(e, b, 3);
}

int	emit_xor_r8_r8(t_emitter *e, t_reg dst, t_reg src)
{
	uint8_t b[3]; int n = 0;
	uint8_t r = mk_rex(0, src, dst);
	if (r != 0x40) b[n++] = r;
	b[n++] = 0x30;
	b[n++] = MODRM11(src, dst);
	return emit_raw(e, b, n);
}

/* ── and ─────────────────────────────────────────────────────── */
int	emit_and_r8_imm8(t_emitter *e, t_reg reg, uint8_t imm)
{
	/* forme courte pour AL uniquement */
	if (reg == REG_RAX) {
		uint8_t b[2] = {0x24, imm}; return emit_raw(e, b, 2);
	}
	uint8_t b[4]; int n = 0;
	uint8_t r = mk_rex(0, 0, reg);
	if (r != 0x40) b[n++] = r;
	b[n++] = 0x80; b[n++] = MODRM11(4, reg); b[n++] = imm;
	return emit_raw(e, b, n);
}

int	emit_and_r32_imm8(t_emitter *e, t_reg reg, uint8_t imm)
{
	uint8_t b[4]; int n = 0;
	uint8_t r = mk_rex(0, 0, reg);
	if (r != 0x40) b[n++] = r;
	b[n++] = 0x83; b[n++] = MODRM11(4, reg); b[n++] = imm;
	return emit_raw(e, b, n);
}

int	emit_and_r32_imm32(t_emitter *e, t_reg reg, uint32_t imm)
{
	uint8_t b[7]; int n = 0;
	uint8_t r = mk_rex(0, 0, reg);
	if (r != 0x40) b[n++] = r;
	b[n++] = 0x81; b[n++] = MODRM11(4, reg);
	memcpy(b + n, &imm, 4); n += 4;
	return emit_raw(e, b, n);
}

int	emit_and_r64_imm8(t_emitter *e, t_reg dst, uint8_t imm)
{
	uint8_t b[4];
	b[0] = mk_rex(1, 0, dst);
	b[1] = 0x83;
	b[2] = MODRM11(4, dst);
	b[3] = imm;
	return emit_raw(e, b, 4);
}

/* ── add ─────────────────────────────────────────────────────── */
int	emit_add_r8_r8(t_emitter *e, t_reg dst, t_reg src)
{
	uint8_t b[3]; int n = 0;
	uint8_t r = mk_rex(0, src, dst);
	if (r != 0x40) b[n++] = r;
	b[n++] = 0x00; b[n++] = MODRM11(src, dst);
	return emit_raw(e, b, n);
}

int	emit_add_r8_imm8(t_emitter *e, t_reg reg, uint8_t imm)
{
	uint8_t b[4]; int n = 0;
	uint8_t r = mk_rex(0, 0, reg);
	if (r != 0x40) b[n++] = r;
	b[n++] = 0x80; b[n++] = MODRM11(0, reg); b[n++] = imm;
	return emit_raw(e, b, n);
}

int	emit_add_r32_imm8(t_emitter *e, t_reg reg, int8_t imm)
{
	uint8_t b[4]; int n = 0;
	uint8_t r = mk_rex(0, 0, reg);
	if (r != 0x40) b[n++] = r;
	b[n++] = 0x83; b[n++] = MODRM11(0, reg); b[n++] = (uint8_t)imm;
	return emit_raw(e, b, n);
}

/* ADD r32, imm32 : 81 /0 id (6 octets, distinct de 83 pour le LDE) */
int emit_add_r32_imm32_long(t_emitter *e, t_reg dst, uint32_t imm)
{
    uint8_t b[7]; int n = 0;
    uint8_t r = mk_rex(0, 0, dst);
    if (r != 0x40) b[n++] = r;      /* +1 octet SI REX necessaire */
    b[n++] = 0x81;                   /* opcode */
    b[n++] = MODRM11(0, dst);        /* modrm */
    memcpy(b + n, &imm, 4); n += 4;  /* imm32 */
    return emit_raw(e, b, n);
}

int	emit_add_r64_imm8(t_emitter *e, t_reg reg, int8_t imm)
{
	uint8_t b[4];
	b[0] = mk_rex(1, 0, reg);
	b[1] = 0x83; b[2] = MODRM11(0, reg); b[3] = (uint8_t)imm;
	return emit_raw(e, b, 4);
}

/* ── sub ─────────────────────────────────────────────────────── */
int	emit_sub_r32_imm8(t_emitter *e, t_reg reg, int8_t imm)
{
	uint8_t b[4]; int n = 0;
	uint8_t r = mk_rex(0, 0, reg);
	if (r != 0x40) b[n++] = r;
	b[n++] = 0x83; b[n++] = MODRM11(5, reg); b[n++] = (uint8_t)imm;
	return emit_raw(e, b, n);
}

/* ── inc / dec ───────────────────────────────────────────────── */
int	emit_inc_r8(t_emitter *e, t_reg reg)
{
	uint8_t b[3]; int n = 0;
	/* REX requis pour acceder aux registres low-byte r8b-r15b */
	uint8_t r = mk_rex(0, 0, reg);
	if (r != 0x40 || reg >= 4) b[n++] = r;
	b[n++] = 0xFE; b[n++] = MODRM11(0, reg);
	return emit_raw(e, b, n);
}

int	emit_inc_r32(t_emitter *e, t_reg reg)
{
	uint8_t b[3]; int n = 0;
	uint8_t r = mk_rex(0, 0, reg);
	if (r != 0x40) b[n++] = r;
	b[n++] = 0xFF; b[n++] = MODRM11(0, reg);
	return emit_raw(e, b, n);
}

int	emit_inc_r64(t_emitter *e, t_reg reg)
{
	uint8_t b[3];
	b[0] = mk_rex(1, 0, reg);
	b[1] = 0xFF; b[2] = MODRM11(0, reg);
	return emit_raw(e, b, 3);
}

int	emit_dec_r8(t_emitter *e, t_reg reg)
{
	uint8_t b[3]; int n = 0;
	uint8_t r = mk_rex(0, 0, reg);
	if (r != 0x40 || reg >= 4) b[n++] = r;
	b[n++] = 0xFE; b[n++] = MODRM11(1, reg);
	return emit_raw(e, b, n);
}

int	emit_dec_r32(t_emitter *e, t_reg reg)
{
	uint8_t b[3]; int n = 0;
	uint8_t r = mk_rex(0, 0, reg);
	if (r != 0x40) b[n++] = r;
	b[n++] = 0xFF; b[n++] = MODRM11(1, reg);
	return emit_raw(e, b, n);
}

int	emit_dec_r64(t_emitter *e, t_reg reg)
{
	uint8_t b[3];
	b[0] = mk_rex(1, 0, reg);
	b[1] = 0xFF; b[2] = MODRM11(1, reg);
	return emit_raw(e, b, 3);
}

/* ── sar / shr ───────────────────────────────────────────────── */
int	emit_sar_r32_imm8(t_emitter *e, t_reg reg, uint8_t imm)
{
	uint8_t b[4]; int n = 0;
	uint8_t r = mk_rex(0, 0, reg);
	if (r != 0x40) b[n++] = r;
	b[n++] = 0xC1; b[n++] = MODRM11(7, reg); b[n++] = imm;
	return emit_raw(e, b, n);
}

/* ── movzx ───────────────────────────────────────────────────── */
int	emit_movzx_r32_r8(t_emitter *e, t_reg dst, t_reg src)
{
	uint8_t b[4]; int n = 0;
	uint8_t r = mk_rex(0, dst, src);
	if (r != 0x40) b[n++] = r;
	b[n++] = 0x0F; b[n++] = 0xB6; b[n++] = MODRM11(dst, src);
	return emit_raw(e, b, n);
}

int	emit_movzx_r32_mem_reg(t_emitter *e, t_reg dst, t_reg base)
{
	uint8_t b[4]; int n = 0;
	uint8_t r = mk_rex(0, dst, base);
	if (r != 0x40) b[n++] = r;
	b[n++] = 0x0F; b[n++] = 0xB6; b[n++] = MODRM00(dst, base);
	return emit_raw(e, b, n);
}

int	emit_movzx_r32_mem_disp8(t_emitter *e, t_reg dst, t_reg base, int8_t disp)
{
	uint8_t b[5]; int n = 0;
	uint8_t r = mk_rex(0, dst, base);
	if (r != 0x40) b[n++] = r;
	b[n++] = 0x0F; b[n++] = 0xB6;
	b[n++] = MODRM01(dst, base); b[n++] = (uint8_t)disp;
	return emit_raw(e, b, n);
}

/* ── or ──────────────────────────────────────────────────────── */
int	emit_or_r8_r8(t_emitter *e, t_reg dst, t_reg src)
{
	uint8_t b[3]; int n = 0;
	uint8_t r = mk_rex(0, src, dst);
	if (r != 0x40) b[n++] = r;
	b[n++] = 0x08; b[n++] = MODRM11(src, dst);
	return emit_raw(e, b, n);
}

int	emit_or_r32_imm32(t_emitter *e, t_reg reg, uint32_t imm)
{
	uint8_t b[7]; int n = 0;
	uint8_t r = mk_rex(0, 0, reg);
	if (r != 0x40) b[n++] = r;
	b[n++] = 0x81; b[n++] = MODRM11(1, reg);
	memcpy(b + n, &imm, 4); n += 4;
	return emit_raw(e, b, n);
}

/* ── cmp ─────────────────────────────────────────────────────── */
int	emit_cmp_r32_imm8(t_emitter *e, t_reg reg, int8_t imm)
{
	uint8_t b[4]; int n = 0;
	uint8_t r = mk_rex(0, 0, reg);
	if (r != 0x40) b[n++] = r;
	b[n++] = 0x83; b[n++] = MODRM11(7, reg); b[n++] = (uint8_t)imm;
	return emit_raw(e, b, n);
}

int	emit_cmp_r32_imm32(t_emitter *e, t_reg reg, int32_t imm)
{
	uint8_t b[7]; int n = 0;
	uint8_t r = mk_rex(0, 0, reg);
	if (r != 0x40) b[n++] = r;
	b[n++] = 0x81; b[n++] = MODRM11(7, reg);
	memcpy(b + n, &imm, 4); n += 4;
	return emit_raw(e, b, n);
}

int	emit_cmp_r32_r32(t_emitter *e, t_reg dst, t_reg src)
{
	uint8_t b[3]; int n = 0;
	uint8_t r = mk_rex(0, src, dst);
	if (r != 0x40) b[n++] = r;
	b[n++] = 0x39; b[n++] = MODRM11(src, dst);
	return emit_raw(e, b, n);
}

int	emit_cmp_r64_r64(t_emitter *e, t_reg dst, t_reg src)
{
	uint8_t b[3];
	b[0] = mk_rex(1, src, dst);
	b[1] = 0x39; b[2] = MODRM11(src, dst);
	return emit_raw(e, b, 3);
}

int	emit_cmp_r64_imm32(t_emitter *e, t_reg dst, int32_t imm)
{
	uint8_t b[7];
	b[0] = mk_rex(1, 0, dst);
	b[1] = 0x81; b[2] = MODRM11(7, dst);
	memcpy(b + 3, &imm, 4);
	return emit_raw(e, b, 7);
}

/* ── sauts ───────────────────────────────────────────────────── */
int	emit_jcc_rel8(t_emitter *e, uint8_t op, size_t *patch_offset)
{
	uint8_t b[2] = {op, 0};
	*patch_offset = e->len + 1;
	return emit_raw(e, b, 2);
}

int	emit_jcc_rel8_direct(t_emitter *e, uint8_t op, int8_t disp)
{
	uint8_t b[2] = {op, (uint8_t)disp};
	return emit_raw(e, b, 2);
}

int	emit_jmp_rel32(t_emitter *e, size_t *patch_offset)
{
	uint8_t b[5] = {0xE9, 0, 0, 0, 0};
	*patch_offset = e->len + 1;
	return emit_raw(e, b, 5);
}

/* ── syscall ─────────────────────────────────────────────────── */
int	emit_syscall(t_emitter *e)
{
	uint8_t b[2] = {0x0F, 0x05};
	return emit_raw(e, b, 2);
}

/* ── shl ─────────────────────────────────────────────────────── */
int	emit_shl_r8_cl(t_emitter *e, t_reg reg)
{
	uint8_t b[3]; int n = 0;
	uint8_t r = mk_rex(0, 0, reg);
	if (r != 0x40) b[n++] = r;
	b[n++] = 0xD2; b[n++] = MODRM11(4, reg);
	return emit_raw(e, b, n);
}

/* ── shr ─────────────────────────────────────────────────────── */
int	emit_shr_r64_imm8(t_emitter *e, t_reg reg, uint8_t imm)
{
	uint8_t b[4]; int n = 0;
	uint8_t r = mk_rex(1, 0, reg);
	if (r != 0x40) b[n++] = r;
	b[n++] = 0xC1;
	b[n++] = 0xE8 | (reg & 0x07);
	b[n++] = imm;
	return emit_raw(e, b, n);
}

int	emit_shr_r32_imm8(t_emitter *e, t_reg reg, uint8_t imm)
{
	uint8_t b[4]; int n = 0;
	uint8_t r = mk_rex(0, 0, reg);
	if (r != 0x40) b[n++] = r;
	b[n++] = 0xC1;
	b[n++] = 0xE8 | (reg & 0x07);
	b[n++] = imm;
	return emit_raw(e, b, n);
}

int	emit_shr_r8_imm8(t_emitter *e, t_reg reg, uint8_t imm)
{
	uint8_t b[4]; int n = 0;
	uint8_t r = mk_rex(0, 0, reg);
	if (r != 0x40) b[n++] = r;
	b[n++] = 0xC0;
	b[n++] = 0xE8 | (reg & 0x07);
	b[n++] = imm;
	return emit_raw(e, b, n);
}

/* test ------- */
int	emit_test_r8_r8(t_emitter *e, t_reg reg1, t_reg reg2)
{
	uint8_t b[3]; int n = 0;
	uint8_t r = mk_rex(0, reg1, reg2);
	if (r != 0x40) b[n++] = r;
	b[n++] = 0x84;
	b[n++] = 0xC0 | ((reg1 & 0x07) << 3) | (reg2 & 0x07);
	return emit_raw(e, b, n);
}

int	emit_test_r32_r32(t_emitter *e, t_reg reg1, t_reg reg2)
{
	uint8_t b[3]; int n = 0;
	uint8_t r = mk_rex(0, reg1, reg2);
	if (r != 0x40) b[n++] = r;
	b[n++] = 0x85;
	b[n++] = 0xC0 | ((reg1 & 0x07) << 3) | (reg2 & 0x07);
	return emit_raw(e, b, n);
}

int	emit_test_r64_r64(t_emitter *e, t_reg reg1, t_reg reg2)
{
	uint8_t b[3]; int n = 0;
	uint8_t r = mk_rex(1, reg1, reg2);
	if (r != 0x40) b[n++] = r;
	b[n++] = 0x85;
	b[n++] = 0xC0 | ((reg1 & 0x07) << 3) | (reg2 & 0x07);
	return emit_raw(e, b, n);
}

#include <stdio.h>
/* ── lea abs ─────────────────────────────────────────────────── */
int emit_lea_abs(t_emitter *e, t_reg dst, int32_t addr)
{
    uint8_t b[8];
    fprintf(stderr, "[DBG-LEA-ALL] addr=%d (0x%x) dst=%d e->len=%zu\n", addr, (uint32_t)addr, dst, e->len);
    b[0] = mk_rex(1, dst, 0);
    b[1] = 0x8D;
    b[2] = MODRM00(dst, 4);
    b[3] = 0x25;
    memcpy(b + 4, &addr, 4);
    return emit_raw(e, b, 8);
}

/* LEA r64, [src+0] : 48 8D mod=01 disp8=0 (avec SIB si src==RSP) */
int	emit_lea_r64_reg0(t_emitter *e, t_reg dst, t_reg src)
{
	uint8_t b[6]; int n = 0;
	b[n++] = mk_rex(1, dst, src);
	b[n++] = 0x8D;
	if ((src & 0x07) == 4) {
		b[n++] = MODRM01(dst, 4);
		b[n++] = 0x24;
		b[n++] = 0x00;
	} else {
		b[n++] = MODRM01(dst, src);
		b[n++] = 0x00;
	}
	return emit_raw(e, b, n);
}

/* SAR r32, CL : D3 /7 */
int	emit_sar_r32_r32(t_emitter *e, t_reg dst, t_reg src)
{
	/* x86 : seul CL peut etre registre de decalage — src doit etre RCX */
	(void)src;   /* src ignore, toujours CL */
	uint8_t b[3]; int n = 0;
	uint8_t r = mk_rex(0, 0, dst);
	if (r != 0x40) b[n++] = r;
	b[n++] = 0xD3;
	b[n++] = MODRM11(7, dst);
	return emit_raw(e, b, n);
}

/* SAR [base], CL : D3 /7 mod=00 */
int	emit_sar_mem_r32(t_emitter *e, t_reg base)
{
	uint8_t b[3]; int n = 0;
	uint8_t r = mk_rex(0, 0, base);
	if (r != 0x40) b[n++] = r;
	b[n++] = 0xD3;
	b[n++] = MODRM00(7, base);
	return emit_raw(e, b, n);
}

/* ── add supplementaires ─────────────────────────────────────── */

/* ADD r8, [base+idx] : 02 /r SIB (alias lisible d'emit_add_r8_mem_sib8) */
int	emit_add_r8_mem_r8(t_emitter *e, t_reg dst, t_reg base, t_reg idx)
{
	return emit_add_r8_mem_sib8(e, dst, base, idx);
}

/* ADD r32, imm32 : 81 /0 id (3 octets opcode+modrm+imm32) */
int	emit_add_r32_imm32(t_emitter *e, t_reg dst, uint32_t imm)
{
	return emit_add_r32_imm32_long(e, dst, imm);
}

/* ── cmp r64, imm64 ──────────────────────────────────────────── */
/* x86_64 ne supporte pas CMP r64, imm64 directement.
** Strategy : charger imm64 dans un registre scratch et comparer.
** Ici on utilise une sequence : MOV rax, imm64 ; CMP dst, rax
** Si dst == rax, utiliser rcx comme scratch. */
int	emit_cmp_r64_imm64(t_emitter *e, t_reg dst, int64_t imm)
{
	t_reg scratch = (dst == REG_RAX) ? REG_RCX : REG_RAX;

	/* push scratch pour ne pas le corrompre */
	if (emit_push_r64(e, scratch) < 0) return -1;
	if (emit_mov_r64_imm64(e, scratch, (uint64_t)imm) < 0) return -1;
	if (emit_cmp_r64_r64(e, dst, scratch) < 0) return -1;
	if (emit_pop_r64(e, scratch) < 0) return -1;
	return 0;
}

int emit_rdtsc(t_emitter *e) {
    uint8_t b[2] = {0x0F, 0x31};  // Opcode de rdtsc
    return emit_raw(e, b, 2);
}

int emit_jcc_rel32(t_emitter *e, uint8_t op, int32_t disp)
{
    uint8_t b[6] = {0x0F, (uint8_t)(0x80 | (op & 0x0F)), 0,0,0,0};
    memcpy(b + 2, &disp, 4);
    return emit_raw(e, b, 6);
}

/* MOV r8, [base+disp8] sans SIB : 8A /r mod=01 */
int	emit_mov_r8_mem_disp8(t_emitter *e, t_reg dst, t_reg base, int8_t disp)
{
	uint8_t b[4]; int n = 0;
	uint8_t r = mk_rex(0, dst, base);
	if (r != 0x40) b[n++] = r;
	b[n++] = 0x8A;
	b[n++] = MODRM01(dst, base);
	b[n++] = (uint8_t)disp;
	return emit_raw(e, b, n);
}

/* LEA r32, [src+0] : 8D mod=01 disp8=0 (avec SIB si src==RSP/R12) */
int	emit_lea_r32_reg0(t_emitter *e, t_reg dst, t_reg src)
{
	uint8_t b[6]; int n = 0;
	uint8_t r = mk_rex(0, dst, src);
	if (r != 0x40) b[n++] = r;
	b[n++] = 0x8D;
	if ((src & 0x07) == 4) {          /* RSP ou R12 : SIB obligatoire */
		b[n++] = MODRM01(dst, 4);
		b[n++] = 0x24;                 /* SIB: no idx, base=src */
		b[n++] = 0x00;                 /* disp8=0 */
	} else {
		b[n++] = MODRM01(dst, src);
		b[n++] = 0x00;                 /* disp8=0 */
	}
	return emit_raw(e, b, n);
}

/* SUB r8, imm8 : 80 /5 ib */
int emit_sub_r8_imm8(t_emitter *e, t_reg reg, uint8_t imm)
{
	uint8_t b[4]; int n = 0;
	uint8_t r = mk_rex(0, 0, reg);
	if (r != 0x40 || reg >= 4) b[n++] = r;   /* REX requis aussi pour bl/dl/etc si registres >=4 low-byte ambigus */
	b[n++] = 0x80; b[n++] = MODRM11(5, reg); b[n++] = imm;
	return emit_raw(e, b, n);
}

/* SUB r64, imm8 : REX.W 83 /5 ib */
int emit_sub_r64_imm8(t_emitter *e, t_reg reg, uint8_t imm)
{
	uint8_t b[4];
	b[0] = mk_rex(1, 0, reg);
	b[1] = 0x83; b[2] = MODRM11(5, reg); b[3] = imm;
	return emit_raw(e, b, 4);
}

/* MOV r32, imm32 via C7 /0 — encodage distinct de B8-BF, invisible pour le LDE */
int emit_mov_r32_imm32_c7(t_emitter *e, t_reg reg, uint32_t imm)
{
    uint8_t b[7]; int n = 0;
    uint8_t r = mk_rex(0, 0, reg);
    if (r != 0x40) b[n++] = r;
    b[n++] = 0xC7;
    b[n++] = MODRM11(0, reg);
    memcpy(b + n, &imm, 4); n += 4;
    return emit_raw(e, b, n);
}

/* MOV r64, imm32 sign-extended via REX.W C7 /0 — pour les adresses (< 2^31) */
int emit_mov_r64_imm32_sx_c7(t_emitter *e, t_reg reg, int32_t imm)
{
    uint8_t b[7]; int n = 0;
    b[n++] = mk_rex(1, 0, reg);
    b[n++] = 0xC7;
    b[n++] = MODRM11(0, reg);
    memcpy(b + n, &imm, 4); n += 4;
    return emit_raw(e, b, n);
}

/* MOV r64,r64 littéral, sans risque de collision avec @o_89 */
int emit_mov_r64_r64_safe(t_emitter *e, t_reg dst, t_reg src)
{
    if (emit_push_r64(e, src) < 0) return -1;   /* 50+r, jamais checké */
    return emit_pop_r64(e, dst);                /* 58+r, jamais checké */
}

/* CMP AL, imm8 : forme courte speciale 3C ib */
int emit_cmp_al_imm8(t_emitter *e, uint8_t imm)
{
    uint8_t b[2] = {0x3C, imm};
    return emit_raw(e, b, 2);
}

/* CMP r8, imm8 : 80 /7 ib (general, ou 3C pour AL) */
int emit_cmp_r8_imm8(t_emitter *e, t_reg reg, uint8_t imm)
{
    if (reg == REG_RAX)
        return emit_cmp_al_imm8(e, imm);
    uint8_t b[4]; int n = 0;
    uint8_t r = mk_rex(0, 0, reg);
    if (r != 0x40 || reg >= 4) b[n++] = r;
    b[n++] = 0x80; b[n++] = MODRM11(7, reg); b[n++] = imm;
    return emit_raw(e, b, n);
}

/* MOV [base+disp8], r8 : 88 /r mod=01 */
int emit_mov_mem_disp8_r8(t_emitter *e, t_reg base, int8_t disp, t_reg src)
{
    uint8_t b[4]; int n = 0;
    uint8_t r = mk_rex(0, src, base);
    if (r != 0x40 || src >= 4 || base >= 8) b[n++] = r;
    b[n++] = 0x88;
    b[n++] = MODRM01(src, base);
    b[n++] = (uint8_t)disp;
    return emit_raw(e, b, n);
}

/* MOV [base+disp8], r32 : 89 /r mod=01 */
int emit_mov_mem_disp8_r32(t_emitter *e, t_reg base, int8_t disp, t_reg src)
{
    uint8_t b[4]; int n = 0;
    uint8_t r = mk_rex(0, src, base);
    if (r != 0x40) b[n++] = r;
    b[n++] = 0x89;
    b[n++] = MODRM01(src, base);
    b[n++] = (uint8_t)disp;
    return emit_raw(e, b, n);
}

/* MOV [base+disp8], r64 : REX.W 89 /r mod=01 */
int emit_mov_mem_disp8_r64(t_emitter *e, t_reg base, int8_t disp, t_reg src)
{
    uint8_t b[4];
    b[0] = mk_rex(1, src, base);
    b[1] = 0x89;
    b[2] = MODRM01(src, base);
    b[3] = (uint8_t)disp;
    return emit_raw(e, b, 4);
}

/* SUB r64, r64 : REX.W 29 /r */
int emit_sub_r64_r64(t_emitter *e, t_reg dst, t_reg src)
{
    uint8_t b[3];
    b[0] = mk_rex(1, src, dst);
    b[1] = 0x29;
    b[2] = MODRM11(src, dst);
    return emit_raw(e, b, 3);
}

/* SUB r32, r32 : 29 /r */
int emit_sub_r32_r32(t_emitter *e, t_reg dst, t_reg src)
{
    uint8_t b[3]; int n = 0;
    uint8_t r = mk_rex(0, src, dst);
    if (r != 0x40) b[n++] = r;
    b[n++] = 0x29;
    b[n++] = MODRM11(src, dst);
    return emit_raw(e, b, n);
}

/* SUB r8, r8 : 28 /r */
int emit_sub_r8_r8(t_emitter *e, t_reg dst, t_reg src)
{
    uint8_t b[3]; int n = 0;
    uint8_t r = mk_rex(0, src, dst);
    if (r != 0x40 || src >= 4 || dst >= 4) b[n++] = r;
    b[n++] = 0x28;
    b[n++] = MODRM11(src, dst);
    return emit_raw(e, b, n);
}

/* SUB r32, imm32 : 81 /5 id (forme longue, pour valeurs hors [-128,127]) */
int emit_sub_r32_imm32(t_emitter *e, t_reg reg, uint32_t imm)
{
    uint8_t b[7]; int n = 0;
    uint8_t r = mk_rex(0, 0, reg);
    if (r != 0x40) b[n++] = r;
    b[n++] = 0x81;
    b[n++] = MODRM11(5, reg);
    memcpy(b + n, &imm, 4); n += 4;
    return emit_raw(e, b, n);
}

/* SUB r64, imm32 (sign-extended) : REX.W 81 /5 id */
int emit_sub_r64_imm32(t_emitter *e, t_reg reg, int32_t imm)
{
    uint8_t b[7];
    b[0] = mk_rex(1, 0, reg);
    b[1] = 0x81;
    b[2] = MODRM11(5, reg);
    memcpy(b + 3, &imm, 4);
    return emit_raw(e, b, 7);
}

/* ADD r64, imm32 (sign-extended) : REX.W 81 /0 id */
int emit_add_r64_imm32(t_emitter *e, t_reg reg, int32_t imm)
{
    uint8_t b[7];
    b[0] = mk_rex(1, 0, reg);
    b[1] = 0x81;
    b[2] = MODRM11(0, reg);
    memcpy(b + 3, &imm, 4);
    return emit_raw(e, b, 7);
}

/* NEG r8 : F6 /3 */
int emit_neg_r8(t_emitter *e, t_reg reg)
{
    uint8_t b[3]; int n = 0;
    uint8_t r = mk_rex(0, 0, reg);
    if (r != 0x40 || reg >= 4) b[n++] = r;
    b[n++] = 0xf6;
    b[n++] = MODRM11(3, reg);
    return emit_raw(e, b, n);
}

/* NEG r32 : F7 /3 */
int emit_neg_r32(t_emitter *e, t_reg reg)
{
    uint8_t b[3]; int n = 0;
    uint8_t r = mk_rex(0, 0, reg);
    if (r != 0x40) b[n++] = r;
    b[n++] = 0xf7;
    b[n++] = MODRM11(3, reg);
    return emit_raw(e, b, n);
}

/* NEG r64 : REX.W F7 /3 */
int emit_neg_r64(t_emitter *e, t_reg reg)
{
    uint8_t b[3];
    b[0] = mk_rex(1, 0, reg);
    b[1] = 0xf7;
    b[2] = MODRM11(3, reg);
    return emit_raw(e, b, 3);
}

/////////////// Batman
// A tester vvvv

// Émet un CALL direct (relatif 32 bits)
int emit_call_direct(t_emitter *e, int32_t offset) {
    uint8_t b[5];
    int n = 0;

    // Opcode CALL rel32
    b[n++] = 0xE8;

    // Écriture de l'offset (little-endian)
    for (int i = 0; i < 4; i++) {
        b[n++] = (offset >> (i * 8)) & 0xFF;
    }

    return emit_raw(e, b, n);
}

// Émet un CALL indirect via registre (CALL r/m64)
int emit_call_indirect_reg(t_emitter *e, t_reg reg) {
    uint8_t b[3];
    int n = 0;
    uint8_t r = mk_rex(1, 0, reg);  // w=1 (64 bits), reg=0 (non utilisé ici), rm=reg

    // Ajout du REX si nécessaire
    if (r != 0x40 || reg >= 8) b[n++] = r;

    // Opcode CALL r/m64
    b[n++] = 0xFF;

    // ModR/M: mod=11 (registre direct), reg=002 (opcode extension pour CALL), rm=reg
    b[n++] = 0xC0 | (2 << 3) | (reg & 0x07);

    return emit_raw(e, b, n);
}

// Émet un CALL indirect via mémoire (CALL [rip + disp32])
int emit_call_indirect_mem(t_emitter *e, int32_t disp) {
    uint8_t b[7];
    int n = 0;
    uint8_t r = mk_rex(1, 0, 0x05);  // w=1, reg=0, rm=0x05 (disp32)

    // Ajout du REX si nécessaire
    if (r != 0x40) b[n++] = r;

    // Opcode CALL r/m64
    b[n++] = 0xFF;

    // ModR/M: mod=00 (disp32), reg=002 (opcode extension), rm=101 (disp32)
    b[n++] = 0x15;  // mod=00, reg=010 (CALL), rm=101

    // Écriture du displacement (little-endian)
    for (int i = 0; i < 4; i++) {
        b[n++] = (disp >> (i * 8)) & 0xFF;
    }

    return emit_raw(e, b, n);
}

/* MOVZX r32, [base] (word, 16 bits) : 0F B7 /r mod=00 */
int emit_movzx_r32_mem16(t_emitter *e, t_reg dst, t_reg base)
{
    uint8_t b[4]; int n = 0;
    uint8_t r = mk_rex(0, dst, base);
    if (r != 0x40) b[n++] = r;
    b[n++] = 0x0F; b[n++] = 0xB7; b[n++] = MODRM00(dst, base);
    return emit_raw(e, b, n);
}

/* LEA r64, [base+disp8] : REX.W 8D /r mod=01 */
int emit_lea_r64_mem_disp8(t_emitter *e, t_reg dst, t_reg base, int8_t disp)
{
    uint8_t b[4];
    b[0] = mk_rex(1, dst, base);
    b[1] = 0x8D;
    b[2] = MODRM01(dst, base);
    b[3] = (uint8_t)disp;
    return emit_raw(e, b, 4);
}

/* CMP [base+disp8], imm8 : 80 /7 ib */
int emit_cmp_mem_disp8_imm8(t_emitter *e, t_reg base, int8_t disp, uint8_t imm)
{
    uint8_t b[5]; int n = 0;
    uint8_t r = mk_rex(0, 0, base);
    if (r != 0x40) b[n++] = r;
    b[n++] = 0x80;
    b[n++] = MODRM01(7, base);
    b[n++] = (uint8_t)disp;
    b[n++] = imm;
    return emit_raw(e, b, n);
}

/* SHL r32, imm8 : C1 /4 ib */
int emit_shl_r32_imm8(t_emitter *e, t_reg reg, uint8_t imm)
{
    uint8_t b[4]; int n = 0;
    uint8_t r = mk_rex(0, 0, reg);
    if (r != 0x40) b[n++] = r;
    b[n++] = 0xC1;
    b[n++] = MODRM11(4, reg);
    b[n++] = imm;
    return emit_raw(e, b, n);
}

/* SHL r64, imm8 : REX.W C1 /4 ib */
int emit_shl_r64_imm8(t_emitter *e, t_reg reg, uint8_t imm)
{
    uint8_t b[4];
    b[0] = mk_rex(1, 0, reg);
    b[1] = 0xC1;
    b[2] = MODRM11(4, reg);
    b[3] = imm;
    return emit_raw(e, b, 4);
}

/* SHL r8, imm8 : C0 /4 ib */
int emit_shl_r8_imm8(t_emitter *e, t_reg reg, uint8_t imm)
{
    uint8_t b[4]; int n = 0;
    uint8_t r = mk_rex(0, 0, reg);
    if (r != 0x40 || reg >= 4) b[n++] = r;
    b[n++] = 0xC0;
    b[n++] = MODRM11(4, reg);
    b[n++] = imm;
    return emit_raw(e, b, n);
}

/* XOR r8, imm8 : 80 /6 ib (ou 34 ib pour AL specifiquement) */
int emit_xor_r8_imm8(t_emitter *e, t_reg reg, uint8_t imm)
{
    if (reg == REG_RAX) {
        uint8_t b[2] = {0x34, imm};
        return emit_raw(e, b, 2);
    }
    uint8_t b[4]; int n = 0;
    uint8_t r = mk_rex(0, 0, reg);
    if (r != 0x40 || reg >= 4) b[n++] = r;
    b[n++] = 0x80;
    b[n++] = MODRM11(6, reg);
    b[n++] = imm;
    return emit_raw(e, b, n);
}

/* XOR r32, imm32 : 81 /6 id */
int emit_xor_r32_imm32(t_emitter *e, t_reg reg, uint32_t imm)
{
    uint8_t b[7]; int n = 0;
    uint8_t r = mk_rex(0, 0, reg);
    if (r != 0x40) b[n++] = r;
    b[n++] = 0x81;
    b[n++] = MODRM11(6, reg);
    memcpy(b + n, &imm, 4); n += 4;
    return emit_raw(e, b, n);
}

/* XOR r64, imm32 (sign-extended) : REX.W 81 /6 id */
int emit_xor_r64_imm32(t_emitter *e, t_reg reg, int32_t imm)
{
    uint8_t b[7];
    b[0] = mk_rex(1, 0, reg);
    b[1] = 0x81;
    b[2] = MODRM11(6, reg);
    memcpy(b + 3, &imm, 4);
    return emit_raw(e, b, 7);
}

int emit_ret(t_emitter *e)
{
	uint8_t b = 0xC3;
	return emit_raw(e, &b, 1);
}

int emit_nop(t_emitter *e)
{
    uint8_t b = 0x90;
    return emit_raw(e, &b, 1);
}

/* ADD [base+disp8], imm8 : 80 /0 ib */
int emit_add_mem_disp8_imm8(t_emitter *e, t_reg base, int8_t disp, uint8_t imm)
{
    uint8_t b[5]; int n = 0;
    uint8_t r = mk_rex(0, 0, base);
    if (r != 0x40) b[n++] = r;
    b[n++] = 0x80;
    b[n++] = MODRM01(0, base);
    b[n++] = (uint8_t)disp;
    b[n++] = imm;
    return emit_raw(e, b, n);
}

/* SUB [base+disp8], imm8 : 80 /5 ib */
int emit_sub_mem_disp8_imm8(t_emitter *e, t_reg base, int8_t disp, uint8_t imm)
{
    uint8_t b[5]; int n = 0;
    uint8_t r = mk_rex(0, 0, base);
    if (r != 0x40) b[n++] = r;
    b[n++] = 0x80;
    b[n++] = MODRM01(5, base);
    b[n++] = (uint8_t)disp;
    b[n++] = imm;
    return emit_raw(e, b, n);
}

/* MOV [base+disp8], imm8 : C6 /0 ib */
int emit_mov_mem_disp8_imm8(t_emitter *e, t_reg base, int8_t disp, uint8_t imm)
{
    uint8_t b[5]; int n = 0;
    uint8_t r = mk_rex(0, 0, base);
    if (r != 0x40) b[n++] = r;
    b[n++] = 0xC6;
    b[n++] = MODRM01(0, base);
    b[n++] = (uint8_t)disp;
    b[n++] = imm;
    return emit_raw(e, b, n);
}

/* XOR [base+disp8], imm8 : 80 /6 ib */
int emit_xor_mem_disp8_imm8(t_emitter *e, t_reg base, int8_t disp, uint8_t imm)
{
    uint8_t b[5]; int n = 0;
    uint8_t r = mk_rex(0, 0, base);
    if (r != 0x40) b[n++] = r;
    b[n++] = 0x80;
    b[n++] = MODRM01(6, base);
    b[n++] = (uint8_t)disp;
    b[n++] = imm;
    return emit_raw(e, b, n);
}

/////////////////////

/* MOV r8, [base+idx+disp8] : 8A /r SIB (compatible @o_8a mod00/01) */
int emit_mov_r8_mem_sib_disp(t_emitter *e, t_reg reg_dest, t_reg base, t_reg idx, int8_t disp)
{
	uint8_t b[8]; int n = 0;
	uint8_t r = mk_rex_sib(0, reg_dest, idx, base);
	if (r != 0x40 || reg_dest >= 4) b[n++] = r;
	b[n++] = 0x8A;
	emit_modrm_sib_disp(b, &n, reg_dest, base, idx, 0, disp, 0);
	return emit_raw(e, b, n);
}

/* MOV r32, [base+idx] : 8B /r SIB (compatible @o_8b_and_pair / @o_8b mod00/01) */
int emit_mov_r32_mem_sib(t_emitter *e, t_reg dst, t_reg base, t_reg idx)
{
	uint8_t b[8]; int n = 0;
	uint8_t r = mk_rex_sib(0, dst, idx, base);
	if (r != 0x40) b[n++] = r;
	b[n++] = 0x8B;
	emit_modrm_sib_disp(b, &n, dst, base, idx, 0, 0, 0);
	return emit_raw(e, b, n);
}

/* MOV r32, [base+idx+disp] : 8B /r SIB */
int emit_mov_r32_mem_sib_disp(t_emitter *e, t_reg reg_dest, t_reg base, t_reg idx, int32_t disp)
{
	uint8_t b[10]; int n = 0;
	uint8_t r = mk_rex_sib(0, reg_dest, idx, base);
	if (r != 0x40) b[n++] = r;
	b[n++] = 0x8B;
	emit_modrm_sib_disp(b, &n, reg_dest, base, idx, 0, disp, 0);
	return emit_raw(e, b, n);
}

/* MOV r64, [base+idx+disp] : REX.W 8B /r SIB */
int emit_mov_r64_mem_sib_disp(t_emitter *e, t_reg reg_dest, t_reg base, t_reg idx, int32_t disp)
{
	uint8_t b[10]; int n = 0;
	b[n++] = mk_rex_sib(1, reg_dest, idx, base);
	b[n++] = 0x8B;
	emit_modrm_sib_disp(b, &n, reg_dest, base, idx, 0, disp, 0);
	return emit_raw(e, b, n);
}

/* MOVZX r32, BYTE PTR [base+idx] : 0F B6 /r SIB (compatible @o_0f mod00/01) */
int emit_movzx_r32_mem_sib8(t_emitter *e, t_reg dst, t_reg base, t_reg idx)
{
	uint8_t b[9]; int n = 0;
	uint8_t r = mk_rex_sib(0, dst, idx, base);
	if (r != 0x40) b[n++] = r;
	b[n++] = 0x0F;
	b[n++] = 0xB6;
	emit_modrm_sib_disp(b, &n, dst, base, idx, 0, 0, 0);
	return emit_raw(e, b, n);
}

/* MOV [base+idx], r8 : 88 /r SIB (bit=1 -> mod=00 sauf si base==RBP/R13) */
int emit_mov_mem_sib_r8(t_emitter *e, t_reg base, t_reg idx, t_reg src)
{
	uint8_t b[8]; int n = 0;
	uint8_t r = mk_rex_sib(0, src, idx, base);
	if (r != 0x40 || src >= 4) b[n++] = r;
	b[n++] = 0x88;
	emit_modrm_sib_disp(b, &n, src, base, idx, 0, 0, 0);
	return emit_raw(e, b, n);
}

/* MOV [base+idx+disp8], r8 : 88 /r SIB mod=01 (bit=0 -> force_disp8 = 1) */
int emit_mov_mem_sib_disp8_r8(t_emitter *e, t_reg base, t_reg idx, int8_t disp, t_reg src)
{
	uint8_t b[8]; int n = 0;
	uint8_t r = mk_rex_sib(0, src, idx, base);
	if (r != 0x40 || src >= 4) b[n++] = r;
	b[n++] = 0x88;
	emit_modrm_sib_disp(b, &n, src, base, idx, 0, disp, 1);
	return emit_raw(e, b, n);
}

/* MOV [base+idx], r32 : 89 /r SIB */
int emit_mov_mem_sib_r32(t_emitter *e, t_reg base, t_reg idx, t_reg src)
{
	uint8_t b[8]; int n = 0;
	uint8_t r = mk_rex_sib(0, src, idx, base);
	if (r != 0x40) b[n++] = r;
	b[n++] = 0x89;
	emit_modrm_sib_disp(b, &n, src, base, idx, 0, 0, 0);
	return emit_raw(e, b, n);
}

/* MOV [base+idx], r64 : REX.W 89 /r SIB */
int emit_mov_mem_sib_r64(t_emitter *e, t_reg base, t_reg idx, t_reg src)
{
	uint8_t b[8]; int n = 0;
	b[n++] = mk_rex_sib(1, src, idx, base);
	b[n++] = 0x89;
	emit_modrm_sib_disp(b, &n, src, base, idx, 0, 0, 0);
	return emit_raw(e, b, n);
}

/* XOR [base+idx], r8 : 30 /r SIB */
int emit_xor_mem_sib_r8(t_emitter *e, t_reg base, t_reg idx, t_reg src)
{
	uint8_t b[8]; int n = 0;
	uint8_t r = mk_rex_sib(0, src, idx, base);
	if (r != 0x40 || src >= 4) b[n++] = r;
	b[n++] = 0x30;
	emit_modrm_sib_disp(b, &n, src, base, idx, 0, 0, 0);
	return emit_raw(e, b, n);
}

/* XOR [base+idx], r32 : 31 /r SIB */
int emit_xor_mem_sib_r32(t_emitter *e, t_reg base, t_reg idx, t_reg src)
{
	uint8_t b[8]; int n = 0;
	uint8_t r = mk_rex_sib(0, src, idx, base);
	if (r != 0x40) b[n++] = r;
	b[n++] = 0x31;
	emit_modrm_sib_disp(b, &n, src, base, idx, 0, 0, 0);
	return emit_raw(e, b, n);
}

/* XOR [base+idx], r64 : REX.W 31 /r SIB */
int emit_xor_mem_sib_r64(t_emitter *e, t_reg base, t_reg idx, t_reg src)
{
	uint8_t b[8]; int n = 0;
	b[n++] = mk_rex_sib(1, src, idx, base);
	b[n++] = 0x31;
	emit_modrm_sib_disp(b, &n, src, base, idx, 0, 0, 0);
	return emit_raw(e, b, n);
}

/* XOR r8, [base+idx] : 32 /r SIB */
int emit_xor_r8_mem_sib(t_emitter *e, t_reg dst, t_reg base, t_reg idx)
{
	uint8_t b[8]; int n = 0;
	uint8_t r = mk_rex_sib(0, dst, idx, base);
	if (r != 0x40 || dst >= 4) b[n++] = r;
	b[n++] = 0x32;
	emit_modrm_sib_disp(b, &n, dst, base, idx, 0, 0, 0);
	return emit_raw(e, b, n);
}

/* ADD r8, [base+idx] : 02 /r SIB */
int emit_add_r8_mem_sib8(t_emitter *e, t_reg dst, t_reg base, t_reg idx)
{
	uint8_t b[8]; int n = 0;
	uint8_t r = mk_rex_sib(0, dst, idx, base);
	if (r != 0x40 || dst >= 4) b[n++] = r;
	b[n++] = 0x02;
	emit_modrm_sib_disp(b, &n, dst, base, idx, 0, 0, 0);
	return emit_raw(e, b, n);
}

/* XCHG [base+idx], r8 : 86 /r SIB */
int emit_xchg_mem_sib_r8(t_emitter *e, t_reg base, t_reg idx, t_reg reg)
{
	uint8_t b[8]; int n = 0;
	uint8_t r = mk_rex_sib(0, reg, idx, base);
	if (r != 0x40 || reg >= 4) b[n++] = r;
	b[n++] = 0x86;
	emit_modrm_sib_disp(b, &n, reg, base, idx, 0, 0, 0);
	return emit_raw(e, b, n);
}

/* OR [base+idx], r8 : 08 /r SIB */
int emit_or_mem_sib_r8(t_emitter *e, t_reg base, t_reg idx, t_reg src)
{
	uint8_t b[8]; int n = 0;
	uint8_t r = mk_rex_sib(0, src, idx, base);
	if (r != 0x40 || src >= 4) b[n++] = r;
	b[n++] = 0x08;
	emit_modrm_sib_disp(b, &n, src, base, idx, 0, 0, 0);
	return emit_raw(e, b, n);
}

/* OR [base+idx+disp8], r8 : 08 /r SIB mod=01 */
int emit_or_mem_sib_disp8_r8(t_emitter *e, t_reg base, t_reg idx,
		t_reg src, int8_t disp)
{
	uint8_t b[8]; int n = 0;
	uint8_t r = mk_rex_sib(0, src, idx, base);
	if (r != 0x40 || src >= 4) b[n++] = r;
	b[n++] = 0x08;
	emit_modrm_sib_disp(b, &n, src, base, idx, 0, disp, 1);
	return emit_raw(e, b, n);
}

/* SAR [base+idx], imm8 : C1 /7 SIB ib */
int emit_sar_mem_sib_imm8(t_emitter *e, t_reg base, t_reg idx, uint8_t imm)
{
	uint8_t b[9]; int n = 0;
	uint8_t r = mk_rex_sib(0, 0, idx, base);
	if (r != 0x40) b[n++] = r;
	b[n++] = 0xC1;
	emit_modrm_sib_disp(b, &n, 7, base, idx, 0, 0, 0);
	b[n++] = imm;
	return emit_raw(e, b, n);
}

/* SAR [base+idx+disp8], imm8 : C1 /7 SIB disp8 ib */
int emit_sar_mem_sib_imm8_disp(t_emitter *e, t_reg base, t_reg idx,
		int8_t disp, uint8_t imm)
{
	uint8_t b[9]; int n = 0;
	uint8_t r = mk_rex_sib(0, 0, idx, base);
	if (r != 0x40) b[n++] = r;
	b[n++] = 0xC1;
	emit_modrm_sib_disp(b, &n, 7, base, idx, 0, disp, 1);
	b[n++] = imm;
	return emit_raw(e, b, n);
}

/* SAR [base+idx], CL : D3 /7 SIB */
int emit_sar_mem_sib_cl(t_emitter *e, t_reg base, t_reg idx)
{
	uint8_t b[8]; int n = 0;
	uint8_t r = mk_rex_sib(0, 0, idx, base);
	if (r != 0x40) b[n++] = r;
	b[n++] = 0xD3;
	emit_modrm_sib_disp(b, &n, 7, base, idx, 0, 0, 0);
	return emit_raw(e, b, n);
}

/* CMP [base+idx], imm8 : 80 /7 ib SIB */
int emit_cmp_mem_sib_imm8(t_emitter *e, t_reg base, t_reg idx, uint8_t imm)
{
	uint8_t b[9]; int n = 0;
	uint8_t r = mk_rex_sib(0, 0, idx, base);
	if (r != 0x40) b[n++] = r;
	b[n++] = 0x80;
	emit_modrm_sib_disp(b, &n, 7, base, idx, 0, 0, 0);
	b[n++] = imm;
	return emit_raw(e, b, n);
}

/* CALL [base + idx*scale + disp] : FF /2 SIB */
int emit_call_indirect_sib(t_emitter *e, t_reg base, t_reg idx, int scale, int32_t disp)
{
	uint8_t b[10]; int n = 0;
	uint8_t r = mk_rex_sib(0, 0, idx, base);
	if (r != 0x40) b[n++] = r;
	b[n++] = 0xFF;
	emit_modrm_sib_disp(b, &n, 2, base, idx, (uint8_t)(scale & 0x03), disp, 0);
	return emit_raw(e, b, n);
}