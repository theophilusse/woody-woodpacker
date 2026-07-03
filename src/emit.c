#include "emit.h"

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
int	emit_push_r64(t_emitter *e, t_reg reg)
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

int	emit_mov_r8_mem_sib_disp(t_emitter *e, t_reg reg_dest, t_reg base, t_reg idx, int8_t disp)
{
	uint8_t b[7]; int n = 0;
	uint8_t r = mk_rex(0, reg_dest >> 3, base >> 3);
	if (r != 0x40) b[n++] = r;

	b[n++] = 0x8A;  // mov r8, [base+idx+disp]

	// ModR/M
	if (disp == 0 && base != 5) {
		b[n++] = 0x00 | ((reg_dest & 0x07) << 3) | 0x04;  // [base+idx]
	} else {
		b[n++] = 0x40 | ((reg_dest & 0x07) << 3) | 0x04;  // [base+idx+disp8]
	}

	// SIB
	b[n++] = ((base & 0x07) << 3) | (idx & 0x07);

	// Displacement (si nécessaire)
	if (disp != 0 || base == 5) {
		b[n++] = (uint8_t)disp;
	}

	return emit_raw(e, b, n);
}

int	emit_mov_r32_mem_sib_disp(t_emitter *e, t_reg reg_dest, t_reg base, t_reg idx, int32_t disp)
{
	uint8_t b[7]; int n = 0;
	uint8_t r = mk_rex(0, reg_dest >> 3, base >> 3);
	if (r != 0x40) b[n++] = r;

	b[n++] = 0x8B;  // mov r32, [base+idx+disp]

	// ModR/M
	if (disp == 0 && base != 5) {
		b[n++] = 0x00 | ((reg_dest & 0x07) << 3) | 0x04;  // [base+idx]
	} else {
		b[n++] = 0x40 | ((reg_dest & 0x07) << 3) | 0x04;  // [base+idx+disp8]
	}

	// SIB
	b[n++] = ((base & 0x07) << 3) | (idx & 0x07);

	// Displacement (si nécessaire)
	if (disp != 0 || base == 5) {
		if (disp >= -128 && disp <= 127) {
			b[n++] = (uint8_t)disp;  // disp8
		} else {
			b[n++] = 0x24;  // SIB avec disp32
			*(int32_t*)&b[n] = disp;
			n += 4;
		}
	}

	return emit_raw(e, b, n);
}

int	emit_mov_r64_mem_sib_disp(t_emitter *e, t_reg reg_dest, t_reg base, t_reg idx, int32_t disp)
{
	uint8_t b[10]; int n = 0;
	uint8_t r = mk_rex(1, reg_dest >> 3, base >> 3);
	if (r != 0x40) b[n++] = r;

	b[n++] = 0x8B;  // mov r64, [base+idx+disp]

	// ModR/M
	if (disp == 0 && base != 5) {
		b[n++] = 0x00 | ((reg_dest & 0x07) << 3) | 0x04;  // [base+idx]
	} else {
		b[n++] = 0x40 | ((reg_dest & 0x07) << 3) | 0x04;  // [base+idx+disp8]
	}

	// SIB
	b[n++] = ((base & 0x07) << 3) | (idx & 0x07);

	// Displacement (si nécessaire)
	if (disp != 0 || base == 5) {
		if (disp >= -128 && disp <= 127) {
			b[n++] = (uint8_t)disp;  // disp8
		} else {
			b[n++] = 0x24;  // SIB avec disp32
			*(int32_t*)&b[n] = disp;
			n += 4;
		}
	}

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

int	emit_mov_mem_sib_r8(t_emitter *e, t_reg base, t_reg idx, t_reg src)
{
	uint8_t b[4]; int n = 0;
	uint8_t r = mk_rex_sib(0, src, idx, base);
	if (r != 0x40) b[n++] = r;
	b[n++] = 0x88;
	b[n++] = MODRM00(src, 4);    /* rm=4 = SIB suit */
	b[n++] = SIB(0, idx, base);
	return emit_raw(e, b, n);
}

/* MOV r8, [base] : 8A /r mod=00 */
int emit_mov_r8_mem_reg(t_emitter *e, t_reg reg_dest, t_reg base)
{
    uint8_t b[3]; int n = 0;
    uint8_t r = mk_rex(0, reg_dest >> 3, base >> 3);
    if (r != 0x40) b[n++] = r;

    b[n++] = 0x8A;  // mov r8, [base]
    b[n++] = MODRM00(reg_dest, base);

    return emit_raw(e, b, n);
}

/* MOV r32, [base] : 8B /r mod=00 */
int emit_mov_r32_mem_reg(t_emitter *e, t_reg dst, t_reg base)
{
    uint8_t b[3]; int n = 0;
    uint8_t r = mk_rex(0, dst >> 3, base >> 3);
    if (r != 0x40) b[n++] = r;

    b[n++] = 0x8B;  // mov r32, [base]
    b[n++] = MODRM00(dst, base);

    return emit_raw(e, b, n);
}

/* MOV r64, [base] : 8B /r mod=00 */
int emit_mov_r64_mem_reg(t_emitter *e, t_reg dst, t_reg base)
{
    uint8_t b[3]; int n = 0;
    uint8_t r = mk_rex(1, dst >> 3, base >> 3);
    if (r != 0x40) b[n++] = r;

    b[n++] = 0x8B;  // mov r64, [base]
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

/* MOV r32, [base+idx] : 8B /r SIB mod=00 */
int	emit_mov_r32_mem_sib(t_emitter *e, t_reg dst, t_reg base, t_reg idx)
{
	uint8_t b[4]; int n = 0;
	uint8_t r = mk_rex_sib(0, dst, idx, base);
	if (r != 0x40) b[n++] = r;
	b[n++] = 0x8B;
	b[n++] = MODRM00(dst, 4);
	b[n++] = SIB(0, idx, base);
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

int	emit_xor_mem_sib_r8(t_emitter *e, t_reg base, t_reg idx, t_reg reg)
{
	uint8_t b[4]; int n = 0;
	uint8_t r = mk_rex_sib(0, reg, idx, base);
	if (r != 0x40) b[n++] = r;
	b[n++] = 0x30;
	b[n++] = MODRM00(reg, 4);
	b[n++] = SIB(0, idx, base);
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
	if (reg == REG_RAX) { b[n++] = 0x25; }
	else { b[n++] = 0x81; b[n++] = MODRM11(4, reg); }
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

int	emit_add_r8_mem_sib8(t_emitter *e, t_reg dst, t_reg base, t_reg idx)
{
	uint8_t b[4]; int n = 0;
	uint8_t r = mk_rex_sib(0, dst, idx, base);
	if (r != 0x40) b[n++] = r;
	b[n++] = 0x02; b[n++] = MODRM00(dst, 4); b[n++] = SIB(0, idx, base);
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
int	emit_add_r32_imm32_long(t_emitter *e, t_reg dst, uint32_t imm)
{
	uint8_t b[7]; int n = 0;
	uint8_t r = mk_rex(0, 0, dst);
	if (r != 0x40) b[n++] = r;
	b[n++] = 0x81; b[n++] = MODRM11(0, dst);
	memcpy(b + n, &imm, 4); n += 4;
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

int	emit_movzx_r32_mem_sib8(t_emitter *e, t_reg dst, t_reg base, t_reg idx)
{
	uint8_t b[5]; int n = 0;
	uint8_t r = mk_rex_sib(0, dst, idx, base);
	if (r != 0x40) b[n++] = r;
	b[n++] = 0x0F; b[n++] = 0xB6;
	b[n++] = MODRM00(dst, 4); b[n++] = SIB(0, idx, base);
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

/* ── xchg ────────────────────────────────────────────────────── */
int	emit_xchg_mem_sib_r8(t_emitter *e, t_reg base, t_reg idx, t_reg reg)
{
	uint8_t b[4]; int n = 0;
	uint8_t r = mk_rex_sib(0, reg, idx, base);
	if (r != 0x40) b[n++] = r;
	b[n++] = 0x86; b[n++] = MODRM00(reg, 4); b[n++] = SIB(0, idx, base);
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

int	emit_or_mem_sib_r8(t_emitter *e, t_reg base, t_reg idx, t_reg src)
{
	uint8_t b[4]; int n = 0;
	uint8_t r = mk_rex_sib(0, src, idx, base);
	if (r != 0x40) b[n++] = r;
	b[n++] = 0x08; b[n++] = MODRM00(src, 4); b[n++] = SIB(0, idx, base);
	return emit_raw(e, b, n);
}

int	emit_or_mem_sib_disp8_r8(t_emitter *e, t_reg base, t_reg idx,
		t_reg src, int8_t disp)
{
	uint8_t b[5]; int n = 0;
	uint8_t r = mk_rex_sib(0, src, idx, base);
	if (r != 0x40) b[n++] = r;
	b[n++] = 0x08; b[n++] = MODRM01(src, 4);
	b[n++] = SIB(0, idx, base); b[n++] = (uint8_t)disp;
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
	uint8_t r = mk_rex(1, 0, reg >> 3);  // REX.W (1), REX.B (reg)
	if (r != 0x40) b[n++] = r;

	b[n++] = 0xC1;  // Opcode pour SHR r64, imm8
	b[n++] = 0xE8 | (reg & 0x07);  // ModR/M : 11 101 reg
	b[n++] = imm;  // Immédiat (4 dans notre cas)

	return emit_raw(e, b, n);
}

int	emit_shr_r32_imm8(t_emitter *e, t_reg reg, uint8_t imm)
{
	uint8_t b[3]; int n = 0;
	uint8_t r = mk_rex(0, 0, reg >> 3);  // Pas de REX.W
	if (r != 0x40) b[n++] = r;

	b[n++] = 0xC1;  // Opcode pour SHR r32, imm8
	b[n++] = 0xE8 | (reg & 0x07);  // ModR/M
	b[n++] = imm;  // Immédiat

	return emit_raw(e, b, n);
}

int	emit_shr_r8_imm8(t_emitter *e, t_reg reg, uint8_t imm)
{
	uint8_t b[3]; int n = 0;
	uint8_t r = mk_rex(0, 0, reg >> 3);  // Pas de REX.W, REX.B pour reg8
	if (r != 0x40) b[n++] = r;

	b[n++] = 0xC0;  // Opcode pour SHR r8, imm8
	b[n++] = 0xE8 | (reg & 0x07);  // ModR/M : 11 101 reg
	b[n++] = imm;  // Immédiat (4 dans notre cas)

	return emit_raw(e, b, n);
}

/* test ------- */
int	emit_test_r8_r8(t_emitter *e, t_reg reg1, t_reg reg2)
{
	uint8_t b[3]; int n = 0;
	uint8_t r = mk_rex(0, reg1 >> 3, reg2 >> 3);  // REX.R (reg1), REX.B (reg2)
	if (r != 0x40) b[n++] = r;

	b[n++] = 0x84;  // Opcode pour TEST r8, r8
	b[n++] = 0xC0 | ((reg1 & 0x07) << 3) | (reg2 & 0x07);  // ModR/M

	return emit_raw(e, b, n);
}

int	emit_test_r32_r32(t_emitter *e, t_reg reg1, t_reg reg2)
{
	uint8_t b[3]; int n = 0;
	uint8_t r = mk_rex(0, reg1 >> 3, reg2 >> 3);  // Pas de REX.W
	if (r != 0x40) b[n++] = r;

	b[n++] = 0x85;  // Opcode pour TEST r32, r32
	b[n++] = 0xC0 | ((reg1 & 0x07) << 3) | (reg2 & 0x07);  // ModR/M

	return emit_raw(e, b, n);
}

int	emit_test_r64_r64(t_emitter *e, t_reg reg1, t_reg reg2)
{
	uint8_t b[4]; int n = 0;
	uint8_t r = mk_rex(1, reg1 >> 3, reg2 >> 3);  // REX.W (1), REX.R (reg1), REX.B (reg2)
	if (r != 0x40) b[n++] = r;

	b[n++] = 0x85;  // Opcode pour TEST r64, r64
	b[n++] = 0xC0 | ((reg1 & 0x07) << 3) | (reg2 & 0x07);  // ModR/M

	return emit_raw(e, b, n);
}

/* ── lea abs ─────────────────────────────────────────────────── */
int	emit_lea_abs(t_emitter *e, t_reg dst, int32_t addr)
{
	uint8_t b[8];
	b[0] = mk_rex(1, dst, 0);
	b[1] = 0x8D;
	b[2] = MODRM00(dst, 4);   /* rm=4 = SIB suit */
	b[3] = 0x25;               /* SIB: no idx, disp32 */
	memcpy(b + 4, &addr, 4);
	return emit_raw(e, b, 8);
}

/* LEA r64, [src+0] : 48 8D mod=01 disp8=0 (avec SIB si src==RSP) */
int	emit_lea_r64_reg0(t_emitter *e, t_reg dst, t_reg src)
{
	uint8_t b[6]; int n = 0;
	b[n++] = mk_rex(1, dst, src);
	b[n++] = 0x8D;
	if (src == REG_RSP) {
		b[n++] = MODRM01(dst, 4);   /* rm=4 = SIB */
		b[n++] = 0x24;               /* SIB: no idx, base=rsp */
		b[n++] = 0x00;               /* disp8=0 */
	} else {
		b[n++] = MODRM01(dst, src);
		b[n++] = 0x00;               /* disp8=0 */
	}
	return emit_raw(e, b, n);
}


/* ── sar supplementaires ─────────────────────────────────────── */

/* SAR [base+idx], imm8 : C1 /7 SIB ib */
int	emit_sar_mem_sib_imm8(t_emitter *e, t_reg base, t_reg idx, uint8_t imm)
{
	uint8_t b[5]; int n = 0;
	uint8_t r = mk_rex_sib(0, 0, idx, base);
	if (r != 0x40) b[n++] = r;
	b[n++] = 0xC1;
	b[n++] = MODRM00(7, 4);
	b[n++] = SIB(0, idx, base);
	b[n++] = imm;
	return emit_raw(e, b, n);
}

/* SAR [base+idx+disp8], imm8 : C1 /7 SIB disp8 ib */
int	emit_sar_mem_sib_imm8_disp(t_emitter *e, t_reg base, t_reg idx,
		int8_t disp, uint8_t imm)
{
	uint8_t b[6]; int n = 0;
	uint8_t r = mk_rex_sib(0, 0, idx, base);
	if (r != 0x40) b[n++] = r;
	b[n++] = 0xC1;
	b[n++] = MODRM01(7, 4);
	b[n++] = SIB(0, idx, base);
	b[n++] = (uint8_t)disp;
	b[n++] = imm;
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

/* SAR [base+idx], CL : D3 /7 SIB mod=00 */
int emit_sar_mem_sib_cl(t_emitter *e, t_reg base, t_reg idx)
{
    uint8_t b[4]; int n = 0;
    uint8_t r = mk_rex_sib(0, 0, idx, base);
    if (r != 0x40) b[n++] = r;
    b[n++] = 0xD3;
    b[n++] = MODRM00(7, 4);
    b[n++] = SIB(0, idx, base);
    return emit_raw(e, b, n);
}

int emit_rdtsc(t_emitter *e) {
    uint8_t b[2] = {0x0F, 0x31};  // Opcode de rdtsc
    return emit_raw(e, b, 2);
}