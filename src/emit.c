#include "woody.h"

int	emit_raw(t_emitter *e, const uint8_t *bytes, size_t n)
{
	uint8_t	*tmp;
	size_t	new_cap;

	if (!e || !bytes)
		return (-1);
	if (e->len + n > e->cap)
	{
		new_cap = e->cap == 0 ? 64 : e->cap;
		while (new_cap < e->len + n)
			new_cap *= 2;
		tmp = realloc(e->buf, new_cap);
		if (!tmp)
			return (-1);
		e->buf = tmp;
		e->cap = new_cap;
	}
	memcpy(e->buf + e->len, bytes, n);
	e->len += n;
	return (0);
}

int	emit_mov_r32_imm32(t_emitter *e, t_reg dst, uint32_t imm)
{
	uint8_t	bytes[5];

	bytes[0] = 0xB8 + dst;
	memcpy(bytes + 1, &imm, 4);
	return (emit_raw(e, bytes, 5));
}

/* MOV r64, imm64 : REX.W + B8+r + 8 octets */
int	emit_mov_r64_imm64(t_emitter *e, t_reg dst, uint64_t imm)
{
	uint8_t	bytes[10];

	bytes[0] = 0x48;
	bytes[1] = 0xB8 + dst;
	memcpy(bytes + 2, &imm, 8);
	return (emit_raw(e, bytes, 10));
}

int	emit_lea_rip(t_emitter *e, t_reg dst, size_t *patch_offset)
{
	uint8_t	bytes[7];
	int32_t	placeholder;

	bytes[0] = 0x48;
	bytes[1] = 0x8D;
	bytes[2] = (dst << 3) | 0x05;
	placeholder = 0;
	memcpy(bytes + 3, &placeholder, 4);
	*patch_offset = e->len + 3;
	return (emit_raw(e, bytes, 7));
}

int emit_lea_abs(t_emitter *e, t_reg dst, uint32_t addr)
{
    uint8_t bytes[8];

    bytes[0] = 0x48;              // REX.W
    bytes[1] = 0x8D;              // LEA
    bytes[2] = (dst << 3) | 4;   // ModRM: mod=00, reg=dst, rm=100(SIB)
    bytes[3] = 0x25;              // SIB: scale=00, index=100(none), base=101(disp32 only)
    memcpy(bytes + 4, &addr, 4);
    return (emit_raw(e, bytes, 8));
}

int	emit_mov_r64_r64(t_emitter *e, t_reg dst, t_reg src)
{
	uint8_t	bytes[3];

	bytes[0] = 0x48;
	bytes[1] = 0x89;
	bytes[2] = (3 << 6) | (src << 3) | dst;
	return (emit_raw(e, bytes, 3));
}

int	emit_xor_r32_r32(t_emitter *e, t_reg dst, t_reg src)
{
	uint8_t	bytes[2];

	bytes[0] = 0x31;
	bytes[1] = (3 << 6) | (src << 3) | dst;
	return (emit_raw(e, bytes, 2));
}

int	emit_cmp_r32_imm8(t_emitter *e, t_reg reg, int8_t imm)
{
	uint8_t	bytes[3];

	bytes[0] = 0x83;
	bytes[1] = (3 << 6) | (7 << 3) | reg;
	memcpy(bytes + 2, &imm, 1);
	return (emit_raw(e, bytes, 3));
}

int	emit_cmp_r32_imm32(t_emitter *e, t_reg reg, int32_t imm)
{
	uint8_t	bytes[6];

	bytes[0] = 0x81;
	bytes[1] = (3 << 6) | (7 << 3) | reg;
	memcpy(bytes + 2, &imm, 4);
	return (emit_raw(e, bytes, 6));
}

int emit_cmp_r64_imm32(t_emitter *e, t_reg dst, int32_t imm)
{
    uint8_t b[7] = {0x48, 0x81, (uint8_t)((7 << 3) | dst), 0, 0, 0, 0};
    memcpy(b + 3, &imm, 4);
    return emit_raw(e, b, 7);
}

int emit_cmp_r64_imm64(t_emitter *e, t_reg dst, int64_t imm)
{
    uint8_t b[10] = {0x48, 0x81, (uint8_t)((7 << 3) | dst), 0, 0, 0, 0, 0, 0, 0};
    memcpy(b + 3, &imm, 8);
    return emit_raw(e, b, 10);
}

int	emit_jcc_rel8(t_emitter *e, uint8_t cc_opcode, size_t *patch_offset)
{
	uint8_t	bytes[2];

	bytes[0] = cc_opcode;
	bytes[1] = 0;
	*patch_offset = e->len + 1;
	return (emit_raw(e, bytes, 2));
}

int	emit_jcc_rel8_direct(t_emitter *e, uint8_t cc_opcode, int8_t disp)
{
	uint8_t	bytes[2];

	bytes[0] = cc_opcode;
	bytes[1] = (uint8_t)disp;
	return (emit_raw(e, bytes, 2));
}

int	emit_jmp_rel32(t_emitter *e, size_t *patch_offset)
{
	uint8_t	bytes[5];
	int32_t	placeholder;

	bytes[0] = 0xE9;
	placeholder = 0;
	memcpy(bytes + 1, &placeholder, 4);
	*patch_offset = e->len + 1;
	return (emit_raw(e, bytes, 5));
}

int	emit_syscall(t_emitter *e)
{
	const uint8_t	bytes[] = {0x0F, 0x05};

	return (emit_raw(e, bytes, sizeof(bytes)));
}

void	patch_disp32(t_emitter *e, size_t at, int32_t value)
{
	memcpy(e->buf + at, &value, sizeof(int32_t));
}

void	patch_disp32_buf(uint8_t *buf, size_t at, int32_t value)
{
	memcpy(buf + at, &value, sizeof(int32_t));
}

int	emit_push_r64(t_emitter *e, t_reg reg)
{
	uint8_t	byte;

	byte = 0x50 + reg;
	return (emit_raw(e, &byte, 1));
}

int	emit_pop_r64(t_emitter *e, t_reg reg)
{
	uint8_t	byte;

	byte = 0x58 + reg;
	return (emit_raw(e, &byte, 1));
}

/* SUB rsp, imm32 : 48 81 EC imm32 */
int	emit_sub_rsp_imm32(t_emitter *e, uint32_t imm)
{
	uint8_t	bytes[7];

	bytes[0] = 0x48;
	bytes[1] = 0x81;
	bytes[2] = (3 << 6) | (5 << 3) | 4;
	memcpy(bytes + 3, &imm, 4);
	return (emit_raw(e, bytes, 7));
}

/* DEC r/m8 : FE /1    ex: dec cl = FE C9 */
int	emit_dec_r8(t_emitter *e, t_reg reg)
{
	uint8_t	bytes[2];

	bytes[0] = 0xFE;
	bytes[1] = (3 << 6) | (1 << 3) | reg;
	return (emit_raw(e, bytes, 2));
}

/* DEC r/m32 : FF /1    ex: dec eax = FF C8 */
int	emit_dec_r32(t_emitter *e, t_reg reg)
{
	uint8_t	bytes[2];

	bytes[0] = 0xFF;
	bytes[1] = (3 << 6) | (1 << 3) | reg;
	return (emit_raw(e, bytes, 2));
}

/* DEC r/m64 : 48 FF /1    ex: dec rax = 48 FF C8 */
int	emit_dec_r64(t_emitter *e, t_reg reg)
{
	uint8_t	bytes[3];

	bytes[0] = 0x48;
	bytes[1] = 0xFF;
	bytes[2] = (3 << 6) | (1 << 3) | reg;
	return (emit_raw(e, bytes, 3));
}

/* SUB r/m32, imm8 : 83 /5 ib    ex: sub eax, 1 = 83 E8 01 */
int	emit_sub_r32_imm8(t_emitter *e, t_reg reg, int8_t imm)
{
	uint8_t	bytes[3];

	bytes[0] = 0x83;
	bytes[1] = (3 << 6) | (5 << 3) | reg;
	bytes[2] = (uint8_t)imm;
	return (emit_raw(e, bytes, 3));
}

/* ADD rsp, imm32 : 48 81 C4 imm32 */
int	emit_add_rsp_imm32(t_emitter *e, uint32_t imm)
{
	uint8_t	bytes[7];

	bytes[0] = 0x48;
	bytes[1] = 0x81;
	bytes[2] = (3 << 6) | (0 << 3) | 4;
	memcpy(bytes + 3, &imm, 4);
	return (emit_raw(e, bytes, 7));
}

/* INC r/m8 : FE /0 */
int emit_inc_r8(t_emitter *e, t_reg reg)
{
    uint8_t bytes[2];

    bytes[0] = 0xFE;                      // Opcode principal
    bytes[1] = (3 << 6) | (0 << 3) | reg; // ModR/M: [r/m8], 0 (opcode extension 0)
    return emit_raw(e, bytes, 2);
}

/* INC r/m32 : FF /0 sans REX.W */
int emit_inc_r32(t_emitter *e, t_reg reg)
{
    uint8_t bytes[2];
    bytes[0] = 0xFF;
    bytes[1] = (3 << 6) | (0 << 3) | reg;
    return emit_raw(e, bytes, 2);
}

/* INC r/m64 : FF /0 (avec préfixe REX.W implicite) */
int emit_inc_r64(t_emitter *e, t_reg reg)
{
    uint8_t bytes[3]; // 3 octets : préfixe REX.W + opcode + ModR/M

    bytes[0] = 0x48;                      // Préfixe REX.W (obligatoire pour 64 bits)
    bytes[1] = 0xFF;                      // Opcode principal
    bytes[2] = (3 << 6) | (0 << 3) | reg; // ModR/M: [r/m64], 0 (opcode extension 0)
    return emit_raw(e, bytes, 3);
}

/* MOV [base+idx], src_low8 : 88 /r SIB
 * ex: mov [rsp+rcx], cl = 88 0C 0C */
int	emit_mov_mem_sib_r8(t_emitter *e, t_reg base, t_reg idx, t_reg src)
{
	uint8_t	bytes[3];

	bytes[0] = 0x88;
	bytes[1] = (0 << 6) | (src << 3) | 4;
	bytes[2] = (0 << 6) | (idx << 3) | base;
	return (emit_raw(e, bytes, 3));
}

/* MOVZX r32, byte [base+idx] : 0F B6 /r SIB
 * ex: movzx eax, [rsp+rcx] = 0F B6 04 0C */
int	emit_movzx_r32_mem_sib8(t_emitter *e, t_reg dst, t_reg base, t_reg idx)
{
	uint8_t	bytes[4];

	bytes[0] = 0x0F;
	bytes[1] = 0xB6;
	bytes[2] = (0 << 6) | (dst << 3) | 4;
	bytes[3] = (0 << 6) | (idx << 3) | base;
	return (emit_raw(e, bytes, 4));
}

/* MOVZX r32, r8 : 0F B6 /r mod=11
 * ex: movzx eax, al = 0F B6 C0 */
int	emit_movzx_r32_r8(t_emitter *e, t_reg dst, t_reg src)
{
	uint8_t	bytes[3];

	bytes[0] = 0x0F;
	bytes[1] = 0xB6;
	bytes[2] = (3 << 6) | (dst << 3) | src;
	return (emit_raw(e, bytes, 3));
}

/* ADD r/m8, r8 : 00 /r    ex: add dl, al = 00 C2 */
int	emit_add_r8_r8(t_emitter *e, t_reg dst, t_reg src)
{
	uint8_t	bytes[2];

	bytes[0] = 0x00;
	bytes[1] = (3 << 6) | (src << 3) | dst;
	return (emit_raw(e, bytes, 2));
}

/* ADD r8, [base+idx] : 02 /r SIB
 * ex: add al, [rsp+rdx] = 02 04 14 */
int	emit_add_r8_mem_sib8(t_emitter *e, t_reg dst, t_reg base, t_reg idx)
{
	uint8_t	bytes[3];

	bytes[0] = 0x02;
	bytes[1] = (0 << 6) | (dst << 3) | 4;
	bytes[2] = (0 << 6) | (idx << 3) | base;
	return (emit_raw(e, bytes, 3));
}

/* ADD r/m8, r8 : 00 /r    ex: add [rsp+rdx], al = 00 04 14 */
int emit_add_r8_mem_r8(t_emitter *e, t_reg base, t_reg idx, t_reg src) {
    uint8_t bytes[3];

    bytes[0] = 0x00;
    bytes[1] = (0 << 6) | (src << 3) | 4;  // ModR/M: [base+idx], src
    bytes[2] = (0 << 6) | (idx << 3) | base; // SIB
    return emit_raw(e, bytes, 3);
}

/* ADD r/m32, imm8 : 83 /0 ib    ex: add eax, 1 = 83 C0 01 */
int emit_add_r32_imm8(t_emitter *e, t_reg dst, uint8_t imm)
{
    uint8_t bytes[3];
    bytes[0] = 0x83;
    bytes[1] = (3 << 6) | (0 << 3) | dst;
    bytes[2] = imm;
    return emit_raw(e, bytes, 3);
}

/* ADD r16, imm16 : 83 /0 iw    ex: add ax, 42 = 66 83 C0 2A */
int emit_add_r16_imm16(t_emitter *e, t_reg dst, uint16_t imm) {
    uint8_t bytes[4];

    bytes[0] = 0x66; // Prefix 16-bit
    bytes[1] = 0x83;
    bytes[2] = (3 << 6) | (0 << 3) | dst;  // ModR/M: dst, 0 (opcode extension)
    bytes[3] = (uint8_t)imm;
    return emit_raw(e, bytes, 4);
}

/* ADD r32, imm32 : 83 /0 id    ex: add eax, 42 = 83 C0 2A */
int emit_add_r32_imm32(t_emitter *e, t_reg dst, uint32_t imm)
{
    uint8_t bytes[6];

    bytes[0] = 0x83;
    bytes[1] = (3 << 6) | (0 << 3) | dst;  // ModR/M: dst, 0 (opcode extension)
    bytes[2] = (uint8_t)imm;
    bytes[3] = (uint8_t)(imm >> 8);
    bytes[4] = (uint8_t)(imm >> 16);
    bytes[5] = (uint8_t)(imm >> 24);
    return emit_raw(e, bytes, 6);
}

/* MOV r/m8, r8 registre->registre : 88 /r mod=11	
 * ex: mov al, cl = 88 C8 */
int	emit_mov_r8_r8(t_emitter *e, t_reg dst, t_reg src)
{
	uint8_t	bytes[2];

	bytes[0] = 0x88;
	bytes[1] = (3 << 6) | (src << 3) | dst;
	return (emit_raw(e, bytes, 2));
}

/* AND r/m8, imm8 : forme courte AL=24ib, generale=80 /4 ib
 * ex: and al, 0x0F = 24 0F
 * NOTE: fonctionne uniquement si key_len est une puissance de 2 */
int	emit_and_r8_imm8(t_emitter *e, t_reg reg, uint8_t imm)
{
	uint8_t	bytes[3];

	if (reg == REG_RAX)
	{
		bytes[0] = 0x24;
		bytes[1] = imm;
		return (emit_raw(e, bytes, 2));
	}
	bytes[0] = 0x80;
	bytes[1] = (3 << 6) | (4 << 3) | reg;
	bytes[2] = imm;
	return (emit_raw(e, bytes, 3));
}

/* XCHG [base+idx], r8 : 86 /r SIB
 * ex: xchg [rsp+rdx], al = 86 04 14
 * bidirectionnel : al <- mem, mem <- al */
int	emit_xchg_mem_sib_r8(t_emitter *e, t_reg base, t_reg idx, t_reg reg)
{
	uint8_t	bytes[3];

	bytes[0] = 0x86;
	bytes[1] = (0 << 6) | (reg << 3) | 4;
	bytes[2] = (0 << 6) | (idx << 3) | base;
	return (emit_raw(e, bytes, 3));
}

/* XOR [base+idx], r8 : 30 /r SIB
 * ex: xor [rdi+rbx], al = 30 04 1F */
int	emit_xor_mem_sib_r8(t_emitter *e, t_reg base, t_reg idx, t_reg reg)
{
	uint8_t	bytes[3];

	bytes[0] = 0x30;
	bytes[1] = (0 << 6) | (reg << 3) | 4;
	bytes[2] = (0 << 6) | (idx << 3) | base;
	return (emit_raw(e, bytes, 3));
}

/* ADD r/m64, imm8          : 48 83 /0 ib */
int emit_add_r64_imm8(t_emitter *e, t_reg reg, int8_t imm)
{
    uint8_t bytes[4] = {0x48, 0x83, (3 << 6) | (0 << 3) | reg, (uint8_t)imm};
    return emit_raw(e, bytes, 4);
}

/* AND r/m32, imm8          : 83 /4 ib  (valeurs 0x00-0x7F seulement) */
int emit_and_r32_imm8(t_emitter *e, t_reg reg, uint8_t imm)
{
    uint8_t bytes[3] = {0x83, (3 << 6) | (4 << 3) | reg, imm};
    return emit_raw(e, bytes, 3);
}

/* AND r/m32, imm32         : 25 id (eax) ou 81 /4 id */
int emit_and_r32_imm32(t_emitter *e, t_reg reg, uint32_t imm)
{
    uint8_t bytes[6];
    if (reg == REG_RAX) {
        bytes[0] = 0x25; memcpy(bytes + 1, &imm, 4); return emit_raw(e, bytes, 5);
    }
    bytes[0] = 0x81; bytes[1] = (3 << 6) | (4 << 3) | reg;
    memcpy(bytes + 2, &imm, 4); return emit_raw(e, bytes, 6);
}

//* SAR r/m32, imm8 : C1 /7 ib */
int emit_sar_r32_imm8(t_emitter *e, t_reg reg, uint8_t imm)
{
    uint8_t bytes[3] = {0xC1, (0b11 << 6) | (7 << 3) | reg, imm};
    return emit_raw(e, bytes, 3);
}

/* SAR r32, r32 : D3 /7 */
int emit_sar_r32_r32(t_emitter *e, t_reg reg_dest, t_reg reg_src)
{
    (void)reg_src; // Inutile ici, mais gardé pour cohérence
    uint8_t bytes[2] = {0xD3, (0b11 << 6) | (7 << 3) | reg_dest};
    return emit_raw(e, bytes, 2);
}

/* SAR [r/m32], imm8 : C1 /7 ib */
int emit_sar_mem_sib_imm8(t_emitter *e, t_reg base, t_reg idx, uint8_t imm)
{
    uint8_t modrm = (0b00 << 6) | (7 << 3) | 0b100; // mod=00, r/m=100 (SIB)
    uint8_t sib = (0b00 << 6) | (idx << 3) | base;
    uint8_t bytes[4] = {0xC1, modrm, sib, imm};
    return emit_raw(e, bytes, 4);
}

/* SAR [r/m32 + disp8], imm8 : C1 /7 ib */
int emit_sar_mem_sib_imm8_disp(t_emitter *e, t_reg base, t_reg idx, int8_t disp, uint8_t imm)
{
    uint8_t modrm = (0b01 << 6) | (7 << 3) | 0b100; // mod=01 (disp8)
    uint8_t sib = (0b00 << 6) | (idx << 3) | base;
    uint8_t bytes[5] = {0xC1, modrm, sib, (uint8_t)disp, imm};
    return emit_raw(e, bytes, 5);
}

/* SAR [r/m32], r32 : D3 /7 */
int emit_sar_mem_r32(t_emitter *e, t_reg base, t_reg idx, t_reg reg_src)
{
    (void)reg_src; // Inutile ici, mais gardé pour cohérence
    uint8_t modrm = (0b00 << 6) | (7 << 3) | 0b100; // mod=00, r/m=100 (SIB)
    uint8_t sib = (0b00 << 6) | (idx << 3) | base;
    uint8_t bytes[3] = {0xD3, modrm, sib};
    return emit_raw(e, bytes, 3);
}

/* CMP r/m64, r64           : 48 39 /r */
int emit_cmp_r64_r64(t_emitter *e, t_reg dst, t_reg src)
{
    uint8_t bytes[3] = {0x48, 0x39, (3 << 6) | (src << 3) | dst};
    return emit_raw(e, bytes, 3);
}

/* MOVZX r32, [base] : 0F B6 mod=00 */
int emit_movzx_r32_mem_reg(t_emitter *e, t_reg dst, t_reg base)
{
    uint8_t bytes[3] = {0x0F, 0xB6, (0 << 6) | (dst << 3) | base};
    return emit_raw(e, bytes, 3);
}

/* MOVZX r32, [base+disp8] : 0F B6 mod=01 disp8 */
int emit_movzx_r32_mem_disp8(t_emitter *e, t_reg dst, t_reg base, int8_t disp)
{
    uint8_t bytes[4] = {0x0F, 0xB6, (1 << 6) | (dst << 3) | base, (uint8_t)disp};
    return emit_raw(e, bytes, 4);
}

int emit_mov_r32_r32(t_emitter *e, t_reg dst, t_reg src) {
    uint8_t b[2] = {0x89, (uint8_t)((3<<6)|(src<<3)|dst)};
    return emit_raw(e, b, 2);
}

int emit_mov_r8_imm8(t_emitter *e, t_reg reg, uint8_t imm)
{
    uint8_t b[2] = {0xB0 + reg, imm};
    return emit_raw(e, b, 2);
}

int emit_shl_r8_cl(t_emitter *e, t_reg reg)
{
    uint8_t b[2] = {0xD2, (uint8_t)((3 << 6) | (4 << 3) | reg)};
    return emit_raw(e, b, 2);
}

int emit_or_r32_imm32(t_emitter *e, t_reg reg, uint32_t imm)
{
	uint8_t bytes[6];
	bytes[0] = 0x81;
	bytes[1] = (3 << 6) | (1 << 3) | reg;
	memcpy(bytes + 2, &imm, 4);
	return emit_raw(e, bytes, 6);
}

/* OR r8, r8 (registre→registre) : 08 /r mod=11 */
int emit_or_r8_r8(t_emitter *e, t_reg dst, t_reg src)
{
    uint8_t bytes[2];
    bytes[0] = 0x08;
    bytes[1] = (3 << 6) | (src << 3) | dst;
    return emit_raw(e, bytes, 2);
}

/* OR [base+idx], r8 (mémoire SIB) : 08 /r mod=00 SIB */
int emit_or_mem_sib_r8(t_emitter *e, t_reg base, t_reg idx, t_reg src)
{
    uint8_t bytes[3];
    bytes[0] = 0x08;
    bytes[1] = (0 << 6) | (src << 3) | 4;          /* mod=00 reg=src rm=SIB */
    bytes[2] = (0 << 6) | (idx << 3) | base;        /* SIB */
    return emit_raw(e, bytes, 3);
}

int emit_or_mem_sib_disp8_r8(t_emitter *e, t_reg base, t_reg idx, t_reg src, int8_t disp)
{
    uint8_t bytes[4];
    bytes[0] = 0x08;
    bytes[1] = (1 << 6) | (src << 3) | 4;       /* mod=01 reg=src rm=SIB */
    bytes[2] = (0 << 6) | (idx << 3) | base;     /* SIB */
    bytes[3] = (uint8_t)disp;
    return emit_raw(e, bytes, 4);
}

/* MOV r32, [base]       : 8B /r mod=00 */
int emit_mov_r32_mem_reg(t_emitter *e, t_reg dst, t_reg base) {
    uint8_t b[2] = {0x8B, (uint8_t)((0<<6)|(dst<<3)|base)};
    return emit_raw(e, b, 2); }

/* MOV r32, [base+disp8] : 8B /r mod=01 disp8 */
int emit_mov_r32_mem_disp8(t_emitter *e, t_reg dst, t_reg base, int8_t disp) {
    uint8_t b[3] = {0x8B, (uint8_t)((1<<6)|(dst<<3)|base), (uint8_t)disp};
    return emit_raw(e, b, 3); }

/* MOV r32, [base+idx]   : 8B /r SIB mod=00 */
int emit_mov_r32_mem_sib(t_emitter *e, t_reg dst, t_reg base, t_reg idx) {
    uint8_t b[3] = {0x8B, (uint8_t)((0<<6)|(dst<<3)|4),
                          (uint8_t)((0<<6)|(idx<<3)|base)};
    return emit_raw(e, b, 3); }

int emit_add_r8_imm8(t_emitter *e, t_reg dst, uint8_t imm) {
    uint8_t b[3] = {0x80, (uint8_t)((3<<6)|(0<<3)|dst), imm};
    return emit_raw(e, b, 3);
}

/* LEA r64, [src+0] : 48 8D mod=01 disp8=0 */
int emit_lea_r64_reg0(t_emitter *e, t_reg dst, t_reg src)
{
    if (src == REG_RSP) {
        /* RSP comme rm=4 impose SIB même en mod=01 */
        uint8_t b[5] = {0x48, 0x8D,
                        (uint8_t)((1<<6)|(dst<<3)|4),  /* rm=SIB */
                        0x24,                            /* SIB: no idx, base=rsp */
                        0x00};                           /* disp8=0 */
        return emit_raw(e, b, 5);
    }
    uint8_t b[4] = {0x48, 0x8D,
                    (uint8_t)((1<<6)|(dst<<3)|src),
                    0x00};
    return emit_raw(e, b, 4);
}

int emit_rdtsc(t_emitter *e) {
    uint8_t b[2] = {0x0F, 0x31};  // Opcode de rdtsc
    return emit_raw(e, b, 2);
}

int emit_xor_r8_r8(t_emitter *e, t_reg dst, t_reg src) {
    uint8_t b[2] = {0x30, (uint8_t)((3<<6)|(src<<3)|dst)};
    return emit_raw(e, b, 2);
}

int emit_and_r64_imm8(t_emitter *e, t_reg dst, uint8_t imm) {
    uint8_t b[4] = {0x48, 0x83, (uint8_t)((4<<3)|dst), imm};
    return emit_raw(e, b, 4);
}

int emit_xor_r64_r64(t_emitter *e, t_reg dst, t_reg src) {
    uint8_t b[3] = {0x48, 0x31, (uint8_t)((3<<6)|(src<<3)|dst)};
    return emit_raw(e, b, 3);
}