#ifndef EMIT_H
# define EMIT_H

# include <stdint.h>
# include <stddef.h>
# include <stdlib.h>
# include <string.h>

/* ModRM : mod(2) | reg(3) | rm(3) */
#define MODRM(mod, reg, rm)  ((uint8_t)(((mod)<<6)|((( reg)&7)<<3)|((rm)&7)))
#define MODRM11(reg, rm)     MODRM(3, reg, rm)
#define MODRM00(reg, rm)     MODRM(0, reg, rm)
#define MODRM01(reg, rm)     MODRM(1, reg, rm)
#define SIB(sc, idx, base)   ((uint8_t)(((sc)<<6)|(((idx)&7)<<3)|((base)&7)))

typedef enum e_reg
{
	REG_RAX, REG_RCX, REG_RDX, REG_RBX,
	REG_RSP, REG_RBP, REG_RSI, REG_RDI,
	REG_R8, REG_R9, REG_R10, REG_R11, REG_R12
}	t_reg;

typedef struct s_emitter
{
	uint8_t	*buf;
	size_t	len;
	size_t	cap;
}	t_emitter;

/* fondamentales */
int		emit_raw(t_emitter *e, const uint8_t *bytes, size_t n);
void	patch_disp32(t_emitter *e, size_t at, int32_t value);
void	patch_disp32_buf(uint8_t *buf, size_t at, int32_t value);

/* registres / immediats */
int		emit_mov_r32_imm32(t_emitter *e, t_reg dst, uint32_t imm);
int		emit_mov_r64_imm64(t_emitter *e, t_reg dst, uint64_t imm);
int		emit_mov_r64_r64(t_emitter *e, t_reg dst, t_reg src);
int		emit_mov_r8_r8(t_emitter *e, t_reg dst, t_reg src);
int 	emit_or_r8_r8(t_emitter *e, t_reg dst, t_reg src);
int		emit_lea_r64_reg0(t_emitter *e, t_reg dst, t_reg src);
int		emit_xor_r8_r8(t_emitter *e, t_reg dst, t_reg src);
int		emit_xor_r64_r64(t_emitter *e, t_reg dst, t_reg src);

/* pile */
int		emit_push_r64(t_emitter *e, t_reg reg);
int		emit_pop_r64(t_emitter *e, t_reg reg);
int		emit_sub_rsp_imm32(t_emitter *e, uint32_t imm);
int		emit_add_rsp_imm32(t_emitter *e, uint32_t imm);

/* rip-relative */
int		emit_lea_rip(t_emitter *e, t_reg dst, size_t *patch_offset);
int 	emit_lea_abs(t_emitter *e, t_reg dst, int32_t addr);

/* 64 bits */
int		emit_dec_r64(t_emitter *e, t_reg reg);
int		emit_and_r64_imm8(t_emitter *e, t_reg dst, uint8_t imm);
int		emit_cmp_r64_imm32(t_emitter *e, t_reg dst, int32_t imm);
int		emit_shr_r64_imm8(t_emitter *e, t_reg reg, uint8_t imm);
int		emit_test_r64_r64(t_emitter *e, t_reg reg1, t_reg reg2);

/* 32 bits */
int		emit_xor_r32_r32(t_emitter *e, t_reg dst, t_reg src);
int		emit_cmp_r32_imm8(t_emitter *e, t_reg reg, int8_t imm);
int		emit_cmp_r32_imm32(t_emitter *e, t_reg reg, int32_t imm);
int		emit_add_r32_imm8(t_emitter *e, t_reg dst, int8_t imm);
int		emit_sub_r32_imm8(t_emitter *e, t_reg reg, int8_t imm);
int		emit_dec_r32(t_emitter *e, t_reg reg);
int 	emit_or_r32_imm32(t_emitter *e, t_reg reg, uint32_t imm);
int		emit_shr_r32_imm8(t_emitter *e, t_reg reg, uint8_t imm);
int		emit_test_r32_r32(t_emitter *e, t_reg reg1, t_reg reg2);

/* 16 bits */
int		emit_add_r16_imm16(t_emitter *e, t_reg dst, uint16_t imm);

/* 8 bits */
int			emit_dec_r8(t_emitter *e, t_reg reg);
int		emit_inc_r8(t_emitter *e, t_reg reg);
int		emit_inc_r32(t_emitter *e, t_reg reg);
int		emit_inc_r64(t_emitter *e, t_reg reg);
int		emit_and_r8_imm8(t_emitter *e, t_reg reg, uint8_t imm);
int		emit_add_r8_imm8(t_emitter *e, t_reg dst, uint8_t imm);
int		emit_add_r8_r8(t_emitter *e, t_reg dst, t_reg src);
int		emit_movzx_r32_r8(t_emitter *e, t_reg dst, t_reg src);
int		emit_mov_r8_imm8(t_emitter *e, t_reg reg, uint8_t imm);
int		emit_shl_r8_cl(t_emitter *e, t_reg reg);
int		emit_shr_r8_imm8(t_emitter *e, t_reg reg, uint8_t imm);
int		emit_test_r8_r8(t_emitter *e, t_reg reg1, t_reg reg2);

/* SIB [base+idx] */
int		emit_mov_mem_sib_r8(t_emitter *e, t_reg base, t_reg idx, t_reg src);
int		emit_movzx_r32_mem_sib8(t_emitter *e, t_reg dst, t_reg base, t_reg idx);
int		emit_add_r8_mem_sib8(t_emitter *e, t_reg dst, t_reg base, t_reg idx);
int		emit_xchg_mem_sib_r8(t_emitter *e, t_reg base, t_reg idx, t_reg reg);
int		emit_xor_mem_sib_r8(t_emitter *e, t_reg base, t_reg idx, t_reg reg);
int		emit_or_mem_sib_r8(t_emitter *e, t_reg base, t_reg idx, t_reg src);
int		emit_or_mem_sib_disp8_r8(t_emitter *e, t_reg base, t_reg idx, t_reg src, int8_t disp);
int		emit_mov_r32_mem_reg(t_emitter *e, t_reg dst, t_reg base);
int		emit_mov_r32_mem_disp8(t_emitter *e, t_reg dst, t_reg base, int8_t disp);
int		emit_mov_r32_mem_sib(t_emitter *e, t_reg dst, t_reg base, t_reg idx);

/* sauts */
int		emit_jcc_rel8(t_emitter *e, uint8_t cc_opcode, size_t *patch_offset);
int		emit_jcc_rel8_direct(t_emitter *e, uint8_t cc_opcode, int8_t disp);
int		emit_jmp_rel32(t_emitter *e, size_t *patch_offset);

/* syscall */
int		emit_syscall(t_emitter *e);
int		emit_rdtsc(t_emitter *e);

int emit_movzx_r32_mem_reg(t_emitter *e, t_reg dst, t_reg base);
int emit_movzx_r32_mem_disp8(t_emitter *e, t_reg dst, t_reg base, int8_t disp);
int emit_add_r64_imm8(t_emitter *e, t_reg reg, int8_t imm);
int emit_and_r32_imm8(t_emitter *e, t_reg reg, uint8_t imm);
int emit_and_r32_imm32(t_emitter *e, t_reg reg, uint32_t imm);
int emit_sar_r32_imm8(t_emitter *e, t_reg reg, uint8_t imm);
int emit_cmp_r64_r64(t_emitter *e, t_reg dst, t_reg src);
int emit_movzx_r32_mem_reg(t_emitter *e, t_reg dst, t_reg base);
int emit_movzx_r32_mem_disp8(t_emitter *e, t_reg dst, t_reg base, int8_t disp);
int emit_mov_r32_r32(t_emitter *e, t_reg dst, t_reg src);

/* sar */
int  emit_sar_mem_sib_imm8(t_emitter *e, t_reg base, t_reg idx, uint8_t imm);
int  emit_sar_mem_sib_imm8_disp(t_emitter *e, t_reg base, t_reg idx, int8_t disp, uint8_t imm);
int  emit_sar_r32_r32(t_emitter *e, t_reg dst, t_reg src);
int  emit_sar_mem_r32(t_emitter *e, t_reg base);

/* add */
int  emit_add_r8_mem_r8(t_emitter *e, t_reg dst, t_reg base, t_reg idx);
int  emit_add_r32_imm32(t_emitter *e, t_reg dst, uint32_t imm);
int  emit_add_r32_imm32_long(t_emitter *e, t_reg dst, uint32_t imm);

/* cmp */
int  emit_cmp_r64_imm64(t_emitter *e, t_reg dst, int64_t imm);

int emit_sar_mem_sib_cl(t_emitter *e, t_reg base, t_reg idx);

int	emit_mov_r64_mem_sib_disp(t_emitter *e, t_reg reg_dest, t_reg base, t_reg idx, int32_t disp);
int	emit_mov_r32_mem_sib_disp(t_emitter *e, t_reg reg_dest, t_reg base, t_reg idx, int32_t disp);
int	emit_mov_r8_mem_sib_disp(t_emitter *e, t_reg reg_dest, t_reg base, t_reg idx, int8_t disp);
int emit_mov_r32_mem_reg(t_emitter *e, t_reg dst, t_reg base);
int emit_mov_r8_mem_reg(t_emitter *e, t_reg reg_dest, t_reg base);
int emit_mov_r64_mem_reg(t_emitter *e, t_reg dst, t_reg base);
int emit_mov_mem_sib_r64(t_emitter *e, t_reg base, t_reg idx, t_reg src);
int emit_mov_mem_sib_r32(t_emitter *e, t_reg base, t_reg idx, t_reg src);
int emit_xor_mem_sib_r32(t_emitter *e, t_reg base, t_reg idx, t_reg src);
int emit_xor_mem_sib_r64(t_emitter *e, t_reg base, t_reg idx, t_reg src);
int emit_xor_r8_mem_sib(t_emitter *e, t_reg dst, t_reg base, t_reg idx);
int emit_jcc_rel32(t_emitter *e, uint8_t op, int32_t disp);
int	emit_mov_r8_mem_disp8(t_emitter *e, t_reg dst, t_reg base, int8_t disp);
int	emit_lea_r32_reg0(t_emitter *e, t_reg dst, t_reg src);
int emit_sub_r8_imm8(t_emitter *e, t_reg reg, uint8_t imm);
int emit_sub_r64_imm8(t_emitter *e, t_reg reg, uint8_t imm);
int emit_mov_r32_imm32_c7(t_emitter *e, t_reg reg, uint32_t imm);
int emit_mov_r64_imm32_sx_c7(t_emitter *e, t_reg reg, int32_t imm);
int emit_mov_r64_r64_safe(t_emitter *e, t_reg dst, t_reg src);
int emit_cmp_al_imm8(t_emitter *e, uint8_t imm);
int emit_cmp_r8_imm8(t_emitter *e, t_reg reg, uint8_t imm);
int emit_mov_mem_disp8_r8(t_emitter *e, t_reg base, int8_t disp, t_reg src);
int emit_mov_mem_disp8_r32(t_emitter *e, t_reg base, int8_t disp, t_reg src);
int emit_mov_mem_disp8_r64(t_emitter *e, t_reg base, int8_t disp, t_reg src);
int emit_sub_r64_r64(t_emitter *e, t_reg dst, t_reg src);
int emit_sub_r32_r32(t_emitter *e, t_reg dst, t_reg src);
int emit_sub_r8_r8(t_emitter *e, t_reg dst, t_reg src);
int emit_sub_r32_imm32(t_emitter *e, t_reg reg, uint32_t imm);
int emit_sub_r64_imm32(t_emitter *e, t_reg reg, int32_t imm);
int emit_add_r64_imm32(t_emitter *e, t_reg reg, int32_t imm);
int emit_neg_r8(t_emitter *e, t_reg reg);
int emit_neg_r32(t_emitter *e, t_reg reg);
int emit_neg_r64(t_emitter *e, t_reg reg);
int emit_call_direct(t_emitter *e, int32_t offset);
int emit_call_indirect_reg(t_emitter *e, t_reg reg);
int emit_call_indirect_mem(t_emitter *e, int32_t disp);
int emit_call_indirect_sib(t_emitter *e, t_reg base, t_reg idx, int scale, int32_t disp);
int emit_movzx_r32_mem16(t_emitter *e, t_reg dst, t_reg base);
int emit_mov_mem_sib_disp8_r8(t_emitter *e, t_reg base, t_reg idx, int8_t disp, t_reg src);
int emit_lea_r64_mem_disp8(t_emitter *e, t_reg dst, t_reg base, int8_t disp);
int emit_cmp_mem_disp8_imm8(t_emitter *e, t_reg base, int8_t disp, uint8_t imm);
int emit_shl_r32_imm8(t_emitter *e, t_reg reg, uint8_t imm);
int emit_shl_r64_imm8(t_emitter *e, t_reg reg, uint8_t imm);
int emit_shl_r8_imm8(t_emitter *e, t_reg reg, uint8_t imm);
int emit_xor_r8_imm8(t_emitter *e, t_reg reg, uint8_t imm);
int emit_xor_r32_imm32(t_emitter *e, t_reg reg, uint32_t imm);
int emit_xor_r64_imm32(t_emitter *e, t_reg reg, int32_t imm);
int emit_ret(t_emitter *e);

/* opcodes jcc utiles */
# define JL   0x7C
# define JNZ  0x75
# define JGE  0x7D

#endif
