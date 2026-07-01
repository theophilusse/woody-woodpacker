#ifndef EMIT_H
# define EMIT_H

typedef enum e_reg
{
	REG_RAX, REG_RCX, REG_RDX, REG_RBX,
	REG_RSP, REG_RBP, REG_RSI, REG_RDI
}	t_reg;

typedef struct s_emitter
{
	uint8_t	*buf;   // le buffer qui contiendra les octets machine du stub, alloué dynamiquement
	size_t	len;    // combien d'octets sont actuellement utilisés dans buf
	size_t	cap;    // combien d'octets buf peut contenir au total avant de devoir realloc
}	t_emitter;

int		emit_raw(t_emitter *e, const uint8_t *bytes, size_t n);
int		emit_mov_r32_imm32(t_emitter *e, t_reg dst, uint32_t imm);
int		emit_lea_rip(t_emitter *e, t_reg dst, size_t *patch_offset);
int		emit_mov_r64_r64(t_emitter *e, t_reg dst, t_reg src);
int		emit_xor_r32_r32(t_emitter *e, t_reg dst, t_reg src);
int		emit_cmp_r32_imm8(t_emitter *e, t_reg reg, int8_t imm);
int		emit_jcc_rel8(t_emitter *e, uint8_t cc_opcode, size_t *patch_offset);
int		emit_jmp_rel32(t_emitter *e, size_t *patch_offset);
int		emit_syscall(t_emitter *e);
void		patch_disp32(t_emitter *e, size_t at, int32_t value);
void		patch_disp32_buf(uint8_t *buf, size_t at, int32_t value);

#endif
