#include "woody.h"

int	emit_raw(t_emitter *e, const uint8_t *bytes, size_t n)
{
	uint8_t	*tmp;
	size_t	new_cap;

	if (!e || !bytes)
		return (-1);
	if (e->len + n > e->cap)
	{
		new_cap = e->cap == 0 ? 16 : e->cap;
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

int	emit_lea_rip(t_emitter *e, t_reg dst, size_t *patch_offset)
{
	uint8_t	bytes[7];
	int32_t	placeholder;

	bytes[0] = 0x48;
	bytes[1] = 0x8D;
	bytes[2] = (0 << 6) + (dst << 3) + 5;
	placeholder = 0;
	memcpy(bytes + 3, &placeholder, 4);
	*patch_offset = e->len + 3;
	return (emit_raw(e, bytes, 7));
}

int	emit_mov_r64_r64(t_emitter *e, t_reg dst, t_reg src)
{
	uint8_t	bytes[3];

	bytes[0] = 0x48;
	bytes[1] = 0x89;
	bytes[2] = (3 << 6) + (src << 3) + dst;
	return (emit_raw(e, bytes, 3));
}

int	emit_xor_r32_r32(t_emitter *e, t_reg dst, t_reg src)
{
	uint8_t	bytes[2];

	bytes[0] = 0x31;
	bytes[1] = (3 << 6) + (src << 3) + dst;
	return (emit_raw(e, bytes, 2));
}

int	emit_cmp_r32_imm8(t_emitter *e, t_reg reg, int8_t imm)
{
	uint8_t	bytes[3];

	bytes[0] = 0x83;
	bytes[1] = (3 << 6) + (7 << 3) + reg;
	memcpy(bytes + 2, &imm, 1);
	return (emit_raw(e, bytes, 3));
}

int	emit_jcc_rel8(t_emitter *e, uint8_t cc_opcode, size_t *patch_offset)
{
	uint8_t	bytes[2];

	bytes[0] = cc_opcode;
	bytes[1] = 0;
	*patch_offset = e->len + 1;
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
