#include "woody.h"

t_stub	*stub_build(t_elf_ctx *ctx, t_crypto_ctx *crypto)
{
	t_emitter	e;
	t_stub		*stub;
	size_t		patch_lea_msg;
	size_t		patch_jmp_oep;
	size_t		msg_offset;
	int32_t		disp;

	(void)crypto;
	e = (t_emitter){0};

	/* --- write(1, WOODY_MSG, 14) --- */
	emit_mov_r32_imm32(&e, REG_RAX, 1);
	emit_mov_r32_imm32(&e, REG_RDI, 1);
	emit_lea_rip(&e, REG_RSI, &patch_lea_msg);
	emit_mov_r32_imm32(&e, REG_RDX, WOODY_MSG_LEN);
	emit_syscall(&e);

	/* ... mprotect + boucle de déchiffrement : TODO ... */

	emit_jmp_rel32(&e, &patch_jmp_oep);         // patch_jmp_oep = offset du disp32 dans e.buf

	msg_offset = e.len;
	emit_raw(&e, (const uint8_t *)WOODY_MSG, WOODY_MSG_LEN);

	disp = (int32_t)(msg_offset - (patch_lea_msg + 4));
	patch_disp32(&e, patch_lea_msg, disp);

	stub = malloc(sizeof(t_stub));
	if (!stub) { free(e.buf); return (NULL); }
	stub->bytes         = e.buf;
	stub->len           = e.len;
	stub->load_vaddr    = 0;
	stub->original_oep  = ctx->ehdr->e_entry;
	stub->patch_jmp_oep = patch_jmp_oep;        // <-- c'est ça qui manque
	return (stub);
}

void	stub_free(t_stub *stub)
{
	if (!stub)
		return ;
	free(stub->bytes);
	free(stub);
}
