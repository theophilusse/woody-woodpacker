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

	/* --- jmp vers OEP --- */
	emit_jmp_rel32(&e, &patch_jmp_oep);

	/* --- données : le message, après tout le code --- */
	msg_offset = e.len;
	emit_raw(&e, (const uint8_t *)WOODY_MSG, WOODY_MSG_LEN);

	/* --- passe 2 : patch du lea (msg_offset connu maintenant) --- */
	/* disp = distance depuis fin du lea jusqu'au message
	 * fin du lea = patch_lea_msg + 4 (les 4 octets du disp32 lui-même) */
	disp = (int32_t)(msg_offset - (patch_lea_msg + 4));
	patch_disp32(&e, patch_lea_msg, disp);

	stub->patch_jmp_oep = patch_jmp_eop;

	/* --- construction du t_stub --- */
	stub = malloc(sizeof(t_stub));
	if (!stub)
	{
		free(e.buf);
		return (NULL);
	}
	stub->bytes        = e.buf;
	stub->len          = e.len;
	stub->load_vaddr   = 0;          /* rempli par elf_patch */
	stub->original_oep = ctx->ehdr->e_entry;
	return (stub);
}

void	stub_free(t_stub *stub)
{
	if (!stub)
		return ;
	free(stub->bytes);
	free(stub);
}
