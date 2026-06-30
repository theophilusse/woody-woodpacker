#include "woody.h"

t_stub	*stub_build(t_elf_ctx *ctx, t_crypto_ctx *crypto)
{
	t_emitter	e = {0};
	size_t		patch_lea_msg, patch_jmp_oep;

	emit_mov_r32_imm32(&e, REG_RAX, 1);
	emit_mov_r32_imm32(&e, REG_RDI, 1);
	emit_lea_rip(&e, REG_RSI, &patch_lea_msg);   // offset réel inconnu pour l'instant
	emit_mov_r32_imm32(&e, REG_RDX, WOODY_MSG_LEN);
	emit_syscall(&e);
	/* ... mprotect, boucle de déchiffrement ... */
	emit_jmp_rel32(&e, &patch_jmp_oep);

	/* deuxième passe : patcher les offsets maintenant que tout est émis */
	patch_disp32(&e, patch_lea_msg, msg_final_offset - (patch_lea_msg + 4));
	patch_disp32(&e, patch_jmp_oep, oep_offset - (patch_jmp_oep + 4));

	return (wrap_in_stub(&e, ctx));
}

void	stub_free(t_stub *stub)
{
	if (!stub)
		return ;
	free(stub->bytes);
	free(stub);
}
