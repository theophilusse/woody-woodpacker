#include <stdlib.h>
#include <string.h>
#include "woody.h"
#include "emit.h"

/*
** Allocation des registres dans le stub:
**   rcx  = i  (compteur KSA/PRGA, 8 bits via cl, wrap naturel)
**   rdx  = j  (compteur KSA/PRGA, 8 bits via dl, wrap naturel)
**   rbx  = k  (index payload PRGA, 64 bits)
**   rax  = temporaire (al pour operations 8 bits)
**   rsi  = base cle (KSA uniquement)
**   rdi  = base payload (PRGA uniquement)
**   rsp  = S-box 256 octets (allouee via sub rsp, 256)
**   rdx est preserve autour du stub entier (push/pop) pour _dl_fini
*/

t_stub	*stub_build(t_elf_ctx *ctx, t_crypto_ctx *crypto)
{
	t_emitter	e;
	t_stub		*stub;
	size_t		patch_lea_msg;
	size_t		patch_lea_key;
	size_t		patch_jmp_oep;
	size_t		msg_offset;
	size_t		key_offset;
	int8_t		disp8;
	int32_t		disp32;
	uint64_t	page_vaddr;
	uint32_t	page_size;
	size_t		ksa_init_start;
	size_t		ksa_loop_start;
	size_t		prga_loop_start;

	e = (t_emitter){0};

	/* page-align pour mprotect */
	page_vaddr = crypto->text_vaddr & ~(uint64_t)0xFFF;
	page_size  = (uint32_t)(((crypto->text_vaddr & 0xFFF)
		+ crypto->text_len + 0xFFF) & ~(size_t)0xFFF);

	/* preserves _dl_fini (kernel le passe dans rdx avant de sauter a _start) */
	emit_push_r64(&e, REG_RDX);

	/* ── write(1, WOODY_MSG, 14) ────────────────────────────────── */
	emit_mov_r32_imm32(&e, REG_RAX, 1);
	emit_mov_r32_imm32(&e, REG_RDI, 1);
	emit_lea_rip(&e, REG_RSI, &patch_lea_msg);
	emit_mov_r32_imm32(&e, REG_RDX, WOODY_MSG_LEN);
	emit_syscall(&e);

	/* ── mprotect(page_vaddr, page_size, PROT_RWX) ──────────────── */
	emit_mov_r64_imm64(&e, REG_RDI, page_vaddr);
	emit_mov_r32_imm32(&e, REG_RSI, page_size);
	emit_mov_r32_imm32(&e, REG_RDX, 7);            /* PROT_READ|WRITE|EXEC */
	emit_mov_r32_imm32(&e, REG_RAX, 10);           /* syscall mprotect */
	emit_syscall(&e);

	/* ── alloue S-box sur la pile ────────────────────────────────── */
	emit_sub_rsp_imm32(&e, 256);

	/* ── rsi = base de la cle (RIP-relative, patchee apres) ──────── */
	emit_lea_rip(&e, REG_RSI, &patch_lea_key);

	/* ── KSA init : S[i] = i pour i dans 0..255 ─────────────────── */
	emit_xor_r32_r32(&e, REG_RCX, REG_RCX);        /* i = 0 */
	ksa_init_start = e.len;
	emit_mov_mem_sib_r8(&e, REG_RSP, REG_RCX, REG_RCX); /* S[i] = cl */
	emit_inc_r8(&e, REG_RCX);                       /* inc cl, wrap a 256 */
	disp8 = (int8_t)((ptrdiff_t)ksa_init_start - (ptrdiff_t)(e.len + 2));
	emit_jcc_rel8_direct(&e, JNZ, disp8);           /* jnz KSA_INIT */

	/* ── KSA : melange de S par la cle ──────────────────────────── */
	emit_xor_r32_r32(&e, REG_RCX, REG_RCX);        /* i = 0 */
	emit_xor_r32_r32(&e, REG_RDX, REG_RDX);        /* j = 0 */
	ksa_loop_start = e.len;

	emit_movzx_r32_mem_sib8(&e, REG_RAX, REG_RSP, REG_RCX); /* al = S[i] */
	emit_add_r8_r8(&e, REG_RDX, REG_RAX);          /* j += S[i] (dl, wrap auto) */

	emit_mov_r8_r8(&e, REG_RAX, REG_RCX);          /* al = i */
	emit_and_r8_imm8(&e, REG_RAX,
		(uint8_t)(crypto->key_len - 1));             /* al = i % key_len (puissance de 2) */
	emit_movzx_r32_r8(&e, REG_RAX, REG_RAX);       /* zero-extend pour adressage */
	emit_movzx_r32_mem_sib8(&e, REG_RAX,
		REG_RSI, REG_RAX);                           /* al = key[i % key_len] */
	emit_add_r8_r8(&e, REG_RDX, REG_RAX);          /* j += key[...] (dl, wrap auto) */

	/* swap S[i] <-> S[j] via XCHG (un seul registre temp: al) */
	emit_movzx_r32_mem_sib8(&e, REG_RAX, REG_RSP, REG_RCX); /* al = S[i] */
	emit_xchg_mem_sib_r8(&e, REG_RSP, REG_RDX, REG_RAX);    /* al=S[j], S[j]=S[i] */
	emit_mov_mem_sib_r8(&e, REG_RSP, REG_RCX, REG_RAX);     /* S[i] = S[j] */

	emit_inc_r8(&e, REG_RCX);                       /* inc cl */
	disp8 = (int8_t)((ptrdiff_t)ksa_loop_start - (ptrdiff_t)(e.len + 2));
	emit_jcc_rel8_direct(&e, JNZ, disp8);           /* jnz KSA_LOOP */

	/* ── PRGA + XOR payload ──────────────────────────────────────── */
	emit_mov_r64_imm64(&e, REG_RDI, crypto->text_vaddr); /* base payload */
	emit_xor_r32_r32(&e, REG_RCX, REG_RCX);        /* i = 0 */
	emit_xor_r32_r32(&e, REG_RDX, REG_RDX);        /* j = 0 */
	emit_xor_r32_r32(&e, REG_RBX, REG_RBX);        /* k = 0 */
	prga_loop_start = e.len;

	emit_inc_r8(&e, REG_RCX);                       /* i = (i+1) % 256 (cl, wrap) */
	emit_movzx_r32_mem_sib8(&e, REG_RAX, REG_RSP, REG_RCX); /* al = S[i] */
	emit_add_r8_r8(&e, REG_RDX, REG_RAX);          /* j += S[i] (dl, wrap) */

	/* swap S[i] <-> S[j] */
	emit_xchg_mem_sib_r8(&e, REG_RSP, REG_RDX, REG_RAX);    /* al=S[j], S[j]=S[i] */
	emit_mov_mem_sib_r8(&e, REG_RSP, REG_RCX, REG_RAX);     /* S[i] = S[j] */

	/* keystream = S[(S[i]+S[j]) % 256]
	 * apres le swap : al = S[j]ancien, [rsp+rdx] = S[i]ancien */
	emit_add_r8_mem_sib8(&e, REG_RAX, REG_RSP, REG_RDX); /* al += S[i]ancien */
	emit_movzx_r32_r8(&e, REG_RAX, REG_RAX);             /* zero-extend */
	emit_movzx_r32_mem_sib8(&e, REG_RAX, REG_RSP, REG_RAX); /* al = keystream */

	emit_xor_mem_sib_r8(&e, REG_RDI, REG_RBX, REG_RAX); /* payload[k] ^= al */
	emit_inc_r64(&e, REG_RBX);                      /* k++ */
	emit_cmp_r32_imm32(&e, REG_RBX, (int32_t)crypto->text_len);
	disp8 = (int8_t)((ptrdiff_t)prga_loop_start - (ptrdiff_t)(e.len + 2));
	emit_jcc_rel8_direct(&e, JL, disp8);            /* jl PRGA_LOOP */

	/* ── restauration et saut vers OEP ──────────────────────────── */
	emit_add_rsp_imm32(&e, 256);                    /* libere S-box */
	emit_pop_r64(&e, REG_RDX);                      /* restaure _dl_fini */
	emit_jmp_rel32(&e, &patch_jmp_oep);             /* jmp OEP (patch dans elf_patch) */

	/* ── donnees embeds apres le code ───────────────────────────── */
	msg_offset = e.len;
	emit_raw(&e, (const uint8_t *)WOODY_MSG, WOODY_MSG_LEN);

	key_offset = e.len;
	emit_raw(&e, crypto->key, crypto->key_len);

	/* ── passe 2 : patch les disp32 connus maintenant ───────────── */
	disp32 = (int32_t)(msg_offset - (patch_lea_msg + 4));
	patch_disp32(&e, patch_lea_msg, disp32);

	disp32 = (int32_t)(key_offset - (patch_lea_key + 4));
	patch_disp32(&e, patch_lea_key, disp32);

	/* patch OEP : load_vaddr inconnu ici, fait dans elf_patch */

	/* ── construction du t_stub ─────────────────────────────────── */
	stub = malloc(sizeof(t_stub));
	if (!stub)
	{
		free(e.buf);
		return (NULL);
	}
	stub->bytes         = e.buf;
	stub->len           = e.len;
	stub->load_vaddr    = 0;
	stub->original_oep  = ctx->ehdr->e_entry;
	stub->patch_jmp_oep = patch_jmp_oep;
	return (stub);
}

void	stub_free(t_stub *stub)
{
	if (!stub)
		return ;
	free(stub->bytes);
	free(stub);
}
