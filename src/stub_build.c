#include <stdlib.h>
#include <string.h>
#include "woody.h"
#include "asm.h"

/*
** Registres utilises par le stub :
**   cl/rcx  = i  (compteur KSA/PRGA, wrap 8 bits naturel)
**   dl/rdx  = j  (idem)
**   rbx     = k  (index payload, 64 bits)
**   rax/al  = temporaire
**   rsi     = base cle (KSA), libere ensuite
**   rdi     = base payload (PRGA)
**   rsp     = S-box 256 octets (sub rsp, 256)
**   rdx preservé via push/pop autour du stub (_dl_fini du kernel)
*/

static const char STUB_SRC[] =
	/* preserves _dl_fini que le kernel passe dans rdx */
	"push rdx\n"

	/* write(1, MSG, 14) */
	"_SET eax, 1\n" //"mov eax, 1\n"
	"_SET edi, 1\n" //"mov edi, 1\n"
	"mov eax, 1\n"
	"mov edi, 1\n"
	"_INC eax\n"
	"_INC eax\n"
	"_INC eax\n"
	"_INC eax\n"
	"lea rsi, [msg]\n"
	"mov edx, 14\n"
	"syscall\n"

	/* mprotect(page_vaddr, page_size, PROT_RWX) */
	"mov rdi, prot_addr\n"
	"mov esi, prot_size\n"
	"mov edx, 7\n"
	"mov eax, 10\n"
	"syscall\n"

	/* S-box sur la pile */
	"sub rsp, 256\n"

	/* rsi = base de la cle (RIP-relative) */
	"lea rsi, [key]\n"

	/* KSA init : S[i] = i, i = 0..255 */
	"xor ecx, ecx\n"
	"@ksa_init:\n"
	"mov [rsp+rcx], cl\n"
	"inc cl\n"
	"jnz @ksa_init\n"

	/* KSA : melange S par la cle */
	"xor ecx, ecx\n"
	"xor edx, edx\n"
	"@ksa_loop:\n"
	"movzx eax, [rsp+rcx]\n"
	"add dl, al\n"
	"mov al, cl\n"
	"and al, key_mask\n"
	"movzx eax, al\n"
	"movzx eax, [rsi+rax]\n"
	"add dl, al\n"
	"movzx eax, [rsp+rcx]\n"
	"xchg [rsp+rdx], al\n"
	"mov [rsp+rcx], al\n"
	"inc cl\n"
	"jnz @ksa_loop\n"

	/* PRGA + XOR payload */
	"mov rdi, text_vaddr\n"
	"xor ecx, ecx\n"
	"xor edx, edx\n"
	"xor ebx, ebx\n"
	"@prga_loop:\n"
	"inc cl\n"
	"movzx eax, [rsp+rcx]\n"
	"add dl, al\n"
	"xchg [rsp+rdx], al\n"
	"mov [rsp+rcx], al\n"
	"add al, [rsp+rdx]\n"
	"movzx eax, al\n"
	"movzx eax, [rsp+rax]\n"
	"xor [rdi+rbx], al\n"
	"inc rbx\n"
	"cmp ebx, text_len\n"
	"jl @prga_loop\n"

	/* restauration et saut vers OEP */
	"add rsp, 256\n"
	"pop rdx\n"
	"jmp @oep\n"

	/* donnees embarquees apres le code */
	"msg:\n"
	".msg\n"
	"key:\n"
	".key\n";

t_stub	*stub_build(t_elf_ctx *ctx, t_crypto_ctx *crypto)
{
	t_asm_result	res;
	t_stub			*stub;

	memset(&res, 0, sizeof(res));
	if (asm_build(STUB_SRC, crypto, &res) < 0)
	{
		free(res.e.buf);
		return (NULL);
	}
	stub = malloc(sizeof(t_stub));
	if (!stub)
	{
		free(res.e.buf);
		return (NULL);
	}
	stub->bytes         = res.e.buf;
	stub->len           = res.e.len;
	stub->load_vaddr    = 0;
	stub->original_oep  = ctx->ehdr->e_entry;
	stub->patch_jmp_oep = res.patch_jmp_oep;
	return (stub);
}

void	stub_free(t_stub *stub)
{
	if (!stub)
		return ;
	free(stub->bytes);
	free(stub);
}
