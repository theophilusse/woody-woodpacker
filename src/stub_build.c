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
	//"mov eax, 1\n"
	//"mov edi, 1\n"
	"lea rsi, [msg]\n"
	"mov edx, 14\n"
	"syscall\n"

/*
// ; rsi = pointeur de scan (adresse de base du stub, set avant)
// ; rbx = fin de scan (= rsi + 0x3E8, set avant)
// ; rax = byte courant + temp

"@lde_loop:\n"
"cmp rsi, rbx\n"
"jae @lde_done\n"

"movzx eax, [rsi]\n"

// ; ── 0x24 : AND al, imm8 (2 octets) ──────────────────────────
"cmp eax, 0x24\n"
"jne @check_80\n"
"movzx eax, [rsi+1]\n"
"cmp eax, 0x0\n"
"jne @adv2_a\n"
// ; ACTION : instruction suspecte (imm=0)
"@adv2_a:\n"
"add rsi, 2\n"
"jmp @lde_loop\n"

// ; ── 0x80 : AND r/m8, imm8 (3 octets) ────────────────────────
"@check_80:\n"
"cmp eax, 0x80\n"
"jne @check_31\n"
"movzx eax, [rsi+2]\n"
"cmp eax, 0x0\n"
"jne @adv3_a\n"
// ; ACTION : instruction suspecte
"@adv3_a:\n"
"add rsi, 3\n"
"jmp @lde_loop\n"

// ; ── 0x31 : XOR r, r (2 octets) — extrait bit de cle ─────────
"@check_31:\n"
"cmp eax, 0x31\n"
"jne @check_b8\n"
"movzx eax, [rsi+1]\n"
"mov ecx, eax\n"
"and eax, 0x18\n"
"sar eax, 3\n"
"and ecx, 0x3\n"
"cmp eax, ecx\n"
"jne @adv3_b\n"
// ; ACTION : XOR r,r valide (reg==rm) → bit de cle = 0
"@adv3_b:\n"
"add rsi, 3\n"
"jmp @lde_loop\n"

// ; ── 0xB8-0xBF : MOV r32, imm32 (5 octets) ───────────────────
"@check_b8:\n"
"cmp eax, 0xb8\n"
"jl @check_48lea\n"
"cmp eax, 0xbf\n"
"jg @check_48lea\n"
// ; ACTION : MOV r32, imm32 → lit imm32 si utile
"add rsi, 5\n"
"jmp @lde_loop\n"

// ; ── 0x48 0x8D xx 0x25 : LEA r64, [abs] (8 octets) ───────────
"@check_48lea:\n"
"cmp eax, 0x48\n"
"jne @check_fe_ff\n"
"movzx eax, [rsi+1]\n"
"cmp eax, 0x8d\n"
"jne @check_fe_ff\n"
"movzx eax, [rsi+2]\n"
"and eax, 0x7\n"
"cmp eax, 0x4\n"
"jne @check_fe_ff\n"
"movzx eax, [rsi+3]\n"
"cmp eax, 0x25\n"
"jne @check_fe_ff\n"
// ; ACTION : LEA r64, [abs] → lit disp32 si utile
"add rsi, 8\n"
"jmp @lde_loop\n"

// ; ── 0xFE / 0xFF / 0x48 0xFF : INC/DEC (2 ou 3 octets) ───────
"@check_fe_ff:\n"
"movzx eax, [rsi]\n"
"cmp eax, 0xfe\n"
"je @check_incdec_modrm\n"
"cmp eax, 0xff\n"
"je @check_incdec_modrm\n"
"cmp eax, 0x48\n"
"jne @check_83_cmp\n"
"movzx eax, [rsi+1]\n"
"cmp eax, 0xff\n"
"jne @check_83_cmp\n"

"@check_incdec_modrm:\n"
"movzx eax, [rsi+1]\n"
"and eax, 0xf8\n"
"cmp eax, 0xc0\n"
"jne @check_dec_c8\n"
// ; INC r : 2 octets (FE/FF) ou 3 (48 FF)
"movzx eax, [rsi]\n"
"cmp eax, 0x48\n"
"jne @incdec2\n"
"add rsi, 3\n"
"jmp @lde_loop\n"
"@incdec2:\n"
"add rsi, 2\n"
"jmp @lde_loop\n"

"@check_dec_c8:\n"
"movzx eax, [rsi+1]\n"
"and eax, 0xf8\n"
"cmp eax, 0xc8\n"
"jne @check_83_sub1\n"
// ; DEC r : 2 ou 3 octets
"movzx eax, [rsi]\n"
"cmp eax, 0x48\n"
"jne @dec2\n"
"add rsi, 3\n"
"jmp @lde_loop\n"
"@dec2:\n"
"add rsi, 2\n"
"jmp @lde_loop\n"

// ; ── 0x83 /7 : CMP r32, imm8 (3 octets) ──────────────────────
"@check_83_cmp:\n"
"movzx eax, [rsi]\n"
"cmp eax, 0x83\n"
"jne @check_83_sub1\n"
"movzx eax, [rsi+1]\n"
"and eax, 0xf8\n"
"cmp eax, 0xf8\n"
"jne @check_83_sub1\n"
// ; ACTION : CMP r32, imm8
"add rsi, 3\n"
"jmp @lde_loop\n"

// ; ── 0x83 /5 : SUB r32, imm8=1 (3 octets) ────────────────────
"@check_83_sub1:\n"
"movzx eax, [rsi]\n"
"cmp eax, 0x83\n"
"jne @check_83_add1\n"
"movzx eax, [rsi+1]\n"
"and eax, 0xf8\n"
"cmp eax, 0xe8\n"
"jne @check_83_add1\n"
"movzx eax, [rsi+2]\n"
"cmp eax, 0x1\n"
"jne @check_83_add1\n"
// ; ACTION : SUB r32, 1
"add rsi, 3\n"
"jmp @lde_loop\n"

// ; ── 0x83 /0 : ADD r32, imm8=1 (3 octets) ────────────────────
"@check_83_add1:\n"
// ; ... meme pattern, /0 = 0x00 dans ModRM & 0xF8

// ; ── fallback : octet inconnu, avance de 1 ────────────────────
"add rsi, 1\n"
"jmp @lde_loop\n"

"@lde_done:\n"
*/

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
