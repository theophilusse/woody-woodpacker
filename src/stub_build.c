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
	// preserves _dl_fini que le kernel passe dans rdx
	"scan_start:\n"
	"push rdx\n"
	"push rbp\n"

	"sub rsp, 16\n"
	"xor eax, eax\n"
	"xor ecx, ecx\n"
	"@zero_key:\n"
	"mov [rsp+rcx], al\n"
	"inc ecx\n"
	"cmp ecx, 16\n"
	"jl @zero_key\n"
	"mov rbp, rsp\n"
	"jmp @do_write\n"

	"@run_lde:\n"
	// ── lecture du payload ───────────────────────────────────────
    /* ── setup ───────────────────────────────────────────── */
    "xor ecx, ecx\n"          /* bit_index = 0 */
    "lea rsi, [scan_start]\n"
    "lea rbx, [scan_end]\n"

    /* ── boucle principale ───────────────────────────────── */
    "@lde_loop:\n"
    "cmp rsi, rbx\n"
    "jae @lde_done\n"
    "movzx eax, [rsi]\n"

    /* ── 0x24 : AND al, imm8  (ZERO lsb=1 / 2 octets) ──── */
    "cmp eax, 0x24\n"
    "jne @check_80\n"
    "movzx eax, [rsi+1]\n"
    "cmp eax, 0x0\n"
    "jne @adv2_24\n"
    /* push(1) */
    "push rcx\n"
    "mov edx, ecx\n" "sar edx, 3\n"
    "and ecx, 7\n" "mov al, 1\n" "shl al, cl\n"
    "pop rcx\n" "or [rbp+rdx], al\n" "inc ecx\n"
    "@adv2_24:\n"
    "add rsi, 2\n" "jmp @lde_loop\n"

    /* ── 0x80 : AND r/m8, imm8  (ZERO alt / 3 octets) ───── */
    "@check_80:\n"
    "cmp eax, 0x80\n"
    "jne @check_31\n"
    "movzx eax, [rsi+2]\n"
    "cmp eax, 0x0\n"
    "jne @adv3_80\n"
    /* push(1) */
    "push rcx\n"
    "mov edx, ecx\n" "sar edx, 3\n"
    "and ecx, 7\n" "mov al, 1\n" "shl al, cl\n"
    "pop rcx\n" "or [rbp+rdx], al\n" "inc ecx\n"
    "@adv3_80:\n"
    "add rsi, 3\n" "jmp @lde_loop\n"

    /* ── 0x31 : XOR r/r  (ZERO lsb=0 / 2 octets) ────────── */
    "@check_31:\n"
    "cmp eax, 0x31\n"
    "jne @check_b8\n"
    "movzx eax, [rsi+1]\n"
    "mov edx, eax\n"
    "and eax, 0x18\n" "sar eax, 3\n"
    "and edx, 0x3\n"
    "cmp eax, edx\n"
    "jne @adv2_31\n"
    "inc ecx\n"                /* push(0) */
    "@adv2_31:\n"
    "add rsi, 2\n" "jmp @lde_loop\n"

    /* ── 0xB8-0xBF : MOV r32, imm32  (SET lsb=1 / 5 octets) */
    "@check_b8:\n"
    "cmp eax, 0xb8\n"
    "jl @check_lea\n"
    "cmp eax, 0xbf\n"
    "jg @check_lea\n"
    /* push(1) */
    "push rcx\n"
    "mov edx, ecx\n" "sar edx, 3\n"
    "and ecx, 7\n" "mov al, 1\n" "shl al, cl\n"
    "pop rcx\n" "or [rbp+rdx], al\n" "inc ecx\n"
    "add rsi, 5\n" "jmp @lde_loop\n"

    /* ── 0x48 0x8D X4 0x25 : LEA r64,[abs]  (SET lsb=0 / 8) */
    "@check_lea:\n"
    "cmp eax, 0x48\n" "jne @check_inc_fe\n"
    "movzx eax, [rsi+1]\n" "cmp eax, 0x8d\n" "jne @check_inc_fe\n"
    "movzx eax, [rsi+2]\n" "and eax, 0x7\n" "cmp eax, 0x4\n" "jne @check_inc_fe\n"
    "movzx eax, [rsi+3]\n" "cmp eax, 0x25\n" "jne @check_inc_fe\n"
    "inc ecx\n"                /* push(0) */
    "add rsi, 8\n" "jmp @lde_loop\n"

    /* ── 0xFE/0xFF (p[1]&0xF8)==0xC0 : INC r  (lsb=1 / 2) ─ */
    "@check_inc_fe:\n"
    "movzx eax, [rsi]\n"
    "cmp eax, 0xfe\n" "je @check_inc_modrm\n"
    "cmp eax, 0xff\n" "jne @check_cmp83\n"
    "@check_inc_modrm:\n"
    "movzx eax, [rsi+1]\n" "and eax, 0xf8\n"
    "cmp eax, 0xc0\n" "jne @check_cmp83\n"
    /* push(1) */
    "push rcx\n"
    "mov edx, ecx\n" "sar edx, 3\n"
    "and ecx, 7\n" "mov al, 1\n" "shl al, cl\n"
    "pop rcx\n" "or [rbp+rdx], al\n" "inc ecx\n"
    "add rsi, 2\n" "jmp @lde_loop\n"

    /* ── 0x83 (p[1]&0xF8)==0xF8 : CMP r32,imm8 (INC lsb=0 / 3) */
    "@check_cmp83:\n"
    "movzx eax, [rsi]\n" "cmp eax, 0x83\n" "jne @check_dec_ff\n"
    "movzx eax, [rsi+1]\n" "and eax, 0xf8\n"
    "cmp eax, 0xf8\n" "jne @check_dec_ff\n"
    "inc ecx\n"                /* push(0) */
    "add rsi, 3\n" "jmp @lde_loop\n"

    /* ── 0xFE/0xFF (p[1]&0xF8)==0xC8 : DEC r  (lsb=1 / 2) ─ */
    "@check_dec_ff:\n"
    "movzx eax, [rsi]\n"
    "cmp eax, 0xfe\n" "je @check_dec_modrm\n"
    "cmp eax, 0xff\n" "jne @check_sub83\n"
    "@check_dec_modrm:\n"
    "movzx eax, [rsi+1]\n" "and eax, 0xf8\n"
    "cmp eax, 0xc8\n" "jne @check_sub83\n"
    /* push(1) */
    "push rcx\n"
    "mov edx, ecx\n" "sar edx, 3\n"
    "and ecx, 7\n" "mov al, 1\n" "shl al, cl\n"
    "pop rcx\n" "or [rbp+rdx], al\n" "inc ecx\n"
    "add rsi, 2\n" "jmp @lde_loop\n"

    /* ── 0x83 (p[1]&0xF8)==0xE8 p[2]==1 : SUB r32,1 (DEC lsb=0 / 3) */
    "@check_sub83:\n"
    "movzx eax, [rsi]\n" "cmp eax, 0x83\n" "jne @lde_fallback\n"
    "movzx eax, [rsi+1]\n" "and eax, 0xf8\n"
    "cmp eax, 0xe8\n" "jne @lde_fallback\n"
    "movzx eax, [rsi+2]\n" "cmp eax, 0x1\n" "jne @lde_fallback\n"
    "inc ecx\n"                /* push(0) */
    "add rsi, 3\n" "jmp @lde_loop\n"

    /* ── fallback : p++ ──────────────────────────────────── */
    "@lde_fallback:\n"
    "add rsi, 1\n" "jmp @lde_loop\n"

    "@lde_done:\n"
	"jmp @after_lde\n"

	//////////////////////////// write(1, MSG, 14)
	"@do_write:\n"
	"_SET eax, 1\n" //"mov eax, 1\n"
	"_SET edi, 1\n" //"mov edi, 1\n"
	//"mov eax, 1\n"
	//"mov edi, 1\n"
	"lea rsi, [msg]\n"
	"mov edx, 14\n"
	"syscall\n"
	"jmp @run_lde\n"

	"@after_lde:\n"

	/////////////////////////////////// Decrypt payload (RC4) et jump vers OEP

	// mprotect(page_vaddr, page_size, PROT_RWX)
	"mov rdi, prot_addr\n"
	"mov esi, prot_size\n"
	"mov edx, 7\n"
	"mov eax, 10\n"
	"syscall\n"

	// S-box sur la pile
	"sub rsp, 256\n"

	// rsi = base de la cle (RIP-relative)
	"mov rsi, rbp\n"

	// KSA init : S[i] = i, i = 0..255
	"xor ecx, ecx\n"
	"@ksa_init:\n"
	"mov [rsp+rcx], cl\n"
	"inc cl\n"
	"jnz @ksa_init\n"

	// KSA : melange S par la cle
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

	// PRGA + XOR payload
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

	// restauration et saut vers OEP
	"add rsp, 256\n"
	"pop rdx\n"
	"pop rbp\n"
	"jmp @oep\n"

	// donnees embarquees apres le code
	"msg:\n"
	".msg\n"
	"key:\n"
	".key\n"
	"scan_end:\n";
/*
    "push rdx\n"
    "_SET eax, 1\n"
    "_SET edi, 1\n"
    "lea rsi, [msg]\n"
    "mov edx, 14\n"
    "syscall\n"
    "mov rdi, prot_addr\n"
    "mov esi, prot_size\n"
    "mov edx, 7\n"
    "mov eax, 10\n"
    "syscall\n"
    "sub rsp, 256\n"
    "lea rsi, [key]\n"
    "xor ecx, ecx\n"
    "@ksa_init:\n"
    "mov [rsp+rcx], cl\n"
    "inc cl\n"
    "jnz @ksa_init\n"
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
    "add rsp, 256\n"
    "pop rdx\n"
    "jmp @oep\n"
    "msg:\n"
    ".msg\n"
    "key:\n"
    ".key\n"
*/

/*

	////////??/////////////////////////////////
    // ── setup ─────────────────────────────────────────────
    "xor ecx, ecx\n"
    "lea rsi, [scan_start]\n"
    "lea rbx, [scan_end]\n"
 
    // ── boucle principale ─────────────────────────────────
    "@lde_loop:\n"
    "cmp rsi, rbx\n"
    "jae @lde_done\n"
    "movzx eax, [rsi]\n"
 
    // ── 0x24 : AND al, imm8  (ZERO lsb=1 / 2 octets) ────
    "cmp eax, 0x24\n"
    "jne @check_80\n"
    "movzx eax, [rsi+1]\n"
    "cmp eax, 0x0\n"
    "jne @adv2_24\n"
    // push(1)
    "push rcx\n"
    "mov edx, ecx\n" "sar edx, 3\n"
    "and ecx, 7\n" "mov al, 1\n" "shl al, cl\n"
    "pop rcx\n" "or [rdi+rdx], al\n" "inc ecx\n"
    "@adv2_24:\n"
    "add rsi, 2\n" "jmp @lde_loop\n"
 
    // ── 0x80 : AND r/m8, imm8  (ZERO alt / 3 octets) ─────
    "@check_80:\n"
    "cmp eax, 0x80\n"
    "jne @check_31\n"
    "movzx eax, [rsi+2]\n"
    "cmp eax, 0x0\n"
    "jne @adv3_80\n"
    // push(1)
    "push rcx\n"
    "mov edx, ecx\n" "sar edx, 3\n"
    "and ecx, 7\n" "mov al, 1\n" "shl al, cl\n"
    "pop rcx\n" "or [rdi+rdx], al\n" "inc ecx\n"
    "@adv3_80:\n"
    "add rsi, 3\n" "jmp @lde_loop\n"
 
    // ── 0x31 : XOR r/r  (ZERO lsb=0 / 2 octets) ──────────
    "@check_31:\n"
    "cmp eax, 0x31\n"
    "jne @check_b8\n"
    "movzx eax, [rsi+1]\n"
    "mov edx, eax\n"
    "and eax, 0x18\n" "sar eax, 3\n"
    "and edx, 0x3\n"
    "cmp eax, edx\n"
    "jne @adv2_31\n"
    "inc ecx\n"                // push(0)
    "@adv2_31:\n"
    "add rsi, 2\n" "jmp @lde_loop\n"
 
    // ── 0xB8-0xBF : MOV r32, imm32  (SET lsb=1 / 5 octets)
    "@check_b8:\n"
    "cmp eax, 0xb8\n"
    "jl @check_lea\n"
    "cmp eax, 0xbf\n"
    "jg @check_lea\n"
    // push(1)
    "push rcx\n"
////////////////////////////////////////////

	*/

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
