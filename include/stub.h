#ifndef STUB_H
# define STUB_H

static const char STUB_SRC[] =
	// preserves _dl_fini que le kernel passe dans rdx
	"scan_start:\n"
	"push rdx\n"
	"push rbp\n"

	"sub rsp, 16\n"
	"_ZERO eax\n"//"xor eax, eax\n"
	"_ZERO ecx\n"//"xor ecx, ecx\n"
	"@zero_key:\n"
	"mov [rsp+rcx], al\n"
	"_INC ecx\n"
	"cmp ecx, 16\n"
	"jl @zero_key\n"
	"_SET rbp, rsp\n"//"mov rbp, rsp\n"
	"jmp @do_write\n"

	"@run_lde:\n"
	// ── lecture du payload ───────────────────────────────────────
    /* ── setup ───────────────────────────────────────────── */
    "_ZERO ecx\n"          /* bit_index = 0 */
    "lea rsi, [scan_start]\n"
    "lea rbx, [scan_end]\n"

    /* ── boucle principale ───────────────────────────────── */
	"@lde_loop:\n"
	"cmp rsi, rbx\n"
	"jb @lde_continue\n"    /* rel8 vers 5 octets plus loin, toujours dans range */
	"jmp @lde_done\n"       /* rel32, atteint n'importe où */
	"@lde_continue:\n"
    "_SET eax, [rsi]\n"

    /* ── 0x24 : AND al, imm8  (ZERO lsb=1 / 2 octets) ──── */
    "cmp eax, 0x24\n"
    "jne @check_80\n"
    "_SET eax, [rsi+1]\n"
    "cmp eax, 0x0\n"
    "jne @adv2_24\n"
    /* push(1) */
	"cmp ecx, 128\n"        /* KEY_LEN * 8 = 128 bits max */
	"jge @lde_done\n"        /* buffer plein : skip stockage */
	"push rcx\n"
	"mov edx, ecx\n" "sar edx, 3\n"
	"and ecx, 7\n" "mov al, 1\n" "shl al, cl\n"
	"pop rcx\n" "or [rbp+rdx], al\n" "_INC ecx\n"
    
	"@adv2_24:\n"
    "add rsi, 2\n" "jmp @lde_loop\n"

    "@check_80:\n"
    "cmp eax, 0x80\n" "jne @check_31\n"
    "_SET eax, [rsi+1]\n"
    "_SET edx, eax\n"
    "and edx, 0x38\n"          /* isole /r */

    /* /4 = AND = 0x20 → ZERO */
    "cmp edx, 0x20\n"
    "jne @check_80_add\n"
    "_SET eax, [rsi+2]\n"
    "cmp eax, 0x0\n"
    "jne @adv3_80\n"
    /* push(1) */
    "cmp ecx, 128\n" "jge @adv3_80\n"
    "push rcx\n"
    "_SET edx, ecx\n" "sar edx, 3\n"
    "and ecx, 7\n" "_SET al, 1\n" "shl al, cl\n"
    "pop rcx\n" "or [rbp+rdx], al\n" "_INC ecx\n"
    "@adv3_80:\n"
    "add rsi, 3\n" "jmp @lde_loop\n"

    /* /0 = ADD r8, 1 → INC lsb=0 */
    "@check_80_add:\n"
    "cmp edx, 0x0\n"           /* /0 = ADD */
    "jne @check_31\n"
    "_SET eax, [rsi+2]\n"
    "cmp eax, 0x1\n"
    "jne @check_31\n"
    "_INC ecx\n"                /* push(0) */
    "add rsi, 3\n" "jmp @lde_loop\n"

    /* ── 0x31 : XOR r/r  (ZERO lsb=0 / 2 octets) ────────── */
    "@check_31:\n"
    "cmp eax, 0x31\n"
    "jne @check_b8\n"
    "_SET eax, [rsi+1]\n"
    "mov edx, eax\n"
    "and eax, 0x18\n" "sar eax, 3\n"
    "and edx, 0x3\n"
    "cmp eax, edx\n"
    "jne @adv2_31\n"
    "_INC ecx\n"                /* push(0) */
    "cmp ecx, 128\n"        /* KEY_LEN * 8 = 128 bits max */
	"jge @lde_done\n"        /* buffer plein : skip stockage */
    "@adv2_31:\n"
    "add rsi, 2\n" "jmp @lde_loop\n"

    /* ── 0xB8-0xBF : MOV r32, imm32  (SET lsb=1 / 5 octets) */
    "@check_b8:\n"
    "cmp eax, 0xb8\n"
    "jl @check_lea\n"
    "cmp eax, 0xbf\n"
    "jg @check_lea\n"
    /* push(1) */
    "cmp ecx, 128\n"        /* KEY_LEN * 8 = 128 bits max */
	"jge @lde_done\n"        /* buffer plein : skip stockage */
	"push rcx\n"
	"mov edx, ecx\n" "sar edx, 3\n"
	"and ecx, 7\n" "mov al, 1\n" "shl al, cl\n"
	"pop rcx\n" "or [rbp+rdx], al\n" "_INC ecx\n"
    "add rsi, 5\n" "jmp @lde_loop\n"

    /* ── 0x48 0x8D X4 0x25 : LEA r64,[abs]  (SET lsb=0 / 8) */
    "@check_lea:\n"
    "cmp eax, 0x48\n" "jne @check_inc_fe\n"
    "_SET eax, [rsi+1]\n" "cmp eax, 0x8d\n" "jne @check_inc_fe\n"
    "_SET eax, [rsi+2]\n" "and eax, 0x7\n" "cmp eax, 0x4\n" "jne @check_inc_fe\n"
    "_SET eax, [rsi+3]\n" "cmp eax, 0x25\n" "jne @check_inc_fe\n"
    "_INC ecx\n"                /* push(0) */
    "cmp ecx, 128\n"        /* KEY_LEN * 8 = 128 bits max */
	"jge @lde_done\n"        /* buffer plein : skip stockage */
    "add rsi, 8\n" "jmp @lde_loop\n"

    /* 0x89 : MOV r32, r32  (SET reg→reg lsb=1 / 2 octets) */
    "@check_89:\n"
    "cmp eax, 0x89\n" "jne @check_0f_b6\n"
    "cmp ecx, 128\n"        /* KEY_LEN * 8 = 128 bits max */
	"jge @lde_done\n"        /* buffer plein : skip stockage */
	"push rcx\n"
	"mov edx, ecx\n" "sar edx, 3\n"
	"and ecx, 7\n" "mov al, 1\n" "shl al, cl\n"
	"pop rcx\n" "or [rbp+rdx], al\n" "_INC ecx\n"
    "add rsi, 5\n" "jmp @lde_loop\n"

    ///////////
    /* 8B : MOV r32, r/m → bit=1 */
    "@check_8b:\n"
    "cmp eax, 0x8b\n" "jne @check_0f_b6\n"
    "cmp ecx, 128\n"        /* KEY_LEN * 8 = 128 bits max */
	"jge @lde_done\n"        /* buffer plein : skip stockage */
    "push rcx\n"
    "mov edx, ecx\n" "sar edx, 3\n"
    "and ecx, 7\n" "mov al, 1\n" "shl al, cl\n"
    "pop rcx\n" "or [rbp+rdx], al\n" "_INC ecx\n"
    "jmp @advance_8b\n"

    /* 0F B6 : MOVZX r32, r/m8 → bit=0 */
    "@check_0f_b6:\n"
    "cmp eax, 0x0f\n" "jne @check_inc_fe\n"
    "_SET eax, [rsi+1]\n" "cmp eax, 0xb6\n" "jne @check_inc_fe\n"
    "_INC ecx\n"
    /* taille identique a 8B mais +1 pour le 0F prefixe */
    "_SET eax, [rsi+2]\n"   /* ModRM du MOVZX */
    "mov edx, eax\n"
    "and edx, 0xc0\n"    /* isole bits 7-6 = mod */
    "sar edx, 6\n"       /* edx = 0, 1, 2, ou 3 */
    "and eax, 7\n"
    "cmp edx, 0\n" "jne @mod01_0fb6\n"
    "cmp eax, 4\n" "je @sib_0fb6\n"
    "add rsi, 3\n" "jmp @lde_loop\n"   /* 0F B6 ModRM */
    "@sib_0fb6:\n"
    "add rsi, 4\n" "jmp @lde_loop\n"   /* 0F B6 ModRM SIB */
    "@mod01_0fb6:\n"
    "cmp edx, 1\n" "jne @lde_fallback\n"
    "cmp eax, 4\n" "je @sib_disp8_0fb6\n"
    "add rsi, 4\n" "jmp @lde_loop\n"   /* 0F B6 ModRM disp8 */
    "@sib_disp8_0fb6:\n"
    "add rsi, 5\n" "jmp @lde_loop\n"   /* 0F B6 ModRM SIB disp8 */

    /* calcul taille pour 8B depuis ModRM */
    "@advance_8b:\n"
    "_SET eax, [rsi+1]\n"
    "mov edx, eax\n"
    "and edx, 0xc0\n"    /* isole bits 7-6 = mod */
    "sar edx, 6\n"       /* edx = 0, 1, 2, ou 3 */
    "and eax, 7\n"
    "cmp edx, 0\n" "jne @mod01_8b\n"
    "cmp eax, 4\n" "je @sib_8b\n"
    "add rsi, 2\n" "jmp @lde_loop\n"   /* 8B ModRM */
    "@sib_8b:\n"
    "add rsi, 3\n" "jmp @lde_loop\n"   /* 8B ModRM SIB */
    "@mod01_8b:\n"
    "cmp edx, 1\n" "jne @lde_fallback\n"
    "cmp eax, 4\n" "je @sib_disp8_8b\n"
    "add rsi, 3\n" "jmp @lde_loop\n"   /* 8B ModRM disp8 */
    "@sib_disp8_8b:\n"
    "add rsi, 4\n" "jmp @lde_loop\n"   /* 8B ModRM SIB disp8 */
    /////////////


    /* 0x0F 0xB6 : MOVZX r32, r8  (SET reg→reg lsb=0 / 3 octets) */
    "@check_0f_b6:\n"
    "cmp eax, 0x0f\n" "jne @check_inc_fe\n"
    "_SET eax, [rsi+1]\n"
    "cmp eax, 0xb6\n" "jne @check_inc_fe\n"
    "_INC ecx\n"             /* push(0) */
    "cmp ecx, 128\n"        /* KEY_LEN * 8 = 128 bits max */
	"jge @lde_done\n"        /* buffer plein : skip stockage */
	"add rsi, 3\n" "jmp @lde_loop\n"

    /* 48 89 : MOV r64,r64 → bit=1 */
    "@check_48_89:\n"
    "cmp eax, 0x48\n" "jne @check_inc_fe\n"
    "_SET eax, [rsi+1]\n"
    "cmp eax, 0x89\n" "jne @check_48_8d\n"
    "cmp ecx, 128\n" "jge @adv3_48_89\n"
    "push rcx\n"
    "mov edx, ecx\n" "sar edx, 3\n"
    "and ecx, 7\n" "mov al, 1\n" "shl al, cl\n"
    "pop rcx\n" "or [rbp+rdx], al\n" "_INC ecx\n"
    "@adv3_48_89:\n"
    "add rsi, 3\n" "jmp @lde_loop\n"

    /* 48 8D mod=01 : LEA r64,[reg+0] → bit=0 */
    "@check_48_8d:\n"
    "cmp eax, 0x8d\n" "jne @check_48_b6\n"
    "_SET eax, [rsi+2]\n"
    "and eax, 0xc0\n"
    "cmp eax, 0x40\n"          /* mod=01 */
    "jne @check_inc_fe\n"
    "_INC ecx\n"               /* push(0) */
    "add rsi, 4\n" "jmp @lde_loop\n"

    /* ── 0xFE/0xFF (p[1]&0xF8)==0xC0 : INC r  (lsb=1 / 2) ─ */
    "@check_inc_fe:\n"
    "_SET eax, [rsi]\n"
    "cmp eax, 0xfe\n" "je @check_inc_modrm\n"
    "cmp eax, 0xff\n" "jne @check_cmp83\n"
    "@check_inc_modrm:\n"
    "_SET eax, [rsi+1]\n" "and eax, 0xf8\n"
    "cmp eax, 0xc0\n" "jne @check_cmp83\n"
    /* push(1) */
    "cmp ecx, 128\n"        /* KEY_LEN * 8 = 128 bits max */
	"jge @lde_done\n"        /* buffer plein : skip stockage */
	"push rcx\n"
	"mov edx, ecx\n" "sar edx, 3\n"
	"and ecx, 7\n" "mov al, 1\n" "shl al, cl\n"
	"pop rcx\n" "or [rbp+rdx], al\n" "_INC ecx\n"
    "add rsi, 2\n" "jmp @lde_loop\n"

    /* ── 0x83 (p[1]&0xF8)==0xF8 : CMP r32,imm8 (INC lsb=0 / 3) */
    "@check_cmp83:\n"
    "_SET eax, [rsi]\n" "cmp eax, 0x83\n" "jne @check_dec_ff\n"
    "_SET eax, [rsi+1]\n" "and eax, 0xf8\n"
    "cmp eax, 0xf8\n" "jne @check_dec_ff\n"
    "_INC ecx\n"                /* push(0) */
    "cmp ecx, 128\n"        /* KEY_LEN * 8 = 128 bits max */
	"jge @lde_done\n"        /* buffer plein : skip stockage */
    "add rsi, 3\n" "jmp @lde_loop\n"

    /* ── 0xFE/0xFF (p[1]&0xF8)==0xC8 : DEC r  (lsb=1 / 2) ─ */
    "@check_dec_ff:\n"
    "_SET eax, [rsi]\n"
    "cmp eax, 0xfe\n" "je @check_dec_modrm\n"
    "cmp eax, 0xff\n" "jne @check_sub83\n"
    "@check_dec_modrm:\n"
    "_SET eax, [rsi+1]\n" "and eax, 0xf8\n"
    "cmp eax, 0xc8\n" "jne @check_sub83\n"
    /* push(1) */
    "cmp ecx, 128\n"        /* KEY_LEN * 8 = 128 bits max */
	"jge @lde_done\n"        /* buffer plein : skip stockage */
	"push rcx\n"
	"mov edx, ecx\n" "sar edx, 3\n"
	"and ecx, 7\n" "mov al, 1\n" "shl al, cl\n"
	"pop rcx\n" "or [rbp+rdx], al\n" "_INC ecx\n"
    "add rsi, 2\n" "jmp @lde_loop\n"

    /* ── 0x83 (p[1]&0xF8)==0xE8 p[2]==1 : SUB r32,1 (DEC lsb=0 / 3) */
    "@check_sub83:\n"
    "_SET eax, [rsi]\n" "cmp eax, 0x83\n" "jne @lde_fallback\n"
    "_SET eax, [rsi+1]\n" "and eax, 0xf8\n"
    "cmp eax, 0xe8\n" "jne @lde_fallback\n"
    "_SET eax, [rsi+2]\n" "cmp eax, 0x1\n" "jne @lde_fallback\n"
    "_INC ecx\n"                /* push(0) */
    "cmp ecx, 128\n"        /* KEY_LEN * 8 = 128 bits max */
	"jge @lde_done\n"        /* buffer plein : skip stockage */
    "add rsi, 3\n" "jmp @lde_loop\n"

    /* ── fallback : p++ ──────────────────────────────────── */
    "@lde_fallback:\n"
    "add rsi, 1\n" "jmp @lde_loop\n"

    "@lde_done:\n"
	"jmp @after_lde\n"

	/////////////////////////////////// write(1, MSG, 14)
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
	"_ZERO ecx\n"//"xor ecx, ecx\n"
	"@ksa_init:\n"
	"mov [rsp+rcx], cl\n"
	"_INC cl\n"
	"jnz @ksa_init\n"

	// KSA : melange S par la cle
	"_ZERO ecx\n"//"xor ecx, ecx\n"
	"_ZERO edx\n"//"xor edx, edx\n"
	"@ksa_loop:\n"
	"_SET eax, [rsp+rcx]\n"
	"add dl, al\n"
	"mov al, cl\n"
	"and al, key_mask\n"
	"_SET eax, al\n"
	"_SET eax, [rsi+rax]\n"
	"add dl, al\n"
	"_SET eax, [rsp+rcx]\n"
	"xchg [rsp+rdx], al\n"
	"mov [rsp+rcx], al\n"
	"_INC cl\n"
	"jnz @ksa_loop\n"

	// PRGA + XOR payload
	"mov rdi, text_vaddr\n"
	"_ZERO ecx\n"//"xor ecx, ecx\n"
	"_ZERO edx\n"//"xor edx, edx\n"
	"_ZERO ebx\n"//"xor ebx, ebx\n"
	"@prga_loop:\n"
	"_INC cl\n"
	"_SET eax, [rsp+rcx]\n"
	"add dl, al\n"
	"xchg [rsp+rdx], al\n"
	"mov [rsp+rcx], al\n"
	"add al, [rsp+rdx]\n"
	"_SET eax, al\n"
	"_SET eax, [rsp+rax]\n"
	"xor [rdi+rbx], al\n"
	"_INC rbx\n"
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

#endif