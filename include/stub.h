#ifndef STUB_H
# define STUB_H

static const char STUB_HEADER[] =
	// preserves _dl_fini que le kernel passe dans rdx
	"scan_start:\n"
	"push rdx\n"
	"push rbp\n";

static const char STUB_ANTIDEBUG_1[] =
    //////////////////////////// ANTI_DEBUG ////////////////////////////
    //; Appel syscall ptrace(PTRACE_TRACEME, 0, 1, 0)
    "_SET rax, 101\n" //       ; sys_ptrace
    "_SET rdi, 0\n" //         ; PTRACE_TRACEME
    "_ZERO rsi\n" //       ; NULL (pid du parent)
    "_SET rdx, 1\n" //         ; NULL (addr)
    "_ZERO r10\n" //       ; NULL (data)
    "syscall\n"
    //; Si rax == -EPERM (-1), le processus est déjà traçé
    "cmp eax, -1\n"//"cmp rax, -1\n"
	"je debugger_detected\n";

static const char STUB_ANTIDEBUG_PROLOGUE[] =
    "jmp debugger_not_detected\n";

static const char STUB_DEBUGGER_DETECTED[] =
    "debugger_detected:\n"
	"jmp evasion_fail\n";

static const char STUB_NO_ANTIDEBUG[] =
	"debugger_not_detected:\n"
	"jmp evasion_complete\n";

static const char STUB_EVASION_FAIL[] =
	"evasion_fail:\n"
    "_SET eax, 1\n"
	"_SET edi, 1\n"
	"lea rsi, [evasion_msg]\n"
	"_SET edx, 9\n"
	"syscall\n"
    "_SET rax, 60\n" //      ; sys_exit (numéro du syscall)
    "_SET rdi, 0\n" //        ; code de sortie (0 = succès)
    "syscall\n";

static const char STUB_EVASION_COMPLETE[] =
	"evasion_complete:\n";

static const char STUB_ZERO_KEY[] =
	"sub rsp, 16\n"
	"_ZERO eax\n"//"xor eax, eax\n"
	"_ZERO ecx\n"//"xor ecx, ecx\n"
	"@zero_key:\n"
	"mov [rsp+rcx], al\n"
	"_INC ecx\n"
	"cmp ecx, 16\n"
	"jl @zero_key\n"
	"_SET rbp, rsp\n"//"mov rbp, rsp\n"
	"jmp @do_write\n";

static const char STUB_ZERO_KEY_NOLDE[] =
	"sub rsp, 16\n"
	"_SET rbp, rsp\n"
	"lea rsi, [key]\n"
	"_ZERO ecx\n"
	"@copy_key_plain:\n"
	"_SET al, [rsi+rcx]\n"
	"mov [rbp+rcx], al\n"
	"_INC ecx\n"
	"cmp ecx, 16\n"
	"jl @copy_key_plain\n"
	"jmp @do_write\n";


static const char STUB_RUN_LDE_BYPASS[] =
	"@run_lde:\n"
	"jmp @lde_done\n";   /* rbp deja rempli en amont, saute tout le scan */

static const char STUB_RUN_LDE_ACTIVE[] =
"@run_lde:\n"
    /* ── setup ───────────────────────────────────────────── */
"_ZERO ecx\n"          /* bit_index = 0 */
"lea rsi, [scan_start]\n"
"lea rbx, [scan_end]\n"
"@lde_loop:\n"
"cmp rsi, rbx\n"
"jb @lde_continue\n"
"jmp @lde_done\n"
"@lde_continue:\n"
"_SET eax, [rsi]\n"
"cmp al, 0x40\n" "jl @lde_no_rex\n"
"cmp al, 0x4f\n" "jg @lde_no_rex\n"
"add rsi, 1\n"
"@lde_no_rex:\n"
"_SET eax, [rsi]\n"
"cmp al, 0xe9\n" "jne @o_eb\n"
"add rsi, 5\n" "jmp @lde_loop\n"
"@o_eb:\n"
"cmp al, 0xeb\n" "jne @o_3c\n"
"add rsi, 2\n" "jmp @lde_loop\n"
"@o_3c:\n"
"cmp al, 0x3c\n" "jne @o_3c_break\n"
"add rsi, 2\n" "jmp @lde_loop\n"
"@o_3c_break:\n";

static const char STUB_LDE_INT3_TRAP[] =
	"@o_cc:\n"
	"cmp al, 0xcc\n" "jne @o_cc_break\n"
	"cmp ecx, 128\n" "jge @adv_cc\n"
	"push rcx\n" "_SET edx, ecx\n" "sar edx, 3\n"
	"and ecx, 7\n" "mov al, 1\n" "shl al, cl\n"
	"pop rcx\n" "or [rbp+rdx], al\n" "_INC ecx\n"
	"@adv_cc:\n" "add rsi, 1\n" "jmp @lde_loop\n"
	"@o_cc_break:\n";

static const char STUB_LDE_CORE_EPILOGUE[] =
	"@o_24:\n"
	"cmp al, 0x24\n" "jne @o_80\n"
	"_SET eax, [rsi+1]\n" "cmp al, 0x0\n" "jne @adv2_24\n"
	"cmp ecx, 128\n" "jge @adv2_24\n"
	"push rcx\n" "_SET edx, ecx\n" "sar edx, 3\n"
	"and ecx, 7\n" "mov al, 1\n" "shl al, cl\n"
	"pop rcx\n" "or [rbp+rdx], al\n" "_INC ecx\n"
	"@adv2_24:\n" "add rsi, 2\n" "jmp @lde_loop\n"

	/* ══════════ 0x80 /r ib : AND r8,0 (bit1) / ADD r8,1 (bit0) / SUB r8,1 (bit0) ══════════ */
	"@o_80:\n"
	"cmp al, 0x80\n" "jne @o_81\n"
	"_SET eax, [rsi+1]\n" "_SET edx, eax\n" "and edx, 0x38\n"
	"cmp edx, 0x20\n" "je @o80_and\n"
	"cmp edx, 0x0\n"  "je @o80_add\n"
	"cmp edx, 0x28\n" "je @o80_sub\n"
	"jmp @lde_fallback\n"

	"@o80_and:\n"
	"_SET eax, [rsi+2]\n" "cmp al, 0x0\n" "jne @lde_fallback\n"
	"cmp ecx, 128\n" "jge @adv3_80and\n"
	"push rcx\n" "_SET edx, ecx\n" "sar edx, 3\n"
	"and ecx, 7\n" "mov al, 1\n" "shl al, cl\n"
	"pop rcx\n" "or [rbp+rdx], al\n" "_INC ecx\n"
	"@adv3_80and:\n" "add rsi, 3\n" "jmp @lde_loop\n"

	"@o80_add:\n"
	"_SET eax, [rsi+2]\n" "cmp al, 0x1\n" "jne @lde_fallback\n"
	"cmp ecx, 128\n" "jge @adv3_80add\n"
	"_INC ecx\n"
	"@adv3_80add:\n" "add rsi, 3\n" "jmp @lde_loop\n"

	"@o80_sub:\n"                                  /* NOUVEAU : SUB r8,1 (_DEC bit=0) */
	"_SET eax, [rsi+2]\n" "cmp al, 0x1\n" "jne @lde_fallback\n"
	"cmp ecx, 128\n" "jge @adv3_80sub\n"
	"_INC ecx\n"
	"@adv3_80sub:\n" "add rsi, 3\n" "jmp @lde_loop\n"

	/* ══════════ 0x81 /r id : ADD r32,1 long (bit0) / AND r32,imm32 (bit0) / CMP (skip) ══════════ */
	"@o_81:\n"
	"cmp al, 0x81\n" "jne @o_83\n"
	"_SET eax, [rsi+1]\n" "_SET edx, eax\n" "and edx, 0x38\n"
	"cmp edx, 0x0\n"  "je @o81_add\n"
	"cmp edx, 0x20\n" "je @o81_and\n"
	"cmp edx, 0x38\n" "je @o81_cmp\n"
	"jmp @lde_fallback\n"

	"@o81_add:\n"
	"_SET eax, [rsi+2]\n" "cmp al, 0x1\n" "jne @lde_fallback\n"
	"_SET eax, [rsi+3]\n" "cmp al, 0x0\n" "jne @lde_fallback\n"
	"_SET eax, [rsi+4]\n" "cmp al, 0x0\n" "jne @lde_fallback\n"
	"_SET eax, [rsi+5]\n" "cmp al, 0x0\n" "jne @lde_fallback\n"
	"cmp ecx, 128\n" "jge @adv6_81add\n"
	"_INC ecx\n"
	"@adv6_81add:\n" "add rsi, 6\n" "jmp @lde_loop\n"

	"@o81_and:\n"
	"_SET eax, [rsi+2]\n" "cmp al, 0xff\n" "jne @lde_fallback\n"
	"_SET eax, [rsi+3]\n" "cmp al, 0x0\n"  "jne @lde_fallback\n"
	"_SET eax, [rsi+4]\n" "cmp al, 0x0\n"  "jne @lde_fallback\n"
	"_SET eax, [rsi+5]\n" "cmp al, 0x0\n"  "jne @lde_fallback\n"
	"cmp ecx, 128\n" "jge @adv6_81and\n"
	"push rcx\n" "_SET edx, ecx\n" "sar edx, 3\n"
	"and ecx, 7\n" "mov al, 1\n" "shl al, cl\n"
	"pop rcx\n" "or [rbp+rdx], al\n" "_INC ecx\n"
	"@adv6_81and:\n" "add rsi, 6\n" "jmp @lde_loop\n"

	"@o81_cmp:\n"                                  /* filet de securite, structurel, aucun bit */
	"add rsi, 6\n" "jmp @lde_loop\n"

	/* ══════════ 0x83 /r ib : AND r32/64,0 (bit1) / SUB r32/64,1 (bit0) / CMP (skip) ══════════ */
	"@o_83:\n"
	"cmp al, 0x83\n" "jne @o_31\n"
	"_SET eax, [rsi+1]\n" "and eax, 0xf8\n"
	"cmp al, 0xe0\n" "je @o83_and_checkimm\n"
	"cmp eax, 0xe8\n" "je @o83_sub\n"
	"cmp eax, 0xf8\n" "je @o83_cmp\n"
	"jmp @lde_fallback\n"

	"@o83_and_checkimm:\n"
	"_SET eax, [rsi+2]\n" "cmp al, 0x0\n" "jne @lde_fallback\n"
	"cmp ecx, 128\n" "jge @adv3_83and\n"
	"push rcx\n" "_SET edx, ecx\n" "sar edx, 3\n"
	"and ecx, 7\n" "mov al, 1\n" "shl al, cl\n"
	"pop rcx\n" "or [rbp+rdx], al\n" "_INC ecx\n"
	"@adv3_83and:\n" "add rsi, 3\n" "jmp @lde_loop\n"

	"@o83_sub:\n"
	"_SET eax, [rsi+2]\n" "cmp al, 0x1\n" "jne @lde_fallback\n"
	"cmp ecx, 128\n" "jge @adv3_83sub\n"
	"_INC ecx\n"
	"@adv3_83sub:\n" "add rsi, 3\n" "jmp @lde_loop\n"

	"@o83_cmp:\n" "add rsi, 3\n" "jmp @lde_loop\n"

	/* ══════════ 0x31 /r mod=11 meme registre : XOR reg,reg → bit=0 ══════════ */
	"@o_31:\n"
	"cmp al, 0x31\n" "jne @o_89\n"
	"_SET eax, [rsi+1]\n"
	"_SET edx, eax\n" "and edx, 0xc0\n" "cmp dl, 0xc0\n" "jne @adv2_31\n"
	"_SET edx, eax\n" "and edx, 0x38\n" "sar edx, 3\n"
	"and eax, 0x7\n"
	"cmp eax, edx\n" "jne @adv2_31\n"
	"cmp ecx, 128\n" "jge @adv2_31\n"
	"_INC ecx\n"
	"@adv2_31:\n" "add rsi, 2\n" "jmp @lde_loop\n"

	/* ══════════ 0x89 /r mod=11 : MOV r32/64,r32/64 → bit=1 ══════════ */
	"@o_89:\n"
	"cmp al, 0x89\n" "jne @o_8a\n"
	"_SET eax, [rsi+1]\n" "and eax, 0xc0\n" "cmp eax, 0xc0\n" "jne @lde_fallback\n"
	"cmp ecx, 128\n" "jge @adv2_89\n"
	"push rcx\n" "_SET edx, ecx\n" "sar edx, 3\n"
	"and ecx, 7\n" "mov al, 1\n" "shl al, cl\n"
	"pop rcx\n" "or [rbp+rdx], al\n" "_INC ecx\n"
	"@adv2_89:\n" "add rsi, 2\n" "jmp @lde_loop\n"

	/* ══════════ 0x8A /r : MOV r8, r/m8 → bit=1 (mod00/01, +SIB) ══════════ */
	"@o_8a:\n"
	"cmp al, 0x8a\n" "jne @o_8b_and_pair\n"
	"_SET eax, [rsi+1]\n"
	"_SET edx, eax\n" "and edx, 0xc0\n" "and eax, 0x7\n"
	"cmp edx, 0x0\n" "je @o8a_m00\n"
	"cmp edx, 0x40\n" "je @o8a_m01\n"
	"jmp @lde_fallback\n"

	"@o8a_m00:\n"
	"cmp ecx, 128\n" "jge @adv_8a00\n"
	"push rax\n"                              /* NOUVEAU : sauvegarde eax (rm) */
	"push rcx\n" "_SET edx, ecx\n" "sar edx, 3\n"
	"and ecx, 7\n" "mov al, 1\n" "shl al, cl\n"
	"pop rcx\n" "or [rbp+rdx], al\n" "_INC ecx\n"
	"pop rax\n"                               /* NOUVEAU : restaure eax (rm) */
	"@adv_8a00:\n"
	"cmp eax, 4\n" "je @adv_8a00_sib\n"
	"add rsi, 2\n" "jmp @lde_loop\n"
	"@adv_8a00_sib:\n" "add rsi, 3\n" "jmp @lde_loop\n"

	"@o8a_m01:\n"
	"cmp ecx, 128\n" "jge @adv_8a01\n"
	"push rax\n"                              /* NOUVEAU */
	"push rcx\n" "_SET edx, ecx\n" "sar edx, 3\n"
	"and ecx, 7\n" "mov al, 1\n" "shl al, cl\n"
	"pop rcx\n" "or [rbp+rdx], al\n" "_INC ecx\n"
	"pop rax\n"                               /* NOUVEAU */
	"@adv_8a01:\n"
	"cmp eax, 4\n" "je @adv_8a01_sib\n"
	"add rsi, 3\n" "jmp @lde_loop\n"
	"@adv_8a01_sib:\n" "add rsi, 4\n" "jmp @lde_loop\n"

/* 8B /r (mod00 ou mod01, sans SIB) immediatement suivi de
** AND r32,0xFF forme longue (REX? 81 /4 imm32=0xFF)
** = paire emise par _SET bit=1 (equivalent semantique a movzx,
** ne lit qu'1 octet). Detection PUREMENT structurelle (masque
** mod+reg comme @o_83), aucun registre precis n'est teste. */
"@o_8b_and_pair:\n"
"cmp al, 0x8b\n" "jne @o_8b\n"
"_SET edx, [rsi+1]\n"                       /* edx = modrm du 8B */
"_SET r8d, edx\n" "and r8d, 0xc0\n"          /* r8d = mod */
"and edx, 0x7\n"                            /* edx = rm */
"cmp r8d, 0x0\n"  "je @o8bp_try00\n"
"cmp r8d, 0x40\n" "je @o8bp_try01\n"
"jmp @o_8b\n"

/* ── mod=00 : 8B fait 2 octets (opcode+modrm, pas de disp) ── */
"@o8bp_try00:\n"
"cmp dl, 4\n" "je @o8bp_try00_sib\n"
"_SET edx, [rsi+2]\n"
"cmp dl, 0x40\n" "jl @o8bp00_norex\n"
"cmp dl, 0x4f\n" "jg @o8bp00_norex\n"
"_SET edx, [rsi+3]\n" "cmp dl, 0x81\n" "jne @o_8b\n"
"_SET edx, [rsi+4]\n" "and dl, 0xf8\n" "cmp dl, 0xe0\n" "jne @o_8b\n"
"_SET edx, [rsi+5]\n" "cmp dl, 0xff\n" "jne @o_8b\n"
"_SET edx, [rsi+6]\n" "cmp dl, 0x0\n"  "jne @o_8b\n"
"_SET edx, [rsi+7]\n" "cmp dl, 0x0\n"  "jne @o_8b\n"
"_SET edx, [rsi+8]\n" "cmp dl, 0x0\n"  "jne @o_8b\n"
"cmp ecx, 128\n" "jge @o8bp_a1\n"
"push rcx\n" "push rdx\n" "_SET edx, ecx\n" "sar edx, 3\n"
"and ecx, 7\n" "mov al, 1\n" "shl al, cl\n"
"pop rdx\n" "or [rbp+rdx], al\n" "pop rcx\n" "_INC ecx\n"
"@o8bp_a1:\n" "add rsi, 9\n" "jmp @lde_loop\n"

"@o8bp00_norex:\n"
"cmp dl, 0x81\n" "jne @o_8b\n"
"_SET edx, [rsi+3]\n" "and dl, 0xf8\n" "cmp dl, 0xe0\n" "jne @o_8b\n"
"_SET edx, [rsi+4]\n" "cmp dl, 0xff\n" "jne @o_8b\n"
"_SET edx, [rsi+5]\n" "cmp dl, 0x0\n"  "jne @o_8b\n"
"_SET edx, [rsi+6]\n" "cmp dl, 0x0\n"  "jne @o_8b\n"
"_SET edx, [rsi+7]\n" "cmp dl, 0x0\n"  "jne @o_8b\n"
"cmp ecx, 128\n" "jge @o8bp_a2\n"
"push rcx\n" "push rdx\n" "_SET edx, ecx\n" "sar edx, 3\n"
"and ecx, 7\n" "mov al, 1\n" "shl al, cl\n"
"pop rdx\n" "or [rbp+rdx], al\n" "pop rcx\n" "_INC ecx\n"
"@o8bp_a2:\n" "add rsi, 8\n" "jmp @lde_loop\n"

"@o8bp_try00_sib:\n"
"_SET edx, [rsi+3]\n"
"cmp dl, 0x40\n" "jl @o8bp00sib_norex\n"
"cmp dl, 0x4f\n" "jg @o8bp00sib_norex\n"
"_SET edx, [rsi+4]\n" "cmp dl, 0x81\n" "jne @o_8b\n"
"_SET edx, [rsi+5]\n" "and dl, 0xf8\n" "cmp dl, 0xe0\n" "jne @o_8b\n"
"_SET edx, [rsi+6]\n" "cmp dl, 0xff\n" "jne @o_8b\n"
"_SET edx, [rsi+7]\n" "cmp dl, 0x0\n"  "jne @o_8b\n"
"_SET edx, [rsi+8]\n" "cmp dl, 0x0\n"  "jne @o_8b\n"
"_SET edx, [rsi+9]\n" "cmp dl, 0x0\n"  "jne @o_8b\n"
"cmp ecx, 128\n" "jge @o8bp_a5\n"
"push rcx\n" "push rdx\n" "_SET edx, ecx\n" "sar edx, 3\n"
"and ecx, 7\n" "mov al, 1\n" "shl al, cl\n"
"pop rdx\n" "or [rbp+rdx], al\n" "pop rcx\n" "_INC ecx\n"
"@o8bp_a5:\n" "add rsi, 10\n" "jmp @lde_loop\n"

"@o8bp00sib_norex:\n"
"cmp dl, 0x81\n" "jne @o_8b\n"
"_SET edx, [rsi+4]\n" "and dl, 0xf8\n" "cmp dl, 0xe0\n" "jne @o_8b\n"
"_SET edx, [rsi+5]\n" "cmp dl, 0xff\n" "jne @o_8b\n"
"_SET edx, [rsi+6]\n" "cmp dl, 0x0\n"  "jne @o_8b\n"
"_SET edx, [rsi+7]\n" "cmp dl, 0x0\n"  "jne @o_8b\n"
"_SET edx, [rsi+8]\n" "cmp dl, 0x0\n"  "jne @o_8b\n"
"cmp ecx, 128\n" "jge @o8bp_a6\n"
"push rcx\n" "push rdx\n" "_SET edx, ecx\n" "sar edx, 3\n"
"and ecx, 7\n" "mov al, 1\n" "shl al, cl\n"
"pop rdx\n" "or [rbp+rdx], al\n" "pop rcx\n" "_INC ecx\n"
"@o8bp_a6:\n" "add rsi, 9\n" "jmp @lde_loop\n"

/* ── mod=01 : 8B fait 3 octets (opcode+modrm+disp8, pas de disp32) ── */
"@o8bp_try01:\n"
"cmp dl, 4\n" "je @o8bp_try00_sib\n"
"_SET edx, [rsi+3]\n"
"cmp dl, 0x40\n" "jl @o8bp01_norex\n"
"cmp dl, 0x4f\n" "jg @o8bp01_norex\n"
"_SET edx, [rsi+4]\n" "cmp dl, 0x81\n" "jne @o_8b\n"
"_SET edx, [rsi+5]\n" "and dl, 0xf8\n" "cmp dl, 0xe0\n" "jne @o_8b\n"
"_SET edx, [rsi+6]\n" "cmp dl, 0xff\n" "jne @o_8b\n"
"_SET edx, [rsi+7]\n" "cmp dl, 0x0\n"  "jne @o_8b\n"
"_SET edx, [rsi+8]\n" "cmp dl, 0x0\n"  "jne @o_8b\n"
"_SET edx, [rsi+9]\n" "cmp dl, 0x0\n"  "jne @o_8b\n"
"cmp ecx, 128\n" "jge @o8bp_a3\n"
"push rcx\n" "push rdx\n" "_SET edx, ecx\n" "sar edx, 3\n"
"and ecx, 7\n" "mov al, 1\n" "shl al, cl\n"
"pop rdx\n" "or [rbp+rdx], al\n" "pop rcx\n" "_INC ecx\n"
"@o8bp_a3:\n" "add rsi, 10\n" "jmp @lde_loop\n"

"@o8bp01_norex:\n"
"cmp dl, 0x81\n" "jne @o_8b\n"
"_SET edx, [rsi+4]\n" "and dl, 0xf8\n" "cmp dl, 0xe0\n" "jne @o_8b\n"
"_SET edx, [rsi+5]\n" "cmp dl, 0xff\n" "jne @o_8b\n"
"_SET edx, [rsi+6]\n" "cmp dl, 0x0\n"  "jne @o_8b\n"
"_SET edx, [rsi+7]\n" "cmp dl, 0x0\n"  "jne @o_8b\n"
"_SET edx, [rsi+8]\n" "cmp dl, 0x0\n"  "jne @o_8b\n"
"cmp ecx, 128\n" "jge @o8bp_a4\n"
"push rcx\n" "push rdx\n" "_SET edx, ecx\n" "sar edx, 3\n"
"and ecx, 7\n" "mov al, 1\n" "shl al, cl\n"
"pop rdx\n" "or [rbp+rdx], al\n" "pop rcx\n" "_INC ecx\n"
"@o8bp_a4:\n" "add rsi, 9\n" "jmp @lde_loop\n"

	/* ══════════ 0x8B /r : MOV r32/64, r/m → bit=1 (mod00/01, +SIB) ══════════ */
	"@o_8b:\n"
	"cmp al, 0x8b\n" "jne @o_8d\n"
	"_SET eax, [rsi+1]\n"
	"_SET edx, eax\n" "and edx, 0xc0\n" "and eax, 0x7\n"
	"cmp edx, 0x0\n" "je @o8b_m00\n"
	"cmp edx, 0x40\n" "je @o8b_m01\n"
	"jmp @lde_fallback\n"

	"@o8b_m00:\n"
	"cmp ecx, 128\n" "jge @adv_8b00\n"
	"push rax\n"
	"push rcx\n" "_SET edx, ecx\n" "sar edx, 3\n"
	"and ecx, 7\n" "mov al, 1\n" "shl al, cl\n"
	"pop rcx\n" "or [rbp+rdx], al\n" "_INC ecx\n"
	"pop rax\n"
	"@adv_8b00:\n"
	"cmp eax, 4\n" "je @adv_8b00_sib\n"
	"add rsi, 2\n" "jmp @lde_loop\n"
	"@adv_8b00_sib:\n" "add rsi, 3\n" "jmp @lde_loop\n"

	"@o8b_m01:\n"
	"cmp ecx, 128\n" "jge @adv_8b01\n"
	"push rax\n"
	"push rcx\n" "_SET edx, ecx\n" "sar edx, 3\n"
	"and ecx, 7\n" "mov al, 1\n" "shl al, cl\n"
	"pop rcx\n" "or [rbp+rdx], al\n" "_INC ecx\n"
	"pop rax\n"
	"@adv_8b01:\n"
	"cmp eax, 4\n" "je @adv_8b01_sib\n"
	"add rsi, 3\n" "jmp @lde_loop\n"
	"@adv_8b01_sib:\n" "add rsi, 4\n" "jmp @lde_loop\n"

	/* ══════════ 0x8D /r : LEA reg,[reg+0] mod01 (bit0) / LEA abs mod00+SIB=0x25 (bit0) ══════════ */
	"@o_8d:\n"
	"cmp al, 0x8d\n" "jne @o_0f\n"
	"_SET eax, [rsi+1]\n"
	"_SET edx, eax\n" "and edx, 0xc0\n" "and eax, 0x7\n"
	"cmp edx, 0x40\n" "je @o8d_m01\n"
	"cmp edx, 0x0\n"  "je @o8d_m00\n"
	"jmp @lde_fallback\n"

	"@o8d_m00:\n"                                  /* MODIFIÉ : dispatch SIB vs RIP-relative */
	"cmp eax, 4\n" "je @o8d_absSIB\n"
	"cmp eax, 5\n" "je @o8d_ripRel\n"
	"jmp @lde_fallback\n"

	"@o8d_absSIB:\n"                               /* LEA absolue via SIB : mod00 rm=100 SIB=0x25 disp32 */
	"_SET eax, [rsi+2]\n" "cmp al, 0x25\n" "jne @lde_fallback\n"
	"cmp ecx, 128\n" "jge @adv_8dabs\n"
	"_INC ecx\n"
	"@adv_8dabs:\n" "add rsi, 7\n" "jmp @lde_loop\n"

	"@o8d_ripRel:\n"                               /* NOUVEAU : LEA RIP-relative, mod00 rm=101
													** aucun bit — saute tout le bloc d'un coup,
													** sans jamais réinterpréter le disp32 octet par octet */
	"add rsi, 6\n" "jmp @lde_loop\n"

	"@o8d_m01:\n"                                  /* INCHANGÉ : LEA reg,[reg+0] : mod01 disp8=0 */
	"cmp ecx, 128\n" "jge @adv_8d01\n"
	"_INC ecx\n"
	"@adv_8d01:\n"
	"cmp eax, 4\n" "je @adv_8d01_sib\n"
	"add rsi, 3\n" "jmp @lde_loop\n"
	"@adv_8d01_sib:\n" "add rsi, 4\n" "jmp @lde_loop\n"

	/* ══════════ 0x0F 0xB6 /r : MOVZX → bit=1 (reg-reg mod11) / bit=0 (mem mod00/01) ══════════ */
	"@o_0f:\n"
	"cmp al, 0x0f\n" "jne @o_b8\n"
	"_SET eax, [rsi+1]\n" "cmp al, 0xb6\n" "jne @lde_fallback\n"
	"_SET eax, [rsi+2]\n"
	"_SET edx, eax\n" "and edx, 0xc0\n" "and eax, 0x7\n"
	"cmp dl, 0xc0\n" "je @o0f_reg\n"
	"cmp edx, 0x0\n"  "je @o0f_m00\n"
	"cmp edx, 0x40\n" "je @o0f_m01\n"
	"jmp @lde_fallback\n"

	"@o0f_reg:\n"                                  /* MOVZX r32,r8 reg-reg → bit=1 (NOUVEAU) */
	"cmp ecx, 128\n" "jge @adv_0freg\n"
	"push rcx\n" "_SET edx, ecx\n" "sar edx, 3\n"
	"and ecx, 7\n" "mov al, 1\n" "shl al, cl\n"
	"pop rcx\n" "or [rbp+rdx], al\n" "_INC ecx\n"
	"@adv_0freg:\n" "add rsi, 3\n" "jmp @lde_loop\n"

	"@o0f_m00:\n"
	"cmp ecx, 128\n" "jge @adv_0f00\n"
	"_INC ecx\n"
	"@adv_0f00:\n"
	"cmp eax, 4\n" "je @adv_0f00_sib\n"
	"add rsi, 3\n" "jmp @lde_loop\n"
	"@adv_0f00_sib:\n" "add rsi, 4\n" "jmp @lde_loop\n"

	"@o0f_m01:\n"
	"cmp ecx, 128\n" "jge @adv_0f01\n"
	"_INC ecx\n"
	"@adv_0f01:\n"
	"cmp eax, 4\n" "je @adv_0f01_sib\n"
	"add rsi, 4\n" "jmp @lde_loop\n"
	"@adv_0f01_sib:\n" "add rsi, 5\n" "jmp @lde_loop\n"

	/* ══════════ 0xB8-0xBF : MOV r32,imm32 → bit=1 ══════════ */
	"@o_b8:\n"
	"cmp al, 0xb8\n" "jl @o_fe\n"
	"cmp al, 0xbf\n" "jg @o_fe\n"
	"_SET edx, [rsi-1]\n"                 /* octet precedent = potentiel REX */
	"cmp dl, 0x48\n" "jl @o_b8_32\n"
	"cmp dl, 0x4f\n" "jg @o_b8_32\n"
	"and edx, 0x08\n" "cmp edx, 0x08\n" "jne @o_b8_32\n"

	"@o_b8_64:\n"                          /* REX.W present -> imm64, 8 octets */
	"cmp ecx, 128\n" "jge @adv9_b8\n"
	"push rcx\n" "_SET edx, ecx\n" "sar edx, 3\n"
	"and ecx, 7\n" "mov al, 1\n" "shl al, cl\n"
	"pop rcx\n" "or [rbp+rdx], al\n" "_INC ecx\n"
	"@adv9_b8:\n" "add rsi, 9\n" "jmp @lde_loop\n"

	"@o_b8_32:\n"                          /* pas de REX.W -> imm32, 4 octets */
	"cmp ecx, 128\n" "jge @adv5_b8\n"
	"push rcx\n" "_SET edx, ecx\n" "sar edx, 3\n"
	"and ecx, 7\n" "mov al, 1\n" "shl al, cl\n"
	"pop rcx\n" "or [rbp+rdx], al\n" "_INC ecx\n"
	"@adv5_b8:\n" "add rsi, 5\n" "jmp @lde_loop\n"

	/* ══════════ 0xFE/0xFF /0 (INC, bit1) ou /1 (DEC, bit1) ══════════ */
	"@o_fe:\n"
	"cmp al, 0xfe\n" "je @fe_ff_body\n"
	"cmp al, 0xff\n" "jne @lde_fallback\n"
	"@fe_ff_body:\n"
	"_SET eax, [rsi+1]\n" "and eax, 0xf8\n"
	"cmp eax, 0xc0\n" "je @o_inc\n"
	"cmp eax, 0xc8\n" "je @o_dec\n"
	"jmp @lde_fallback\n"

	"@o_inc:\n"
	"cmp ecx, 128\n" "jge @adv2_inc\n"
	"push rcx\n" "_SET edx, ecx\n" "sar edx, 3\n"
	"and ecx, 7\n" "mov al, 1\n" "shl al, cl\n"
	"pop rcx\n" "or [rbp+rdx], al\n" "_INC ecx\n"
	"@adv2_inc:\n" "add rsi, 2\n" "jmp @lde_loop\n"

	"@o_dec:\n"
	"cmp ecx, 128\n" "jge @adv2_dec\n"
	"push rcx\n" "_SET edx, ecx\n" "sar edx, 3\n"
	"and ecx, 7\n" "mov al, 1\n" "shl al, cl\n"
	"pop rcx\n" "or [rbp+rdx], al\n" "_INC ecx\n"
	"@adv2_dec:\n" "add rsi, 2\n" "jmp @lde_loop\n"

	/* ══════════ fallback : rien reconnu, avance d'1 octet ══════════ */
	"@lde_fallback:\n" "add rsi, 1\n" "jmp @lde_loop\n";

static const char STUB_LDE_DONE[] =
	"@lde_done:\n"
	"jmp @after_lde\n";

static const char STUB_WRITE_WOODY[] =
	/////////////////////////////////// write(1, MSG, 14)
	"@do_write:\n"
	"_SET eax, 1\n" //"mov eax, 1\n"
	"_SET edi, 1\n" //"mov edi, 1\n"
	//"mov eax, 1\n"
	//"mov edi, 1\n"
	"lea rsi, [msg]\n"
	"_SET edx, 14\n"
	"syscall\n"
	"jmp @run_lde\n";

static const char STUB_AFTER_LDE[] =
	"@after_lde:\n";

static const char STUB_WRITE_KEY[] =
	/////////////////////////////////// write(1, MSG, 14)
	"@do_write:\n"
	"_SET eax, 1\n" //"mov eax, 1\n"
	"_SET edi, 1\n" //"mov edi, 1\n"
	//"lea rsi, [rsp]\n"
	"_SET rsi, rbp\n"
	"_SET edx, 16\n"
	"syscall\n";

static const char STUB_DEBUG_HEXBUF_SETUP[] =
"sub rsp, 40\n"
"_SET r8, rsp\n"
"add r8, 40\n"
"_SET rsi, rsp\n"
"_SET r9, rsp\n"
"_ZERO r10\n"
"_ZERO r11\n"
"_SET eax, 16\n"
"jmp .loop_start\n"
".loop:\n"
"_SET bl, [r8+r10]\n"
"_SET ecx, ebx\n"
"shr ecx, 4\n"
"and ecx, 15\n"
"cmp ecx, 9\n"
"jbe .digit_high\n"
"add ecx, 55\n"
"jmp .store_high\n"
".digit_high:\n"
"add ecx, 48\n"
".store_high:\n"
"mov [r9+r11], cl\n"
"_INC r11\n"
"_SET ecx, ebx\n"
"and ecx, 15\n"
"cmp ecx, 9\n"
"jbe .digit_low\n"
"add ecx, 55\n"
"jmp .store_low\n"
".digit_low:\n"
"add ecx, 48\n"
".store_low:\n"
"mov [r9+r11], cl\n"
"_INC r11\n"
"_INC r10\n"
"_DEC eax\n"
".loop_start:\n"
"test eax, eax\n"
"jnz .loop\n";

static const char STUB_DEBUG_HEXBUF_WRITE[] =
"_SET rax, 1\n" "_SET rdi, 1\n" "_SET rsi, r9\n" "_SET rdx, 32\n"
"syscall\n"
"mov cl, 10\n"
"mov [r9+32], cl\n"
"_SET rax, 1\n" "_SET rdi, 1\n"
"_SET rsi, r9\n" "add rsi, 32\n"
"_SET rdx, 1\n"
"syscall\n";

static const char STUB_DEBUG_HEXBUF_TEARDOWN[] =
"add rsp, 40\n";

static const char STUB_PIE_BASE_CALC[] =
"pie_base_marker:\n"
"lea rax, [pie_base_marker]\n"
"mov rdx, pie_base_marker\n"
"sub rax, rdx\n"
"sub rax, stub_load_vaddr\n"
"_SET r15, rax\n";

static const char STUB_MPROTECT[] =
"_SET rdi, rax\n"
"add rdi, prot_addr\n"
"mov esi, prot_size\n"
"_SET edx, 7\n"
"_SET eax, 10\n"
"syscall\n"
"cmp rax, 0\n"
"jge mprotect_ok\n"
"_SET rdi, rax\n"
"neg rdi\n"
"_SET rax, 60\n"
"_SET rdi, 1\n"
"syscall\n"
"mprotect_ok:\n";

static const char STUB_KSA[] =
"sub rsp, 256\n"
"_SET rsi, rbp\n"
"_ZERO ecx\n"
"@ksa_init:\n"
"mov [rsp+rcx], cl\n"
"_INC cl\n"
"jnz @ksa_init\n"
"_ZERO ecx\n"
"_ZERO edx\n"
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
"jnz @ksa_loop\n";

static const char STUB_PRGA[] =
"_SET rdi, r15\n"
"add rdi, text_vaddr\n"
"_ZERO ecx\n"
"_ZERO edx\n"
"_ZERO ebx\n"
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
"jl @prga_loop\n";

static const char STUB_FREE[] =
	"add rsp, 256\n"     // libère le S-box
	"add rsp, 16\n"      // ← DÉPLACÉ ICI : libère le buffer clé, seulement maintenant qu'on n'en a plus besoin
	"pop rdx\n"
	"pop rbp\n";

static const char STUB_FOOTER[] =
	"scan_end:\n"
	"jmp @oep\n";

static const char STUB_DATA_EVAMSG[] =
	// donnees embarquees apres le code
    "evasion_msg:\n"
    ".evasion_msg\n";

static const char STUB_DATA_WOODYMSG[] =
	"msg:\n"
	".msg\n";

static const char STUB_DATA_CLEARKEY[] =
	"key:\n"
	".key\n";

#endif