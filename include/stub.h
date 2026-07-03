#ifndef STUB_H
# define STUB_H

static const char STUB_SRC[] =
	// preserves _dl_fini que le kernel passe dans rdx
	"scan_start:\n"
	"push rdx\n"
	"push rbp\n"

	"_ZERO rax\n"
	"_ZERO rax\n"
	"_ZERO rax\n"
	"_ZERO rax\n"
	"_ZERO rax\n"
	"_ZERO rax\n"
	"_ZERO rax\n"
	"_ZERO rax\n"
	"_ZERO rax\n"
	"_ZERO rax\n"
	"_ZERO rax\n"
		"_ZERO rax\n"
	"_ZERO rax\n"
	"_ZERO rax\n"
	"_ZERO rax\n"
	"_ZERO rax\n"
	"_ZERO rax\n"
	"_ZERO rax\n"
	"_ZERO rax\n"
	"_ZERO rax\n"
	"_ZERO rax\n"
	"_ZERO rax\n"
		"_ZERO rax\n"
	"_ZERO rax\n"
	"_ZERO rax\n"
	"_ZERO rax\n"
	"_ZERO rax\n"
	"_ZERO rax\n"
	"_ZERO rax\n"
	"_ZERO rax\n"
	"_ZERO rax\n"
	"_ZERO rax\n"
	"_ZERO rax\n"
		"_ZERO rax\n"
	"_ZERO rax\n"
	"_ZERO rax\n"
	"_ZERO rax\n"
	"_ZERO rax\n"
	"_ZERO rax\n"
	"_ZERO rax\n"
	"_ZERO rax\n"
	"_ZERO rax\n"
	"_ZERO rax\n"
	"_ZERO rax\n"
		"_ZERO rax\n"
	"_ZERO rax\n"
	"_ZERO rax\n"
	"_ZERO rax\n"
	"_ZERO rax\n"
	"_ZERO rax\n"
	"_ZERO rax\n"
	"_ZERO rax\n"
	"_ZERO rax\n"
	"_ZERO rax\n"
	"_ZERO rax\n"
		"_ZERO rax\n"
	"_ZERO rax\n"
	"_ZERO rax\n"
	"_ZERO rax\n"
	"_ZERO rax\n"
	"_ZERO rax\n"
	"_ZERO rax\n"
	"_ZERO rax\n"
	"_ZERO rax\n"
	"_ZERO rax\n"
	"_ZERO rax\n"
		"_ZERO rax\n"
	"_ZERO rax\n"
	"_ZERO rax\n"
	"_ZERO rax\n"
	"_ZERO rax\n"
	"_ZERO rax\n"
	"_ZERO rax\n"
	"_ZERO rax\n"
	"_ZERO rax\n"
	"_ZERO rax\n"
	"_ZERO rax\n"
		"_ZERO rax\n"
	"_ZERO rax\n"
	"_ZERO rax\n"
	"_ZERO rax\n"
	"_ZERO rax\n"
	"_ZERO rax\n"
	"_ZERO rax\n"
	"_ZERO rax\n"
	"_ZERO rax\n"
	"_ZERO rax\n"
	"_ZERO rax\n"
		"_ZERO rax\n"
	"_ZERO rax\n"
	"_ZERO rax\n"
	"_ZERO rax\n"
	"_ZERO rax\n"
	"_ZERO rax\n"
	"_ZERO rax\n"
	"_ZERO rax\n"
	"_ZERO rax\n"
	"_ZERO rax\n"
	"_ZERO rax\n"
		"_ZERO rax\n"
	"_ZERO rax\n"
	"_ZERO rax\n"
	"_ZERO rax\n"
	"_ZERO rax\n"
	"_ZERO rax\n"
	"_ZERO rax\n"
	"_ZERO rax\n"
	"_ZERO rax\n"
	"_ZERO rax\n"
	"_ZERO rax\n"
		"_ZERO rax\n"
	"_ZERO rax\n"
	"_ZERO rax\n"
	"_ZERO rax\n"
	"_ZERO rax\n"
	"_ZERO rax\n"
	"_ZERO rax\n"
	"_ZERO rax\n"
	"_ZERO rax\n"
	"_ZERO rax\n"
	"_ZERO rax\n"
		"_ZERO rax\n"
	"_ZERO rax\n"
	"_ZERO rax\n"
	"_ZERO rax\n"
	"_ZERO rax\n"
	"_ZERO rax\n"
	"_ZERO rax\n"
	"_ZERO rax\n"
	"_ZERO rax\n"
	"_ZERO rax\n"
	"_ZERO rax\n"
		"_ZERO rax\n"
	"_ZERO rax\n"
	"_ZERO rax\n"
	"_ZERO rax\n"
	"_ZERO rax\n"
	"_ZERO rax\n"
	"_ZERO rax\n"
	"_ZERO rax\n"
	"_ZERO rax\n"
	"_ZERO rax\n"
	"_ZERO rax\n"

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
    "je debugger_detected\n"

    "jmp debugger_not_detected\n"

    "debugger_detected:\n"
    "_SET eax, 1\n"
	"_SET edi, 1\n"
	"lea rsi, [evasion_msg]\n"
	"mov edx, 9\n"
	"syscall\n"
    "_SET rax, 60\n" //      ; sys_exit (numéro du syscall)
    "_SET rdi, 0\n" //        ; code de sortie (0 = succès)
    "syscall\n"
    ////////////////////////////////////////////////////////////////////

    "debugger_not_detected:\n"
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
	"jmp @after_lde\n" // PATCH BATMAN
	// ── lecture du payload ───────────────────────────────────────
    /* ── setup ───────────────────────────────────────────── */
    "_ZERO ecx\n"          /* bit_index = 0 */
    "lea rsi, [scan_start]\n"
    "lea rbx, [scan_end]\n"

    /* ── boucle principale ───────────────────────────────── */
"@lde_loop:\n"
"cmp rsi, rbx\n"
"jb @lde_continue\n"
"jmp @lde_done\n"
"@lde_continue:\n"
"_SET eax, [rsi]\n"

/* 0x24 */
"cmp eax, 0x24\n" "jne @check_80\n"
"_SET eax, [rsi+1]\n" "cmp eax, 0x0\n" "jne @adv2_24\n"
"cmp ecx, 128\n" "jge @adv2_24\n"
"push rcx\n" "mov edx, ecx\n" "sar edx, 3\n"
"and ecx, 7\n" "mov al, 1\n" "shl al, cl\n"
"pop rcx\n" "or [rbp+rdx], al\n" "_INC ecx\n"
"@adv2_24:\n" "add rsi, 2\n" "jmp @lde_loop\n"

/* 0x80 */
"@check_80:\n"
"cmp eax, 0x80\n" "jne @check_31\n"
"_SET eax, [rsi+1]\n" "_SET edx, eax\n" "and edx, 0x38\n"
"cmp edx, 0x20\n" "jne @check_80_add\n"
"_SET eax, [rsi+2]\n" "cmp eax, 0x0\n" "jne @adv3_80\n"
"cmp ecx, 128\n" "jge @adv3_80\n"
"push rcx\n" "_SET edx, ecx\n" "sar edx, 3\n"
"and ecx, 7\n" "_SET al, 1\n" "shl al, cl\n"
"pop rcx\n" "or [rbp+rdx], al\n" "_INC ecx\n"
"@adv3_80:\n" "add rsi, 3\n" "jmp @lde_loop\n"

"@check_80_add:\n"
"cmp edx, 0x0\n" "jne @check_31\n"
"_SET eax, [rsi+2]\n" "cmp eax, 0x1\n" "jne @check_31\n"
"_INC ecx\n" "add rsi, 3\n" "jmp @lde_loop\n"

/* 0x31 */
"@check_31:\n"
"cmp eax, 0x31\n" "jne @check_b8\n"
"_SET eax, [rsi+1]\n"
"mov edx, eax\n" "and eax, 0x18\n" "sar eax, 3\n" "and edx, 0x3\n"
"cmp eax, edx\n" "jne @adv2_31\n"
"cmp ecx, 128\n" "jge @adv2_31\n"
"_INC ecx\n"
"@adv2_31:\n" "add rsi, 2\n" "jmp @lde_loop\n"

/* 0xB8-0xBF */
"@check_b8:\n"
"cmp eax, 0xb8\n" "jl @check_lea\n"
"cmp eax, 0xbf\n" "jg @check_lea\n"
"cmp ecx, 128\n" "jge @adv5_b8\n"
"push rcx\n" "mov edx, ecx\n" "sar edx, 3\n"
"and ecx, 7\n" "mov al, 1\n" "shl al, cl\n"
"pop rcx\n" "or [rbp+rdx], al\n" "_INC ecx\n"
"@adv5_b8:\n" "add rsi, 5\n" "jmp @lde_loop\n"

/* 0x48 0x8D 0x25 : LEA abs → bit=0 */
"@check_lea:\n"
"cmp eax, 0x48\n" "jne @check_89\n"
"_SET eax, [rsi+1]\n" "cmp eax, 0x8d\n" "jne @check_48_89\n"
"_SET eax, [rsi+2]\n" "and eax, 0x7\n" "cmp eax, 0x4\n" "jne @check_48_8d\n"
"_SET eax, [rsi+3]\n" "cmp eax, 0x25\n" "jne @check_48_8d\n"
"cmp ecx, 128\n" "jge @adv8_lea\n"
"_INC ecx\n"
"@adv8_lea:\n" "add rsi, 8\n" "jmp @lde_loop\n"

/* 0x89 : MOV r32, r32 → bit=1 */
"@check_89:\n"
"cmp eax, 0x89\n" "jne @check_8b\n"
"cmp ecx, 128\n" "jge @adv2_89\n"
"push rcx\n" "mov edx, ecx\n" "sar edx, 3\n"
"and ecx, 7\n" "mov al, 1\n" "shl al, cl\n"
"pop rcx\n" "or [rbp+rdx], al\n" "_INC ecx\n"
"@adv2_89:\n" "add rsi, 2\n" "jmp @lde_loop\n"

/* 0x8B : MOV r32, r/m → bit=1 */
"@check_8b:\n"
"cmp eax, 0x8b\n" "jne @check_0f_b6\n"
"cmp ecx, 128\n" "jge @advance_8b\n"
"push rcx\n" "mov edx, ecx\n" "sar edx, 3\n"
"and ecx, 7\n" "mov al, 1\n" "shl al, cl\n"
"pop rcx\n" "or [rbp+rdx], al\n" "_INC ecx\n"
"jmp @advance_8b\n"
"@advance_8b:\n"
"_SET eax, [rsi+1]\n"
"mov edx, eax\n" "and edx, 0xc0\n" "sar edx, 6\n" "and eax, 7\n"
"cmp edx, 0\n" "jne @mod01_8b\n"
"cmp eax, 4\n" "je @sib_8b\n"
"add rsi, 2\n" "jmp @lde_loop\n"
"@sib_8b:\n" "add rsi, 3\n" "jmp @lde_loop\n"
"@mod01_8b:\n"
"cmp edx, 1\n" "jne @lde_fallback\n"
"cmp eax, 4\n" "je @sib_disp8_8b\n"
"add rsi, 3\n" "jmp @lde_loop\n"
"@sib_disp8_8b:\n" "add rsi, 4\n" "jmp @lde_loop\n"

/* 0x0F 0xB6 : MOVZX r32, r/m8 → bit=0 */
"@check_0f_b6:\n"
"cmp eax, 0x0f\n" "jne @check_48_89\n"
"_SET eax, [rsi+1]\n" "cmp eax, 0xb6\n" "jne @check_48_89\n"
"cmp ecx, 128\n" "jge @sz_0fb6\n"
"_INC ecx\n"
"@sz_0fb6:\n"
"_SET eax, [rsi+2]\n"
"mov edx, eax\n" "and edx, 0xc0\n" "sar edx, 6\n" "and eax, 7\n"
"cmp edx, 0\n" "jne @mod01_0fb6\n"
"cmp eax, 4\n" "je @sib_0fb6\n"
"add rsi, 3\n" "jmp @lde_loop\n"
"@sib_0fb6:\n" "add rsi, 4\n" "jmp @lde_loop\n"
"@mod01_0fb6:\n"
	"cmp edx, 1\n" "jne @lde_fallback\n"
	"cmp eax, 4\n" "je @sib_disp8_0fb6\n" // THIS JUMP BUG
	"add rsi, 4\n" "jmp @lde_loop\n"
	"@sib_disp8_0fb6:\n" "add rsi, 5\n" "jmp @lde_loop\n"
/*
"cmp edx, 1\n" "jne @debug_jmp\n"
"cmp eax, 4\n" "je @sib_disp8_0fb6\n" // THIS JUMP BUG
"add rsi, 4\n" "jmp @lde_loop\n"
"@sib_disp8_0fb6:\n" "add rsi, 5\n" "jmp @lde_loop\n"
"@debug_jmp:\n"
"jmp @lde_fallback\n"
*/


/* 48 89 : MOV r64, r64 → bit=1 */
"@check_48_89:\n"
"cmp eax, 0x48\n" "jne @check_inc_fe\n"
"_SET eax, [rsi+1]\n"
"cmp eax, 0x89\n" "jne @check_48_8d\n"
"cmp ecx, 128\n" "jge @adv3_48_89\n"
"push rcx\n" "mov edx, ecx\n" "sar edx, 3\n"
"and ecx, 7\n" "mov al, 1\n" "shl al, cl\n"
"pop rcx\n" "or [rbp+rdx], al\n" "_INC ecx\n"
"@adv3_48_89:\n" "add rsi, 3\n" "jmp @lde_loop\n"

/* 48 8D mod=01 : LEA r64,[reg+0] → bit=0 */
"@check_48_8d:\n"
"cmp eax, 0x8d\n" "jne @check_81_add\n"
"_SET eax, [rsi+2]\n" "and eax, 0xc0\n" "cmp eax, 0x40\n"
"jne @check_81_add\n"
"cmp ecx, 128\n" "jge @adv4_48_8d\n"
"_INC ecx\n"
"@adv4_48_8d:\n"
"_SET eax, [rsi+2]\n" "and eax, 0x7\n" "cmp eax, 0x4\n"
"je @adv5_48_8d\n"
"add rsi, 4\n" "jmp @lde_loop\n"
"@adv5_48_8d:\n" "add rsi, 5\n" "jmp @lde_loop\n"

"@check_81_add:\n"
"cmp eax, 0x81\n" "jne @check_inc_fe\n"
"_SET eax, [rsi+1]\n" "and eax, 0xf8\n"
"cmp eax, 0xc0\n" "jne @check_inc_fe\n"
"_SET eax, [rsi+2]\n" "cmp eax, 0x1\n" "jne @check_inc_fe\n"
"_SET eax, [rsi+3]\n" "cmp eax, 0x0\n" "jne @check_inc_fe\n"
"_SET eax, [rsi+4]\n" "cmp eax, 0x0\n" "jne @check_inc_fe\n"
"_SET eax, [rsi+5]\n" "cmp eax, 0x0\n" "jne @check_inc_fe\n"
"_INC ecx\n"
"add rsi, 6\n" "jmp @lde_loop\n"

/* 0xFE/0xFF INC → bit=1 */
"@check_inc_fe:\n"
"_SET eax, [rsi]\n"
"cmp eax, 0xfe\n" "je @check_inc_modrm\n"
"cmp eax, 0xff\n" "jne @check_cmp83\n"
"@check_inc_modrm:\n"
"_SET eax, [rsi+1]\n" "and eax, 0xf8\n" "cmp eax, 0xc0\n"
"jne @check_cmp83\n"
"cmp ecx, 128\n" "jge @adv2_inc\n"
"push rcx\n" "mov edx, ecx\n" "sar edx, 3\n"
"and ecx, 7\n" "mov al, 1\n" "shl al, cl\n"
"pop rcx\n" "or [rbp+rdx], al\n" "_INC ecx\n"
"@adv2_inc:\n" "add rsi, 2\n" "jmp @lde_loop\n"

/* 0x83 /7 : CMP → INC bit=0 */
"@check_cmp83:\n"
"_SET eax, [rsi]\n" "cmp eax, 0x83\n" "jne @check_dec_ff\n"
"_SET eax, [rsi+1]\n" "and eax, 0xf8\n" "cmp eax, 0xf8\n"
"jne @check_dec_ff\n"
"cmp ecx, 128\n" "jge @adv3_cmp\n"
"_INC ecx\n"
"@adv3_cmp:\n" "add rsi, 3\n" "jmp @lde_loop\n"

/* 0xFE/0xFF DEC → bit=1 */
"@check_dec_ff:\n"
"_SET eax, [rsi]\n"
"cmp eax, 0xfe\n" "je @check_dec_modrm\n"
"cmp eax, 0xff\n" "jne @check_sub83\n"
"@check_dec_modrm:\n"
"_SET eax, [rsi+1]\n" "and eax, 0xf8\n" "cmp eax, 0xc8\n"
"jne @check_sub83\n"
"cmp ecx, 128\n" "jge @adv2_dec\n"
"push rcx\n" "mov edx, ecx\n" "sar edx, 3\n"
"and ecx, 7\n" "mov al, 1\n" "shl al, cl\n"
"pop rcx\n" "or [rbp+rdx], al\n" "_INC ecx\n"
"@adv2_dec:\n" "add rsi, 2\n" "jmp @lde_loop\n"

/* 0x83 /5 : SUB r32,1 → DEC bit=0 */
"@check_sub83:\n"
"_SET eax, [rsi]\n" "cmp eax, 0x83\n" "jne @lde_fallback\n"
"_SET eax, [rsi+1]\n" "and eax, 0xf8\n" "cmp eax, 0xe8\n"
"jne @lde_fallback\n"
"_SET eax, [rsi+2]\n" "cmp eax, 0x1\n" "jne @lde_fallback\n"
"cmp ecx, 128\n" "jge @adv3_sub\n"
"_INC ecx\n"
"@adv3_sub:\n" "add rsi, 3\n" "jmp @lde_loop\n"

/* fallback */
"@lde_fallback:\n" "add rsi, 1\n" "jmp @lde_loop\n"
"@lde_done:\n" "jmp @after_lde\n"

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

	/////////////////////////////////// AFFICHE LA CLE (DEBUG)

	"sub rsp, 32\n" //; allouer un buffer de 32 octets sur la pile
	"mov r8, rsp\n"         //; r8 = pointeur vers les données
	"add r8, 32\n"
	"mov rsi, rsp\n"
    "mov r9, rsp\n" //; r9 = pointeur vers le buffer de sortie (après "0x")
    "mov r10, 0\n"           //; r10 = index pour les données (0 à 15)
    "mov r11, 0\n"           //; r11 = index pour le buffer de sortie (0 à 31)

    //; === Boucle pour traiter chaque octet (16 octets) ===
    "mov rax, 16\n"          //; r12 = compteur d'octets (16)
    "jmp .loop_start\n"

".loop:\n"
    //; === Traiter l'octet courant ===
    //"movzx rbx, byte [r8 + r10]\n" //; r13 = octet à convertir
    "mov bl, [r8+r10]\n"
	"mov rcx, rbx\n"        //; Copie de l'octet

    //; Extraire le nibble haut (4 bits de poids fort)
    "shr rcx, 4\n"
    "and rcx, 15\n" // 0x0F
    "cmp rcx, 9\n"
    "jbe .digit_high\n"
    "add rcx, 55\n"    //; Convertir en lettre (a-f)
    "jmp .store_high\n"
".digit_high:\n"
    "add rcx, 48\n"         //; Convertir en chiffre (0-9)
".store_high:\n"
    "mov [r9+r11], cl\n" //; Stocker le nibble haut
    "_INC rcx\n"              //; Incrémenter l'index du buffer

    //; Extraire le nibble bas (4 bits de poids faible)
    "mov rcx, r13\n"
    "and rcx, 15\n" // 0x0F
    "cmp rcx, 9\n"
    "jbe .digit_low\n"
    "add rcx, 55\n"    //; Convertir en lettre (a-f)
    "jmp .store_low\n"
".digit_low:\n"
    "add rcx, 48\n"         //; Convertir en chiffre (0-9)
".store_low:\n"
    "mov [r9+r11], cl\n" //; Stocker le nibble bas
    "_INC r11\n"              //; Incrémenter l'index du buffer

    //; Passer à l'octet suivant
    "_INC r10\n"
    "_DEC rax\n"              //; Décrémenter le compteur d'octets

".loop_start:\n"
    "test rax, rax\n"        //; Vérifier si r12 == 0
    "jnz .loop\n"            //; Si non, continuer la boucle

    //; === Écrire le buffer complet (34 octets : "0x" + 32 hex + '\n') ===
    "mov rax, 1\n"           //; sys_write
    "mov rdi, 1\n"           //; stdout
    "mov rsi, rsp\n"
    "mov rdx, 34\n"
    "syscall\n"

    //; === Terminer le programme ===
    "mov rax, 60\n"          //; sys_exit
    "_ZERO rdi\n"         //; code de sortie 0
    "syscall\n"

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
    "evasion_msg:\n"
    ".evasion_msg\n"
	"msg:\n"
	".msg\n"
	"key:\n"
	".key\n"
	"scan_end:\n";

#endif