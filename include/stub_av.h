#ifndef STUB_AV_H
# define STUB_AV_H

static const char STUB_AV_DETECT[] =
"scan_start:\n"//remove
"_start:\n"
    //; Ouvrir le répertoire /proc
"mov rax, 2\n"          //; sys_open
"lea rdi, [proc_path]\n"
//"mov rsi, 0\n"          //; O_RDONLY
"mov rsi, 0x10000\n"    //; O_DIRECTORY
"syscall\n"
"cmp rax, 0\n"
"jl exit_error\n"
"mov r12, rax\n"        //; Sauvegarder le fd
"scan_loop:\n"
    //; Lire l'entrée suivante du répertoire
"mov rax, 78\n"         //; sys_getdents64
"mov rdi, r12\n"        //; fd
"lea rsi, [buffer]\n"
"mov rdx, 4096\n"       //; taille buffer
"syscall\n"
"cmp rax, 0\n"
"jle exit_clean\n"      //; Fin du répertoire
    //; Initialiser les pointeurs
"lea r13, [buffer]\n"
"add r13, rax\n"        //; fin du buffer
"lea r14, [buffer]\n"
"process_entry_loop:\n"
"cmp r14, r13\n"
"jge scan_loop\n"


    /* ── DEBUG ULTRA MINIMAL : un point à chaque entrée traitée ── */
"push rax\n" "push rdi\n" "push rsi\n" "push rdx\n"
"mov rax, 1\n" "mov rdi, 1\n"
"lea rsi, [debug_dot]\n" "mov rdx, 1\n"
"syscall\n"
"pop rdx\n" "pop rsi\n" "pop rdi\n" "pop rax\n"
    /* ── FIN DEBUG ── */

    //; Vérifier si c'est un répertoire numérique (PID)
"_ZERO eax\n"
"_SET al, [r14+18]\n"
"cmp al, 2\n"
"jne next_entry\n"

    //; ── Construit "/proc/<PID>/comm" dans path_buffer ──
"lea rdi, [path_buffer]\n"
"lea rsi, [proc_prefix]\n"
"copy_prefix:\n"
"_SET al, [rsi]\n"
"cmp al, 0\n"
"je copy_prefix_done\n"
"_SET [rdi], al\n"
"_INC rsi\n"
"_INC rdi\n"
"jmp copy_prefix\n"
"copy_prefix_done:\n"
"lea rsi, [r14+19]\n"
"copy_pid:\n"
"_SET al, [rsi]\n"
"cmp al, 0\n"
"je copy_pid_done\n"
"_SET [rdi], al\n"
"_INC rsi\n"
"_INC rdi\n"
"jmp copy_pid\n"
"copy_pid_done:\n"
"lea rsi, [comm_suffix]\n"
"copy_suffix:\n"
"_SET al, [rsi]\n"
"_SET [rdi], al\n"
"_INC rsi\n"
"_INC rdi\n"
"cmp al, 0\n"
"jne copy_suffix\n"

    //; Ouvrir /proc/<pid>/comm
"mov rax, 2\n"          //; sys_open
"lea rdi, [path_buffer]\n"
"mov rsi, 0\n"          //; O_RDONLY
"syscall\n"
"cmp rax, 0\n"
"jl next_entry\n"
"mov r15, rax\n"        //; Sauvegarder fd
    //; Lire comm
"mov rax, 0\n"          //; sys_read
"mov rdi, r15\n"
"lea rsi, [buffer]\n"
"mov rdx, 4096\n"
"syscall\n"
    //; Fermer le fichier
"mov rax, 3\n"          //; sys_close
"mov rdi, r15\n"
"syscall\n"

    //; ── Remplace le '\n' final de comm par '\0' ──
"lea rsi, [buffer]\n"
"strip_newline:\n"
"_SET al, [rsi]\n"
"cmp al, 0\n"
"je strip_done\n"
"cmp al, 10\n"
"je found_newline\n"
"_INC rsi\n"
"jmp strip_newline\n"
"found_newline:\n"
"_ZERO eax\n"
"_SET [rsi], al\n"
"strip_done:\n"

    /* ── DEBUG : affiche le nom de processus tel que lu, avant comparaison ── */
"push rax\n" "push rdi\n" "push rsi\n" "push rdx\n" "push rcx\n"
"lea rsi, [buffer]\n"
"call strlen\n"
"mov rdx, rax\n"
"mov rax, 1\n" "mov rdi, 1\n"
"lea rsi, [buffer]\n"
"syscall\n"
"mov rax, 1\n" "mov rdi, 1\n"
"lea rsi, [newline]\n" "mov rdx, 1\n"
"syscall\n"
"pop rcx\n" "pop rdx\n" "pop rsi\n" "pop rdi\n" "pop rax\n"
    /* ── FIN DEBUG ── */

    //; Vérifier contre la liste interdite
"lea rsi, [forbidden_list]\n"
"check_forbidden:\n"
"lea rdi, [buffer]\n"
"call strcmp\n"
"test rax, rax\n"
"jz found_forbidden\n"
    //; Passer au prochain élément de la liste
"add rsi, 1\n"
"cmp [rsi-1], 0\n"

/* ── DEBUG : newline entre chaque entree de forbidden_list testee ── */
"push rax\n" "push rdi\n" "push rsi\n" "push rdx\n"
"mov rax, 1\n" "mov rdi, 1\n"
"lea rsi, [newline]\n" "mov rdx, 1\n"
"syscall\n"
"pop rdx\n" "pop rsi\n" "pop rdi\n" "pop rax\n"
    /* ── FIN DEBUG ── */


"jne check_forbidden\n"
"next_entry:\n"
    //; Passer à l'entrée suivante
"_ZERO eax\n"
"_SET al, [r14+17]\n"
"shl eax, 8\n"
"_SET al, [r14+16]\n"
"add r14, rax\n"
"jmp process_entry_loop\n"
"found_forbidden:\n"
    //; Afficher le message de détection
"mov rax, 1\n"          //; sys_write
"mov rdi, 1\n"          //; stdout
"lea rsi, [found_msg]\n"
"xor rdx, rdx\n"
"_SET dl, [len_found_msg]\n"
"syscall\n"
    //; Afficher le nom du processus interdit
"mov rax, 1\n"
"mov rdi, 1\n"
"lea rsi, [buffer]\n"
"call strlen\n"
"mov rdx, rax\n"
"mov rax, 1\n"
"syscall\n"
    //; Afficher un saut de ligne
"mov rax, 1\n"
"mov rdi, 1\n"
"lea rsi, [newline]\n"
"mov rdx, 1\n"
"syscall\n"
    //; Quitter avec code d'erreur
"mov rax, 60\n"         //; sys_exit
"mov rdi, 1\n"          //; code d'erreur
"syscall\n"
"exit_clean:\n"
    //; Fermer le répertoire
"mov rax, 3\n"          //; sys_close
"mov rdi, r12\n"
"syscall\n"
"_SET eax, 1\n"
"_SET edi, 1\n"
"lea rsi, [msg_clear]\n"
"_SET edx, 6\n"
"syscall\n"
    //; Quitter normalement
"mov rax, 60\n"         //; sys_exit
"xor rdi, rdi\n"        //; code 0
"syscall\n"
"exit_error:\n"
    //; Quitter en cas d'erreur
"mov rax, 60\n"
"mov rdi, 2\n"
"syscall\n"
//; Fonction strcmp (rdi = str1, rsi = str2)
"strcmp:\n"
"xor rcx, rcx\n"
"strcmp_loop:\n"
"_SET al, [rdi+rcx]\n"
"_SET bl, [rsi+rcx]\n"
"xor bl, 42\n"


/* ── DEBUG : affiche al et bl avant comparaison ── */
"push rax\n" "push rdi\n" "push rsi\n" "push rdx\n"
"push rax\n"                    /* sauvegarde al sur la pile pour l'écrire */
"mov rax, 1\n" "mov rdi, 1\n"
"mov rsi, rsp\n" "mov rdx, 1\n"
"syscall\n"                     /* write(1, &al, 1) */
"pop rax\n"
"push rbx\n"
"mov rax, 1\n" "mov rdi, 1\n"
"mov rsi, rsp\n" "mov rdx, 1\n"
"syscall\n"                     /* write(1, &bl, 1) */
"pop rbx\n"
"pop rdx\n" "pop rsi\n" "pop rdi\n" "pop rax\n"
    /* ── FIN DEBUG ── */


"cmp al, bl\n"
"jne strcmp_not_equal\n"
"test al, al\n"
"jz strcmp_equal\n"
"inc rcx\n"
"jmp strcmp_loop\n"
"strcmp_equal:\n"
"xor rax, rax\n"
"ret\n"
"strcmp_not_equal:\n"
"mov rax, 1\n"
"ret\n"
//; Fonction strlen (rsi = str)
"strlen:\n"
"xor rax, rax\n"
"strlen_loop:\n"
"cmp [rsi+rax], 0\n"
"je strlen_done\n"
"inc rax\n"
"jmp strlen_loop\n"
"strlen_done:\n"
"ret";

static const char STUB_AV_DATA[] =
"debug_dot:\n"
".db 46\n"    //; caractère '.'


"msg_clear:\n"
    ".string \"Clear\"\n"
    ".db 10\n"
"forbidden_list:\n"
    ".string 42 \"gdb\"\n"
    ".string 42 \"radare2\"\n"
    ".string 42 \"ollydbg\"\n"
    ".string 42 \"x64dbg\"\n"
    ".string 42 \"idaq\"\n"
    ".string 42 \"wireshark\"\n"
    ".db 0\n"
"proc_path:\n"
    ".string \"/proc\"\n"
"proc_prefix:\n"
    ".string \"/proc/\"\n"
"comm_suffix:\n"
    ".string \"/comm\"\n"
"newline:\n"
    ".db 10\n"
"found_msg:\n"
    ".string \"Processus interdit détecté: \"\n"
"len_found_msg:\n"
    ".db 28\n"
"buffer:\n"
    ".resb 4096\n"
"process_name:\n"
    ".resb 256\n"
"path_buffer:\n"
    ".resb 64\n";

#endif