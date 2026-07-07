#ifndef STUB_AV_H
# define STUB_AV_H

static const char STUB_AV_DETECT[] =
//"section .text\n"
//    "global _start\n"
"scan_start:\n"//remove
"_start:\n"
    //; Ouvrir le répertoire /proc
    "mov rax, 2\n"          //; sys_open
    "_SET rdi, proc_path\n"
    "mov rsi, 0\n"          //; O_RDONLY
    "syscall\n"
    "cmp rax, 0\n"
    "jl exit_error\n"
    "mov r12, rax\n"        //; Sauvegarder le fd

"scan_loop:\n"
    //; Lire l'entrée suivante du répertoire
    "mov rax, 78\n"         //; sys_getdents64
    "mov rdi, r12\n"        //; fd
    "mov rsi, buffer\n"     //; buffer
    "mov rdx, 4096\n"       //; taille buffer
    "syscall\n"
    "cmp rax, 0\n"
    "jle exit_clean\n"      //; Fin du répertoire

    //; Initialiser les pointeurs
    "mov r13, buffer\n"     //; pointeur vers les entrées
    "add r13, rax\n"        //; fin du buffer
    "mov r14, buffer\n"     //; début des entrées

"process_entry_loop:\n"
    "cmp r14, r13\n"
    "jge scan_loop\n"       //; Passer à l'entrée suivante

    //; Vérifier si c'est un répertoire numérique (PID)
    "_SET rdi, [r14 + 16]\n" //; d_type (16 octets après le début de l'entrée)
    "cmp rdi, 2\n"          //; DT_DIR
    "jne next_entry\n"

    //; Extraire le nom du processus (PID)
    "lea rsi, [r14 + 19]\n" //; offset vers le nom (après "d_name")
    "mov rdi, process_name\n"

"copy_name_loop:\n"
    "lodsb\n"
    "stosb\n"
    "test al, al\n"
    "jnz copy_name_loop\n"

    //; Ouvrir /proc/<pid>/cmdline
    "mov rax, 2\n"          //; sys_open
    "mov rdi, process_name\n"
    "mov rsi, 0\n"          //; O_RDONLY
    "syscall\n"
    "cmp rax, 0\n"
    "jl next_entry\n"
    "mov r15, rax\n"        //; Sauvegarder fd

    //; Lire cmdline
    "mov rax, 0\n"          //; sys_read
    "mov rdi, r15\n"
    "mov rsi, buffer\n"
    "mov rdx, 4096\n"
    "syscall\n"

    //; Fermer le fichier
    "mov rax, 3\n"          //; sys_close
    "mov rdi, r15\n"
    "syscall\n"

    //; Vérifier contre la liste interdite
    "mov rsi, forbidden_list\n"
"check_forbidden:\n"
    "mov rdi, buffer\n"
    "call strcmp\n"
    "test rax, rax\n"
    "jz found_forbidden\n"

    //; Passer au prochain élément de la liste
    "add rsi, 1\n"
    "cmp [rsi-1], 0\n"
    "jne check_forbidden\n"

"next_entry:\n"
    //; Passer à l'entrée suivante
    //"movzx rax, word [r14]\n"
    "_ZERO eax\n"
    "_SET al, [r14+1]\n"
    "shl eax, 8\n"
    "_SET al, [r14]\n"
    "add r14, rax\n"
    "jmp process_entry_loop\n"

"found_forbidden:\n"
    //; Afficher le message de détection
    "mov rax, 1\n"          //; sys_write
    "mov rdi, 1\n"          //; stdout
    "mov rsi, found_msg\n"
    "xor rdx, rdx\n"
    "_SET dl, [len_found_msg]\n"
    "syscall\n"

    //; Afficher le nom du processus interdit
    "mov rax, 1\n"
    "mov rdi, 1\n"
    "mov rsi, buffer\n"
    "call strlen\n"
    "mov rdx, rax\n"
    "mov rax, 1\n"
    "syscall\n"

    //; Afficher un saut de ligne
    "mov rax, 1\n"
    "mov rdi, 1\n"
    "mov rsi, newline\n"
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
//; Retourne 0 si égal, non-zero sinon
"strcmp:\n"
    "xor rcx, rcx\n"
"strcmp_loop:\n"
    "mov al, [rdi + rcx]\n"
    "mov bl, [rsi + rcx]\n"
    /// XOR STRING Batman
    "xor bl, 42\n"
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
//; Retourne la longueur dans rax
"strlen:\n"
    "xor rax, rax\n"
"strlen_loop:\n"
    "cmp [rsi + rax], 0\n"
    "je strlen_done\n"
    "inc rax\n"
    "jmp strlen_loop\n"
"strlen_done:\n"
    "ret";

static const char STUB_AV_DATA[] =
//"section .data\n"
    "msg_clear:\n"
        ".string \"Clear\"\n"
        ".db 10\n"
    //; Liste des processus interdits (terminés par un NULL)
    "forbidden_list:\n"
        ".string 42 \"gdb\"\n"
        ".string 42 \"radare2\"\n"
        ".string 42 \"ollydbg\"\n"
        ".string 42 \"x64dbg\"\n"
        ".string 42 \"idaq\"\n"
        ".string 42 \"wireshark\"\n"
        ".db 0\n"  //; Fin de la liste

    //; Chemin vers le répertoire des processus
    "proc_path:\n"
        ".string \"/proc\"\n"
    "newline:\n"
        ".db 10\n"

    //; Messages
    "found_msg:\n"
        ".string \"Processus interdit détecté: \"\n"
    "len_found_msg:\n"
        ".db 28\n"

//"section .bss\n"
    "buffer:\n"
        ".resb 4096\n"
    "process_name:\n"
        ".resb 256";

#endif