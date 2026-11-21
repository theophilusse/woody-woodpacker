scan_start:

    _SET eax, 1
    _SET edi, 1
    lea rsi, [greeting_msg]
    _SET edx, 13
    syscall
    jmp next_block

    _SET eax, 1
    _SET edi, 1
    lea rsi, [farewell_msg]
    _SET edx, 9
    syscall
    jmp back_from_farewell

next_block:

    jmp greeting
back_from_greeting: 
    jmp farewell
back_from_farewell:
    _SET eax, 60
    _ZERO edi
    syscall
    _ZERO eax
    _ZERO edi

scan_end:

greeting_msg:
.string "Hello World!\n"
farewell_msg:
.string "Goodbye!\n"
