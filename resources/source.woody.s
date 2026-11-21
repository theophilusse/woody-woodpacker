scan_start:

%POLYBLOCK_START greeting
%CIPHERTEXT SYNC
    _SET eax, 111
    _SET edi, 111
    _SET esi, 111
    _JUNK 32
%PLAINTEXT NOSYNC
    _SET eax, 1
    _SET edi, 1
    lea rsi, [greeting_msg]
    _SET edx, 13
    syscall
    jmp next_block
%POLYBLOCK_END

%POLYBLOCK_START farewell
%CIPHERTEXT NOSYNC
    _SET eax, 222
    _SET edi, 222
%PLAINTEXT SYNC
    _SET eax, 1
    _SET edi, 1
    lea rsi, [farewell_msg]
    _SET edx, 9
    syscall
    jmp back_from_farewell
%POLYBLOCK_END

next_block:
%DECRYPT main_flow SYNC

%POLYBLOCK_START main_flow
%CIPHERTEXT SYNC
    %DECRYPT greeting XOR
    jmp greeting
back_from_greeting:
    %DECRYPT farewell ADD, SUB
    jmp farewell
back_from_farewell:
    _SET eax, 60
    _ZERO edi
    syscall
%PLAINTEXT NOSYNC
    _ZERO eax
    _ZERO edi
%POLYBLOCK_END;

scan_end:

greeting_msg:
.string "Hello World!\n"
farewell_msg:
.string "Goodbye!\n"
