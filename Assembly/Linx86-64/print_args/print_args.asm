section .text ; program currently prints args

global _start
_start:
    add rax, 0x8         ;add 8 to rax
    add rsp, rax         ;add rsp to rax
    mov rsi, [rsp]       ;copy arg to rsi (message)
    sub rsp, rax         ;restore rsp

global _find_length
_find_length:
    mov rbx, 0x0         ;clear rbx
    mov rcx, rsi         ;copy arg to rcx
    cmp rcx, 0x0         ;check if arg is empty
    jz _exit             ;exit if empty

_loop:                   ;iterate through the arg
    mov dl, [rcx]        ;copy low byte of [rcx] to dl
    cmp dl, 0x0          ;cmp to null byte
    jz _print            ;if null byte, jump to print
    inc rcx              ;if not null byte, inc byte of rcx
    jmp _loop            ;loop again

global _print
_print:
    push rax
    mov rax, 0x0
    mov rax, 0x1         ;system call number (sys_write)
    mov rdi, 0x1         ;file descriptor (stdout)
    sub rcx, rsi         ;subtract the differences
    mov rdx, rcx         ;message length
    syscall              ;sys_write
    mov rax, 0x1         ;system call number (sys_write)
    mov rdi, 0x1         ;file descriptor (stdout)
    mov rsi, new_line    ;print new line
    mov rdx, len         ;message length
    syscall              ;sys_write
    mov rax, 0x0         ;clear rax
    pop rax

_check_args:
    pop rbx              ;put argc into rbx
    dec rbx              ;decrement argc
    cmp rbx, 0x0         ;check for any args
    jz _exit             ;exit if no more args
    push rbx             ;put argc back on the stack
    mov rbx, 0x0         ;clear rbx
    jmp _start           ;take it to the top

global _exit
_exit:
    mov rax, 0x3c        ;system call number (sys_exit)
    mov rdi, 0x0         ;clear ebx
    syscall              ;call kernel

section .data            ; Used these to debug the sys_write, no practcical use
    new_line: db 0dh, 0ah
    len equ $ - new_line   ;length of the string
