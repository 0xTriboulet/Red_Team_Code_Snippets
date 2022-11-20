global _start

section .text

_start:
    push _start+0xb
    push _push_ret
    ret
    push _start+0x16
    push _push_ret_2
    ret
    jmp _exit



_push_ret:
;-----------------------HELLO!
    mov eax, 0x4         ;system call number (sys_write)
    mov ebx, 0x1         ;file descriptor (stdout)
    mov ecx, message     ;message to write
    mov edx, len         ;message length
    int 0x80             ;syscall
    ret

_push_ret_2:
;-----------------------HELLO AGAIN!
    mov eax, 0x4         ;system call number (sys_write)
    mov ebx, 0x1         ;file descriptor (stdout)
    mov ecx, message_2   ;message to write
    mov edx, len_2       ;message length
    int 0x80             ;syscall
    ret


_exit:
;-----------------------_SYS_EXIT
    mov eax, 0x1        ;system call number (sys_exit)
    mov ebx, 0x0
    int 0x80            ;call kernel

section .data
    message: db "HELLO!", 0dh, 0ah
    len equ $ - message   ;length of the string

    message_2: db "HELLO AGAIN!", 0dh, 0ah
    len_2 equ $ - message_2   ;length of the string
