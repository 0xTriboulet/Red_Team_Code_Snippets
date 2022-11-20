extern GetStdHandle
extern WriteFile
extern ExitProcess

section .rodata

msg db "Hello World!", 0x0d, 0x0a

msg_len equ $-msg
stdout_query equ -11
status equ 0

section .data

stdout dw 0
bytesWritten dw 0

section .text

global start

start:
    mov rcx, stdout_query
    call GetStdHandle
    mov [rel stdout], rax

    mov  rcx, [rel stdout]
    mov  rdx, msg
    mov  r8, msg_len
    mov  r9, bytesWritten
    push qword 0
    call WriteFile

    mov rcx, status
    call ExitProcess
	;nasm -f win64 hello.asm -o hello_new.obj
	;link /entry:start /subsystem:console hello_new.obj kernel32.lib"