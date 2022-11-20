extern printf

section .data
    msg db  'Hello World!'
section .text
global main
main:
    ;write your code here
    push    rbp
    mov     rbp, rsp
    
    mov     rcx, msg
    sub     rsp, 32
    call    printf
    add     rsp, 32
    
    leave
    ret