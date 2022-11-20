global _start
section .rodata
  msg: db "Hello, world!", 10
  msglen: equ $ - msg
  a: db 10
  b: db 10
  c: db 10
  d: db 10
  e: db 10
  f: db 10
  g: db 10
  h: db 10
  i: db 10
  j: db 10

section .text

_start:
  push _start+0x7
  jmp _step
  mov rax, 0
  
  mov rax, 60 ;SYS EXIT
  mov rdi, 0  ;
  syscall     ;

_step:
  push _step_2
  mov al, [a]
  mov bl, [b]
  mov cl, [c]
  mov dl, [d]
  ret

_step_2:
  push rax
  add  rax, rbx
  add  rax, rcx
  add  rax, rdx 
  mov  rbx, rax
  add  rsp, 0x8
  ret

