DEFAULT REL

; nasm -f elf64 -o call_me.o call_me.asm -l call_me.assembly -O0
; ld -m elf_x86_64 -o call_me call_me.o

global _start

section .text

_start:

  mov  rbp, rsp ; build stack
  sub  rsp, 0x48

  mov  rax, 59  ; execve

  xor   rcx, rcx ; clear stack
  push  rcx

  lea   rcx, [rel arg1] ; push arguments
  push  rcx

  lea   rcx, [rel arg0] ; push command
  push  rcx

  lea  rdi, [rel arg0] ;cmd
  lea  rsi, [rsp] ;args
  xor  rdx, rdx ;env
  syscall

  xor  rdi, rdi
  mov  rax, 60
  syscall

arg0: db "/usr/bin/echo", 0 ; COMMAND GOES HERE
arg1: db "PAYLOAD GOES HERE!", 10, 0, 0 ; ARGUMENTS GO HERE
