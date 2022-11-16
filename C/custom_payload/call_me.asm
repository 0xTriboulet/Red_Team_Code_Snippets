DEFAULT REL

; nasm -f elf64 -o call_me.o call_me.asm -l call_me.assembly -O0
; ld -m elf_x86_64 -o call_me call_me.o

global _start

section .text

_start:
;Build stack
  mov rbp,rsp
  sub rsp, 0x48


;/usr/bin/echo -> RDI
;6e 69 62 2f \72 73 75 2f \6f 68 63 65 \2f
  mov rax, 0x6e69622f7273752f
  mov rdx, 0x6f6863652f
  mov [rbp-0x28], rdx
  mov [rbp-0x30], rax
  lea rbx, [rbp-0x30]
  push rbx
  lea rbx, [rsp]
  push 0x0

;PAYLOAD GOES HERE! as arg [1] -> RSI
;20 44 41 4f \ 4c 59 41 50 \ 52 45 48 20 \ 53 45 4f 47 \ 21 45

  mov rax, 0x2044414f4c594150
  mov rdx, 0x5245482053454f47
  mov rcx, 0x00002145
  mov [rbp-0x10], rcx
  mov [rbp-0x18], rdx
  mov [rbp-0x20], rax
  lea rcx, [rbp-0x20]
  push rcx; FIRST ARGUMENT EXECUTED BY ECHO, REMEMBER THIS IS A STACK

  push rcx; LAST PUSH IS PSUEDO-HEADER FOR EXEC SECTION 

  lea rsi, [rsp]
  mov rdi, [rbx]

  mov rdx, 0x0
  mov rax, 59  ;execve
  syscall
  mov rax, 60 ;EXIT
  syscall
