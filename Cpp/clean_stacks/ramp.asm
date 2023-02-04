section .text
default rel 
bits 64

global onRamp

onRamp:						; onRamp (exec_mem, return_address) // rcx, rdx
mov r13, rdx				; preserve our return address
push r13					; put return_address on the stack
lea r13, [rsp]				; get return_address

lea r15, offRamp			; preserve offRamp address
push r15					; put r15 on the stack
lea r15, [rsp]				; get offRamp address

sub rsp, 0x20				; protect our addresses

jmp rcx						; jmp to our payload

offRamp:

loop:
pop rax						; pop value off the stack
cmp rsp,r13 				; check if r15 = rsp
jne loop					; loop if there's still garbage on the stack

ret


