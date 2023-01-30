section .text
default rel 
bits 64

global onRamp
global offRamp

;nasm -f win64 ramp.asm -o ramp.o
onRamp:					; onRamp(exec_mem, return_address) where &exec_mem in rcx
pop rax					; corrupt previous frame
push rdx
lea rax, [offRamp]		; get offRemp address
push rax				; if payload returns, it'll return to our off ramp
jmp rcx					; execute exec_mem

offRamp:				; slide back into normal execution (dangerous!)
mov rax, [r13]			; get return_address
jmp rax					; jump to return_address
nop						; This works for the demonstration but depending on your implant/payload you'll need custom offRamps