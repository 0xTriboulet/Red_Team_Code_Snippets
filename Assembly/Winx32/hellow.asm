        global    _main                ; declare main() method
        extern    _printf              ; link to external library
        segment  .data
        message: db   'Hello world!', 0xA, 0
        message_2: db   'Hello again!!', 0xA, 0
        section .text
_other_2:
        push    message_2
        call    _printf
        pop     edi
        ret
_other:
        push    message
        call    _printf
        pop     edi
        ret
_main:                           
        push    _main+0xc
        mov     edi, _other           
        jmp     edi
        push    _main+0x18
        mov     edi, _other_2
        jmp     edi
        add     esp, 4            
        ret                       
        ; compile with  nasm -f win32 hellow.asm
        ; link with  gcc hellow.obj -o hellow.exe