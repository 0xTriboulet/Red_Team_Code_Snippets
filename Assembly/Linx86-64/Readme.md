Assembly programs and executables for Linux (x86_64)

Developed on Kali Linux

nasm -f elf64 -o PROGRAM_NAME.o PROGRAM_NAME.asm -l PROGRAM_NAME.assembly

ld -g PROGRAM_NAME.o -o PROGRAM_NAME.bin

