Win32 programs written in assembly.

nasm -f win32 PROGRAM_NAME.asm -o PROGRAM_NAME.obj -l PROGRAM_NAME.assembly

gcc PROGRAM_NAME.obj -o PROGRAM_NAME.exe
