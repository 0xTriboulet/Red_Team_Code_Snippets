nasm -f win64 payload.asm -o payload.o
nasm -f win64 ramp.asm -o ramp.o
x86_64-w64-mingw32-g++.exe main_clean.cpp ramp.o -o main_clean.exe -masm=intel