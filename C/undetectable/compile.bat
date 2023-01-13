@ECHO OFF

x86_64-w64-mingw32-gcc.exe .\undetectable.c -o undetectable.exe -l"ws2_32" -Wdiscarded-qualifiers