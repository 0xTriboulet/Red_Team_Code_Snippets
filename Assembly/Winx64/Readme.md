Win64 programs written in assembly. I prefer to use link for this architecture in order to leverage Windows function calls more easily.

nasm -f win64 hello.asm -o hello_new.obj -l hello_new.assembly

link /entry:start /subsystem:console hello_new.obj kernel32.lib"
