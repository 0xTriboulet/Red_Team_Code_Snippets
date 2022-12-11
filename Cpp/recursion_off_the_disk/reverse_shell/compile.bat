@ECHO OFF

cl.exe /nologo /Od /MT /W0 /GS- /MP /DNDEBUG /Tcreverse_shell.cpp /link /OUT:reverse_shell.exe /SUBSYSTEM:CONSOLE /MACHINE:x64 