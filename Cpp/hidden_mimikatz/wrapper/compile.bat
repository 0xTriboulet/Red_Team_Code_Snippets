@ECHO OFF

rc resources.rc
cvtres /MACHINE:x64 /OUT:resources.o resources.res

cl.exe /nologo /Od /MT /W0 /GS- /DNDEBUG /Tcmimikatz.cpp /link /OUT:mimikatz.exe /SUBSYSTEM:CONSOLE /MACHINE:x64 resources.o