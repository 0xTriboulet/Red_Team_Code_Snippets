@ECHO OFF

rc resources.rc
cvtres /MACHINE:x64 /OUT:resources.o resources.res
cl.exe /nologo /Od /favor:AMD64 /MT /W0 /GS- /DNDEBUG /D_CRT_SECURE_NO_WARNINGS /Tcrotd.cpp /link /OUT:ROTD.exe /SUBSYSTEM:CONSOLE /MACHINE:x64 resources.o