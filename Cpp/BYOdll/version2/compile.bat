@ECHO OFF

cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /EHsc /Tp *.cpp /link /OUT:implant.exe /SUBSYSTEM:CONSOLE /MACHINE:x64 /STACK:4000000
del *.obj