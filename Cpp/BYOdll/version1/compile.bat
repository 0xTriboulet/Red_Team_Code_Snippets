@ECHO OFF

cl.exe /nologo /Od /MT /W1 /GS- /DNDEBUG /EHsc /Tp *.cpp /link /OUT:implant.exe /SUBSYSTEM:CONSOLE /MACHINE:x64
del *.obj