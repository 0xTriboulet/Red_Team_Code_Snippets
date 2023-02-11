@ECHO OFF

cl.exe /nologo /Od /MT /W0 /GS- /DNDEBUG /Tpmain.cpp /EHsc /link /OUT:crypter.exe /SUBSYSTEM:CONSOLE /MACHINE:x64