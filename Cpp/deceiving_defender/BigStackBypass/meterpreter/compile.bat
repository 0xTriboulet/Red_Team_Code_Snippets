@ECHO OFF

cl.exe /nologo /Od /MT /W0 /GS /std:c++20 /DNDEBUG /Tpimplant.cpp /link /OUT:implant.exe /SUBSYSTEM:CONSOLE /MACHINE:x64 /STACK:300000000