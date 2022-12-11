A self-staging PE binary that achieves hardcoded injection into Teams.exe on Windows 10 using the EarlyBird injection methodology. 

The binary works by passing useful information (stage, threadId) to the next stage before terminating. This breaks the process tree and obfuscates control flow graphs such that it bypasses the most up to date Windows Defender definitions as of 0800 PST 11 December 2022.

1) Edit reverse_shell.c to your listener's specification and compile it with .\compile.bat.

2) Run pe2shc.exe on reverse_shell.exe and output shell.bin

      ```pe2schc.exe: https://github.com/hasherezade/pe_to_shellcode/releases```

3) Encrypt shell.bin with xorencrypt.py (this will give you favicon.ico)

4) Compile rotd.cpp with .\compile.bat

5) ????

6) PROFIT



![image](https://user-images.githubusercontent.com/22229087/206917058-ab89b94c-e751-47a8-a1db-9913e0fdfbfa.png)

