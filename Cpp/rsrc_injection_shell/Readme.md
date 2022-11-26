Using the resource section of a PE file to hide a reverse shell payload that connects to a nc listener on Kali. The shell session and .exe survive command execution
indefinitely as of 1200PST 11/26/2022.

1) Edit reverse_shell.c to your listener's specification and compile it with .\compile.bat.

2) Run pe2shc.exe on reverse_shell.exe and output shell.bin

3) Encrypt shell.bin with xorencrypt.py (this will give you favicon.ico)

4) Compile your implant with .\compile.bat

5) ????

6) PROFIT

![rsrc_injection_shell](https://user-images.githubusercontent.com/22229087/204105867-e3ee7585-9686-4c91-807e-ba851f9f8e2d.png)
