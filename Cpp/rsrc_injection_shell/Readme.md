Using the resource section of a PE file to hide a reverse shell payload that connects to a nc listener on Kali. The shell session and .exe survive command execution
indefinitely as of 1200PST 11/26/2022.

implant.exe works by decrypting the payload and injecting it into the target process (hardcoded as msteams.exe). The payload then connects to our nc listener as a cmd
shell session.

Note: msteams.exe will terminate as a result of this payload's execution, but the session will remain open and implant.exe will remain on disk.

1) Edit reverse_shell.c to your listener's specification and compile it with .\compile.bat.

2) Run pe2shc.exe on reverse_shell.exe and output shell.bin
  > pe2schc.exe: https://github.com/hasherezade/pe_to_shellcode/releases

3) Encrypt shell.bin with xorencrypt.py (this will give you favicon.ico)

4) Compile your implant with .\compile.bat

5) ????

6) PROFIT

![rsrc_injection_shell](https://user-images.githubusercontent.com/22229087/204105867-e3ee7585-9686-4c91-807e-ba851f9f8e2d.png)




As of 1700PST 12/1/2022 this payload is now detected.
![image](https://user-images.githubusercontent.com/22229087/205192825-ce6ff719-bd58-41ec-b1ca-33dcedce8ffe.png)

