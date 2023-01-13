/* 
* By 0xTriboulet
* "good.exe" program
* 12/31/22
* compile with: x86_64-w64-mingw32-g++ good.cpp -o good_x64.exe -Wl,-subsystem,windows
*/

#include <stdio.h>
#include <Windows.h>

#pragma comment(lib, "user32.lib")
#pragma comment(lib, "kernel32.lib")

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, 
    LPSTR lpCmdLine, int nCmdShow) {
	MessageBox(NULL, "This is a safe program!", "Safe!", 0x0);
	return 0;
}
