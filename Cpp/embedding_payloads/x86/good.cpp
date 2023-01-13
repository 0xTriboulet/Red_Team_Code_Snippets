/* 
* By 0xTriboulet
* "good.exe" program
* 12/31/22
* compile with: i686-w64-mingw32-g++ good.cpp -o good.exe -Wl,-subsystem,windows -ansi
*/

#include <stdio.h>
#include <Windows.h>

#pragma comment(lib, "user32.lib")

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, 
    LPSTR lpCmdLine, int nCmdShow) {
	MessageBox(NULL, "This is a safe program!", "Safe!", 0x0);
	return 0;
}
