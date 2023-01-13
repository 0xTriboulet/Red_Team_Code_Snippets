#include <windows.h>
#include <stdio.h>
#include <intrin.h>

int main(VOID){
	getchar();
	//__debugbreak();
	FARPROC a = GetProcAddress(LoadLibraryA("kernel32"),"CreateThread");
	//__debugbreak();
	printf("address %p\n:", a);
	printf("Success!\n");
	return 0;
}