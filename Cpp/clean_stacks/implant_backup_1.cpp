#include <stdio.h>
#include <Windows.h>

// x86_64-w64-mingw32-g++.exe implant.cpp -o implant.exe -masm=intel

/* Reference
asm ( "assembly code"
           : output operands                  optional
           : input operands                   optional
           : list of clobbered registers      optional
);
*/

extern "C" void onRamp(PVOID exec_mem, PVOID ret_addr);

int main(void){
	printf("Implant running...\n");
	
	void * ret_addr = NULL;
	asm("lea %0, [rip+ReturnHere];"
	: "=r" (ret_addr) 								// ret_addr <- rip+ReturnHere
	:												// no inputs
	: 												// no predefined clobbers
	);
	
	printf("Return address: %p\n",ret_addr);		// get return address
	
	asm("int3; ReturnHere:;");							//ret_addr
	printf("Exiting implant...\n");
}


// nasm -f win64 payload.asm -o payload.o
// nasm -f win64 ramp.asm -o ramp.o
// x86_64-w64-mingw32-g++.exe implant.cpp -o implant.exe -masm=intel