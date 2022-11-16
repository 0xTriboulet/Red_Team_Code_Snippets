#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>


#define _GNU_SOURCE

//sample program, that calls an executable payload
//msfvenom -p linux/x64/exec -f c CMD='echo TEST!'
//gcc -m64 -g system.c -o system.bin -O3
//this payload runs echo TEST!
unsigned char cmd[] = 
"\x48\xb8\x2f\x62\x69\x6e\x2f\x73\x68\x00\x99\x50\x54\x5f"
"\x52\x66\x68\x2d\x63\x54\x5e\x52\xe8\x0b\x00\x00\x00\x65"
"\x63\x68\x6f\x20\x54\x45\x53\x54\x21\x00\x56\x57\x54\x5e"
"\x6a\x3b\x58\x0f\x05";


//msfvenom -p linux/x86/exec -f c CMD='echo TEST!' -e x86/shikata_ga_nai
//gcc -m32 -g system.c -o system.bin -O3
/*
unsigned char cmd[] = 
"\xbd\x67\x87\x89\x56\xd9\xc5\xd9\x74\x24\xf4\x5a\x29\xc9"
"\xb1\x0c\x31\x6a\x14\x03\x6a\x14\x83\xc2\x04\x85\x72\xe3"
"\x5d\x11\xe4\xa6\x07\xc9\x3b\x24\x41\xee\x2c\x85\x22\x98"
"\xac\xb1\xeb\x3a\xc4\x2f\x7d\x59\x44\x58\x76\x9d\x69\x98"
"\xec\xfe\x01\xf7\xce\x54\x97\x54\x5b\x75\x17\x0c\x30\xfc"
"\xf6\x7f\x36";
*/


void * ptr = cmd;

int main(int argc, char* argv[])
{
    int rv;
    void* addr;
    size_t diff;

    int page_size = getpagesize();
    printf("page size :        %d\n",page_size);

    //system("echo test!");
    size_t size = sizeof(cmd);
    printf("payload size :     %d\n",size);

    int perms = PROT_READ | PROT_WRITE | PROT_EXEC;
    //int perms = PROT_READ | PROT_EXEC; //reduce cmd buffer permissions since if we don't need to write in this script (depends on the payload encoding)
    printf("prot permissions : %d\n",perms);

    // we have to page-align the address we pass into mprotect
    //  from -- man 2 mprotect: 
    // The implementation shall require that addr be a multiple of the page size as returned by sysconf().
    //
    addr = cmd - ((size_t)cmd % page_size);
    diff = (size_t) cmd - (size_t) addr;

    //change permissions of cmd[] so that we can execute that code
    //rv = mprotect(addr,diff+size,perms);
    rv = mprotect(addr,page_size,perms);
    printf("mprotect status :  %d\n",rv);
    printf("cmd addr :         %p\n", cmd);
    printf("ptr* :             %p\nRunning payload!\n\n", ptr);

    goto *ptr;

    return 0;
}
