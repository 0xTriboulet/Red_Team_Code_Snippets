#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include <dlfcn.h>

#define _GNU_SOURCE

unsigned char cmd[] = 
"\x48\x89\xe5\x48\x81\xec\x48\x00\x00\x00\x48\xb8\x3b\x00\x00\x00"
"\x00\x00\x00\x00\x48\x31\xc9\x51\x48\x8d\x0d\x36\x00\x00\x00\x51"
"\x48\x8d\x0d\x20\x00\x00\x00\x51\x48\x8d\x3d\x18\x00\x00\x00\x48"
"\x8d\x34\x24\x48\x31\xd2\x0f\x05\x48\x31\xff\x48\xb8\x3c\x00\x00"
"\x00\x00\x00\x00\x00\x0f\x05\x2f\x75\x73\x72\x2f\x62\x69\x6e\x2f"
"\x65\x63\x68\x6f\x00\x50\x41\x59\x4c\x4f\x41\x44\x20\x47\x4f\x45"
"\x53\x20\x48\x45\x52\x45\x21\x0a\x00\x00";

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
