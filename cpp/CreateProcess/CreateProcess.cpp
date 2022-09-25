#include <iostream>
#include <Windows.h>

int main(){

    STARTUPINFO si;
    si.cb = sizeof(si); //THE CB MEMBER OF STARTUPINFO SHOULD CONTAIN THE SIZE OF THE STRUCTURE TAKEN FROM THE CREATEPROCESSW DOC
    ZeroMemory(&si, sizeof(si)); //ZERO OUT THE MEMORY TO ENSURE THERE IS NO DATA IN THE REGION PRIOR TO USE

    PROCESS_INFORMATION pi;
    ZeroMemory(&pi, sizeof(pi));//ZERO THIS OUT TOO
    //NOW WE'RE READY TO CALL CREATE PROCESS

    BOOL success = CreateProcess(
        "C:\\Windows\\System32\\notepad.exe",
        NULL,
        0,
        0,
        FALSE,
        0,
        NULL,
        "C:\\Windows\\System32",
        &si,
        &pi);

    if (success){
        printf("Process created with PID: %d\n",pi.dwProcessId);
        return 0;
        
    }else{
        printf("Failed to create process. Error code: %d\n", GetLastError());
        return 1;
    }

}