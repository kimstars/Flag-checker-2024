﻿
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include "LoadLibraryR.h"
#define WIN_X64 0
#define WIN_X86 1
#define WIN_ARM 2
#pragma comment(lib,"Advapi32.lib")

#define BREAK_WITH_ERROR( e ) { printf( "[-] %s. Error=%d", e, GetLastError() ); break; }

// Simple app to inject a reflective DLL into a process vis its process ID.
int main(int argc, char* argv[])
{
	HANDLE hFile = NULL;
	HANDLE hModule = NULL;
	HANDLE hProcess = NULL;
	HANDLE hToken = NULL;
	LPVOID lpBuffer = NULL;
	DWORD dwLength = 0;
	DWORD dwBytesRead = 0;
	DWORD dwProcessId = 0;
	TOKEN_PRIVILEGES priv = { 0 };


	char* cpDllFile = "E:\\CTK\\nam5\\PIPE\\win32-named-pipes-example-master\\win32-named-pipes-example-master\\vc12\\x64\\Debug\\serverdll.dll";


	do
	{
		// Usage: inject.exe [pid] [dll_file]

		dwProcessId = GetCurrentProcessId();
		if (argc == 2)
			cpDllFile = argv[1];
		
			

		hFile = CreateFileA(cpDllFile, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hFile == INVALID_HANDLE_VALUE)
			BREAK_WITH_ERROR("Failed to open the DLL file");

		dwLength = GetFileSize(hFile, NULL);
		if (dwLength == INVALID_FILE_SIZE || dwLength == 0)
			BREAK_WITH_ERROR("Failed to get the DLL file size");

		lpBuffer = HeapAlloc(GetProcessHeap(), 0, dwLength);
		if (!lpBuffer)
			BREAK_WITH_ERROR("Failed to get the DLL file size");

		if (ReadFile(hFile, lpBuffer, dwLength, &dwBytesRead, NULL) == FALSE)
			BREAK_WITH_ERROR("Failed to alloc a buffer!");

		if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
		{
			priv.PrivilegeCount = 1;
			priv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

			if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &priv.Privileges[0].Luid))
				AdjustTokenPrivileges(hToken, FALSE, &priv, 0, NULL, NULL);

			CloseHandle(hToken);
		}

		hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, dwProcessId);
		if (!hProcess)
			BREAK_WITH_ERROR("Failed to open the target process");

		hModule = LoadRemoteLibraryR(hProcess, lpBuffer, dwLength, NULL);
		if (!hModule)
			BREAK_WITH_ERROR("Failed to inject the DLL");

		printf("[+] Injected the '%s' DLL into process %d.", cpDllFile, dwProcessId);

		WaitForSingleObject(hModule, -1);

	} while (0);

	if (lpBuffer)
		HeapFree(GetProcessHeap(), 0, lpBuffer);

	if (hProcess)
		CloseHandle(hProcess);

	return 0;
}