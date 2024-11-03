#include <stdio.h>
#include "ReflectiveLoader.h"

#define BUFFER_SIZE 256
#define PIPE_NAME L"\\\\.\\pipe\\msec2024"
#define PASSWORD "correct_password"

void check_password(HANDLE pipe) {
    char buffer[BUFFER_SIZE];
    DWORD bytes_read, bytes_written;

    ReadFile(pipe, buffer, BUFFER_SIZE, &bytes_read, NULL);

    if (strcmp(buffer, PASSWORD) == 0) {
        WriteFile(pipe, "Success", 8, &bytes_written, NULL);
    }
    else {
        WriteFile(pipe, "Failure", 8, &bytes_written, NULL);
    }
}

DWORD WINAPI ServerThread(LPVOID lpParam) {
    HANDLE pipe = CreateNamedPipe(
        PIPE_NAME,                // Pipe name
        PIPE_ACCESS_DUPLEX,       // Read/Write access
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT, // Message type pipe, blocking mode
        1,                        // Number of instances
        BUFFER_SIZE,              // Out buffer size
        BUFFER_SIZE,              // In buffer size
        0,                        // Default timeout
        NULL                      // Default security attributes
    );

    if (pipe == INVALID_HANDLE_VALUE) {
        printf("CreateNamedPipe failed, error %d\n", GetLastError());
        return 1;
    }

    printf("Waiting for client to connect...\n");
    BOOL connected = ConnectNamedPipe(pipe, NULL) ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED);
    if (!connected) {
        printf("ConnectNamedPipe failed, error %d\n", GetLastError());
        CloseHandle(pipe);
        return 1;
    }

    printf("Client connected, checking password...\n");
    check_password(pipe);

    CloseHandle(pipe);
    return 0;
}

extern HINSTANCE hAppInstance;
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved) {
    switch (fdwReason) {
    case DLL_QUERY_HMODULE:
        if (lpReserved != NULL)
            *(HMODULE*)lpReserved = hAppInstance;
        break;
    case DLL_PROCESS_ATTACH:
        hAppInstance = hinstDLL;
        //CreateThread(NULL, 0, ServerThread, NULL, 0, NULL);
        MessageBoxA(NULL, "Hello from KietDZ!", "Reflective Dll Injection", MB_OK);
        break;
    case DLL_PROCESS_DETACH:
        break;
    case DLL_THREAD_ATTACH:
        break;
    case DLL_THREAD_DETACH:
        break;
    }
    return TRUE;
}

