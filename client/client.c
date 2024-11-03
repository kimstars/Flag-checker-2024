#include <windows.h>
#include <stdio.h>

#define BUFFER_SIZE 256

void send_password(HANDLE pipe, const char* password) {
    DWORD bytes_written;
    WriteFile(pipe, password, strlen(password) + 1, &bytes_written, NULL);
}

void receive_response(HANDLE pipe) {
    char buffer[BUFFER_SIZE];
    DWORD bytes_read;
    ReadFile(pipe, buffer, BUFFER_SIZE, &bytes_read, NULL);
    printf("Server response: %s\n", buffer);
}

int main() {
    HANDLE pipe = CreateFile(
        L"\\\\.\\pipe\\msec2024",            // Pipe name
        GENERIC_READ | GENERIC_WRITE, // Read and Write access
        0,                    // No sharing
        NULL,                 // Default security attributes
        OPEN_EXISTING,        // Opens existing pipe
        0,                    // Default attributes
        NULL                  // No template file
    );

    if (pipe == INVALID_HANDLE_VALUE) {
        printf("CreateFile failed, error %d\n", GetLastError());
        return 1;
    }

    char password[BUFFER_SIZE];
    printf("Enter password: ");
    fgets(password, BUFFER_SIZE, stdin);
    password[strcspn(password, "\n")] = '\0';  // Remove newline character

    send_password(pipe, password);
    receive_response(pipe);

    CloseHandle(pipe);
    return 0;
}
