#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "resource.h"
#include "internals.h"


#define BUFFER_SIZE 256
#define KEY "ILOVEMSEC"


#define BREAK_WITH_ERROR(m) {printf("[-] %s! Error 0x%x", m, GetLastError()); break;}
#define BREAK_WITH_STATUS(m, s) {printf("[-] %s! Error 0x%x", m, s); break;}

// Hàm mã hóa/giải mã XOR
void xor_encrypt_decrypt(const char* key, unsigned char* data, size_t data_len) {
    size_t key_len = strlen(key);
    for (size_t i = 0; i < data_len; ++i) {
        data[i] ^= key[i % key_len];
    }
}


void CreateHollowedProcess(char* pDestCmdLine, BYTE* rawImage, DWORD rawImageSz) {
    BOOL returnStatus = 0;
    NTSTATUS status = 0;

    HMODULE hNtdll = NULL;
    pfnNtUnmapViewOfSection pNtUnmapViewOfSection = NULL;
    pfnNtQueryInformationProcess  pNtQueryInformationProcess = NULL;

    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };

    HANDLE hFile = NULL;
    UINT_PTR imageBase = NULL;

    do {
        // Get APIs address
        if (!(hNtdll = GetModuleHandleW(L"ntdll")))
            BREAK_WITH_ERROR("Failed to get ntdll module");

        if (!(pNtUnmapViewOfSection = (pfnNtUnmapViewOfSection)GetProcAddress(hNtdll, "NtUnmapViewOfSection")))
            BREAK_WITH_ERROR("Failed to get NtUnmapViewOfSection");

        if (!(pNtQueryInformationProcess = (pfnNtQueryInformationProcess)GetProcAddress(hNtdll, "NtQueryInformationProcess")))
            BREAK_WITH_ERROR("Failed to get NtQueryInformationProcess");

        // Create a suspended process
        if (!CreateProcessA(NULL, pDestCmdLine, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi))
            BREAK_WITH_ERROR("Failed to create process");

        // Get PEB of target process
        _PEB peb = { 0 };
        ULONG pbiSize = 0;
        PROCESS_BASIC_INFORMATION pbi = { 0 };
        if (!NT_SUCCESS(status = pNtQueryInformationProcess(pi.hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &pbiSize)))
            BREAK_WITH_STATUS("Failed to retreive process information", status);

        // Read image base of target process
        if (!ReadProcessMemory(pi.hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), NULL))
            BREAK_WITH_ERROR("Failed to read PEB");

        // Unmap main module of target process
        if (!NT_SUCCESS(status = pNtUnmapViewOfSection(pi.hProcess, peb.lpImageBaseAddress)))
            BREAK_WITH_STATUS("Failed to unmap executable module of target process", status);

        // Allocate new memory in target process
        PIMAGE_NT_HEADERS ntHeader = rawImage + ((PIMAGE_DOS_HEADER)rawImage)->e_lfanew;
        if (!(imageBase = VirtualAllocEx(pi.hProcess, peb.lpImageBaseAddress, ntHeader->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)))
            BREAK_WITH_ERROR("Failed to allocate memory for image");

        // Calculate delta and update image base for malicious image
        UINT_PTR delta = imageBase - ntHeader->OptionalHeader.ImageBase;
        ntHeader->OptionalHeader.ImageBase = imageBase;

        // Write header of malicious image to target process
        if (!WriteProcessMemory(pi.hProcess, imageBase, rawImage, ntHeader->OptionalHeader.SizeOfHeaders, NULL))
            BREAK_WITH_ERROR("Failed to write header");

        // Write sections of malicious image to target process
        PIMAGE_SECTION_HEADER sectionHeader = (UINT_PTR)ntHeader + sizeof(IMAGE_NT_HEADERS);
        for (DWORD i = 0; i < ntHeader->FileHeader.NumberOfSections; i++) {
            UINT_PTR sectionRA = rawImage + sectionHeader[i].PointerToRawData;
            UINT_PTR sectionVA = imageBase + sectionHeader[i].VirtualAddress;
            WriteProcessMemory(pi.hProcess, sectionVA, sectionRA, sectionHeader[i].SizeOfRawData, NULL);
        }

        // Implementing relocation for malicious image in target process
        PIMAGE_DATA_DIRECTORY relocDir = &ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        BYTE relocName[] = ".reloc";
        for (DWORD i = 0; i < ntHeader->FileHeader.NumberOfSections; i++) {
            if (memcmp(sectionHeader[i].Name, relocName, sizeof(relocName)))
                continue;

            DWORD relocOffset = 0;
            while (relocOffset < relocDir->Size) {
                PBASE_RELOCATION_BLOCK relocBlock = rawImage + sectionHeader[i].PointerToRawData + relocOffset;
                PBASE_RELOCATION_ENTRY relocEntry = (INT_PTR)relocBlock + sizeof(BASE_RELOCATION_BLOCK);
                DWORD numRelocEntry = (relocBlock->BlockSize - sizeof(BASE_RELOCATION_BLOCK)) / sizeof(BASE_RELOCATION_ENTRY);
                for (DWORD j = 0; j < numRelocEntry; j++) {
                    if (relocEntry[j].Type == 0)
                        continue;

                    UINT_PTR relocPos = imageBase + relocBlock->PageAddress + relocEntry[j].Offset;
                    UINT_PTR relocPosData = 0;
                    ReadProcessMemory(pi.hProcess, relocPos, &relocPosData, sizeof(relocPosData), NULL);
                    relocPosData += delta;
                    WriteProcessMemory(pi.hProcess, relocPos, &relocPosData, sizeof(relocPosData), NULL);
                }
                relocOffset += relocBlock->BlockSize;
            }
        }

        // Get thread context and update new entry point
        CONTEXT context = { 0 };
        context.ContextFlags = CONTEXT_FULL;
        if (!GetThreadContext(pi.hThread, &context))
            BREAK_WITH_ERROR("Failed to get context");

        context.Rcx = imageBase + ntHeader->OptionalHeader.AddressOfEntryPoint;
        if (!SetThreadContext(pi.hThread, &context))
            BREAK_WITH_ERROR("Failed to set context");

        // Resume thread to run malicious image
        ResumeThread(pi.hThread);
        returnStatus = TRUE;
    } while (0);

    if (INVALID_HANDLE_VALUE != hFile)
        CloseHandle(hFile);

    if (rawImage)
        VirtualFree(rawImage, 0, MEM_RELEASE);

    if (pi.hThread)
        CloseHandle(pi.hThread);

    if (pi.hProcess)
        CloseHandle(pi.hProcess);
}




int main() {
    HRSRC hResource = FindResource(NULL, MAKEINTRESOURCE(IDR_SERVERDLL), RT_RCDATA);
    if (!hResource) {
        printf("FindResource failed, error %d\n", GetLastError());
        return 1;
    }

    HGLOBAL hLoadedResource = LoadResource(NULL, hResource);
    if (!hLoadedResource) {
        printf("LoadResource failed, error %d\n", GetLastError());
        return 1;
    }

    DWORD resourceSize = SizeofResource(NULL, hResource);
    BYTE* pResourceData = (BYTE*)LockResource(hLoadedResource);

    BYTE* decodedData = (BYTE*)malloc(resourceSize);
    if (!decodedData) {
        perror("malloc");
        return 1;
    }

    memcpy(decodedData, pResourceData, resourceSize);
    xor_encrypt_decrypt(KEY, decodedData, resourceSize);

    

    int count_fail = 0;
    


    while (1) {
        HANDLE pipe = CreateFile(
            L"\\\\.\\pipe\\msec2024",
            GENERIC_READ | GENERIC_WRITE,
            0,
            NULL,
            OPEN_EXISTING,
            0,
            NULL
        );

        if (pipe == INVALID_HANDLE_VALUE) {
            if (count_fail == 0) {
                CreateHollowedProcess("nslookup.exe", decodedData, resourceSize);
            }
            count_fail++;
            Sleep(2);
            if (count_fail < 5) continue;

            //printf("CreateFile PIPE failed, error %d\n", GetLastError());
            return 1;
        }

        char password[BUFFER_SIZE];
        printf(" __        __   __     __ __    __ __             __ __ __  __   __  __      \n"
            "|_ |   /\\ / _  /  |__||_ /  |_/|_ |__)  __   |\\/|(_ |_ /     _) /  \\  _) |__|\n"
            "|  |__/--\\\\__) \\__|  ||__\\__| \\|__| \\        |  |__)|__\\__  /__ \\__/ /__    |\n");
        printf("Enter flag: ");
        fgets(password, BUFFER_SIZE, stdin);
        password[strcspn(password, "\n")] = '\0';

        DWORD bytes_written, bytes_read;
        WriteFile(pipe, password, strlen(password) + 1, &bytes_written, NULL);

        char buffer[BUFFER_SIZE];
        ReadFile(pipe, buffer, BUFFER_SIZE, &bytes_read, NULL);

        if (strcmp(buffer, "Success") == 0) {
            printf("Server response: %s\n", buffer);
            CloseHandle(pipe);
            break;
        }
        else {
            printf("Server response: %s. Please try again.\n", buffer);
        }

        CloseHandle(pipe);
    }
    
    return 0;
}
