#include <windows.h>
#include <stdio.h>
#include <bcrypt.h>

#pragma comment(lib, "bcrypt.lib")

#define BUFFER_SIZE 256
#define KEY "\x1a\x16\x09\x0c\x44\x55\x44\x5a\x00\x00\x00\x00\x46\x55\x53\x59"
#define KEY_SIZE 16
#define AES_BLOCK_SIZE 16
#define PASSWORD "msec2024"

void handle_error(const char* message) {
    printf("%s, error %d\n", message, GetLastError());
    exit(1);
}

void xor (const char* key, unsigned char* data, size_t data_len) {
    size_t key_len = strlen(key);
    for (size_t i = 0; i < data_len; ++i) {
        data[i] ^= key[i % key_len];
    }
}

void pkcs7_padding(BYTE* plaintext, DWORD* plaintext_len, DWORD block_size) {
    BYTE padding_len = block_size - (*plaintext_len % block_size);
    for (DWORD i = 0; i < padding_len; ++i) {
        plaintext[*plaintext_len + i] = padding_len;
    }
    *plaintext_len += padding_len;
}

void aes_encrypt(const BYTE* key, const BYTE* iv, BYTE* plaintext, DWORD plaintext_len, BYTE* ciphertext, DWORD* ciphertext_len) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    DWORD cbKeyObject, cbData, cbBlockLen;
    PBYTE pbKeyObject = NULL;
    DWORD cbPlaintext = plaintext_len;

    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0) != 0) handle_error("BCryptOpenAlgorithmProvider");

    if (BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0) != 0) handle_error("BCryptSetProperty");

    if (BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&cbKeyObject, sizeof(DWORD), &cbData, 0) != 0) handle_error("BCryptGetProperty");

    pbKeyObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbKeyObject);
    if (!pbKeyObject) handle_error("HeapAlloc");

    if (BCryptGenerateSymmetricKey(hAlg, &hKey, pbKeyObject, cbKeyObject, (PUCHAR)key, KEY_SIZE, 0) != 0) handle_error("BCryptGenerateSymmetricKey");

    cbBlockLen = AES_BLOCK_SIZE;

    // Allocate memory for plaintext with padding
    DWORD padded_len = plaintext_len + (cbBlockLen - (plaintext_len % cbBlockLen));
    BYTE* padded_plaintext = (BYTE*)HeapAlloc(GetProcessHeap(), 0, padded_len);
    if (!padded_plaintext) handle_error("HeapAlloc");

    // Copy plaintext to padded buffer and add padding
    memcpy(padded_plaintext, plaintext, plaintext_len);
    pkcs7_padding(padded_plaintext, &cbPlaintext, cbBlockLen);

    DWORD cbCipherText = cbPlaintext;
    RtlZeroMemory(ciphertext, cbCipherText);

    if (BCryptEncrypt(hKey, (PUCHAR)padded_plaintext, cbPlaintext, NULL, (PUCHAR)iv, AES_BLOCK_SIZE, ciphertext, cbCipherText, &cbCipherText, 0) != 0) handle_error("BCryptEncrypt");

    *ciphertext_len = cbCipherText;

    if (hKey) BCryptDestroyKey(hKey);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    if (pbKeyObject) HeapFree(GetProcessHeap(), 0, pbKeyObject);
    if (padded_plaintext) HeapFree(GetProcessHeap(), 0, padded_plaintext);
}

void check_password(HANDLE pipe) {
    char buffer[BUFFER_SIZE];
    DWORD bytes_read, bytes_written;

    ReadFile(pipe, buffer, BUFFER_SIZE, &bytes_read, NULL);

    BYTE key[KEY_SIZE] = KEY;
    BYTE iv[AES_BLOCK_SIZE] = { 0 };
    BYTE ciphertext[BUFFER_SIZE];
    DWORD ciphertext_len;
    xor (PASSWORD, key, KEY_SIZE);

    memcpy(iv, key, AES_BLOCK_SIZE);
    aes_encrypt(key, iv, (BYTE*)buffer, (DWORD)strlen(buffer), ciphertext, &ciphertext_len);

    BYTE expected_ciphertext[] = { 0x11,0xd9,0x97,0xca,0x76,0xde,0x7d,0xe5,0x3d,0x06,0x8e,0x7d,0xd7,0xa0,0xd2,0x52,0x6b,0x3f,0x4e,0x01,0x4d,0x22,0xe8,0x65,0x54,0x5c,0x0b,0x8c,0x10,0x7a,0x55,0x79 };

    if (memcmp(ciphertext, expected_ciphertext, ciphertext_len) == 0) {
        WriteFile(pipe, "Success", 8, &bytes_written, NULL);
    }
    else {
        WriteFile(pipe, "Failure", 8, &bytes_written, NULL);
    }
}

int main() {
    while (1) {
        HANDLE pipe = CreateNamedPipe(
            L"\\\\.\\pipe\\msec2024",                // Pipe name
            PIPE_ACCESS_DUPLEX,       // Read/Write access
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT, // Message type pipe, blocking mode
            1,                        // Number of instances
            BUFFER_SIZE,              // Out buffer size
            BUFFER_SIZE,              // In buffer size
            0,                        // Default timeout
            NULL                      // Default security attributes
        );

        if (pipe == INVALID_HANDLE_VALUE) {
            //printf("CreateNamedPipe failed, error %d\n", GetLastError());
            return 1;
        }

        BOOL connected = ConnectNamedPipe(pipe, NULL) ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED);
        if (!connected) {
            //printf("ConnectNamedPipe failed, error %d\n", GetLastError());
            CloseHandle(pipe);
            return 1;
        }

        //printf("Checking password...\n");
        check_password(pipe);

        CloseHandle(pipe);
    }

    return 0;
}
