#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void xor_encrypt_decrypt(const char* key, unsigned char* data, size_t data_len) {
    size_t key_len = strlen(key);
    for (size_t i = 0; i < data_len; ++i) {
        data[i] ^= key[i % key_len];
    }
}

int main() {
    const char* key = "ILOVEMSEC";
    const char* input_file = "client.exe";
    const char* output_file = "client_encrypted.exe";

    FILE* fp_in = fopen(input_file, "rb");
    if (!fp_in) {
        perror("fopen input");
        return 1;
    }

    fseek(fp_in, 0, SEEK_END);
    size_t file_size = ftell(fp_in);
    fseek(fp_in, 0, SEEK_SET);

    unsigned char* data = (unsigned char*)malloc(file_size);
    if (!data) {
        perror("malloc");
        fclose(fp_in);
        return 1;
    }

    fread(data, 1, file_size, fp_in);
    fclose(fp_in);

    xor_encrypt_decrypt(key, data, file_size);

    FILE* fp_out = fopen(output_file, "wb");
    if (!fp_out) {
        perror("fopen output");
        free(data);
        return 1;
    }

    fwrite(data, 1, file_size, fp_out);
    fclose(fp_out);
    free(data);

    printf("File encrypted and saved to %s\n", output_file);
    return 0;
}
