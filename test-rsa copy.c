// ========== EXAMPLE USAGE ==========

#include "rsa_keys.h" // Generated header with keys
#include "rsa2048.h"
#include "bigint.h"
#include "sha256.h"
#include <stdio.h>

// Example main function
int main() {
    // Load firmware data (example - replace with actual firmware loading)
    uint8_t firmware_data[1024] = {0}; // Your firmware.bin data
    size_t firmware_size = sizeof(firmware_data);

    // Đọc nội dung từ file "firmware.bin"
    FILE *f = fopen("firmware.bin", "rb");
    if (!f) {
        perror("Failed to open firmware.bin");
        return 1;
    }

    size_t bytes_read = fread(firmware_data, 1, sizeof(firmware_data), f);
    fclose(f);
    if (bytes_read == 0) {
        fprintf(stderr, "No data read from firmware.bin\n");
        return 1;
    }
    firmware_size = bytes_read;

    // Verify signature
    rsa_verify_result_t result = verify_firmware(firmware_data, firmware_size);

    switch (result) {
        case RSA_VERIFY_OK:
            printf(" Firmware signature is VALID\n");
            break;
        case RSA_VERIFY_INVALID_SIGNATURE:
            printf(" Firmware signature is INVALID\n");
            break;
        case RSA_VERIFY_PADDING_ERROR:
            printf(" Signature padding error\n");
            break;
        case RSA_VERIFY_ERROR:
            printf(" RSA verification error\n");
            break;
    }

    return (result == RSA_VERIFY_OK) ? 0 : 1;
}