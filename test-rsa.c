#include "rsa_keys.h" // Generated header with keys
#include "rsa2048.h"
#include "bigint.h"
#include "sha256.h"
#include <stdio.h>
#include <stdint.h>

// Example main function
int main() {
    // Load firmware data (example - replace with actual firmware loading)
    uint8_t firmware_data[1024] = {0}; // Your firmware.bin data
    size_t firmware_size = sizeof(firmware_data);

    printf("[INFO] Opening firmware.bin...\n");

    FILE *f = fopen("firmware.bin", "rb");
    if (!f) {
        perror("[ERROR] Failed to open firmware.bin");
        return 1;
    }

    size_t bytes_read = fread(firmware_data, 1, sizeof(firmware_data), f);
    fclose(f);

    if (bytes_read == 0) {
        fprintf(stderr, "[ERROR] No data read from firmware.bin\n");
        return 1;
    }

    firmware_size = bytes_read;
    printf("[INFO] Read %zu bytes from firmware.bin\n", firmware_size);

    // Debug: print first 32 bytes of firmware
    printf("[DEBUG] First 32 bytes of firmware:\n");
    for (size_t i = 0; i < 32 && i < firmware_size; i++) {
        printf("%02X ", firmware_data[i]);
    }
    printf("\n");

    // Print info about signature and key sizes
    printf("[INFO] Signature size: %d bytes\n", SIGNATURE_SIZE);
    printf("[INFO] Modulus size: %d bytes\n", RSA_KEY_SIZE);
    printf("[INFO] Public exponent: %u\n", rsa_exponent);

    // Verify signature
    printf("[INFO] Verifying firmware signature...\n");
    rsa_verify_result_t result = verify_firmware(firmware_data, firmware_size);

    switch (result) {
        case RSA_VERIFY_OK:
            printf("[SUCCESS] Firmware signature is VALID\n");
            break;
        case RSA_VERIFY_INVALID_SIGNATURE:
            printf("[FAIL] Firmware signature is INVALID\n");
            break;
        case RSA_VERIFY_PADDING_ERROR:
            printf("[FAIL] Signature padding error\n");
            break;
        case RSA_VERIFY_ERROR:
            printf("[FAIL] General RSA verification error\n");
            break;
        default:
            printf("[FAIL] Unknown result code: %d\n", result);
            break;
    }

    return (result == RSA_VERIFY_OK) ? 0 : 1;
}
