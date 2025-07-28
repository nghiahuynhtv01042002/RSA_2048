#include "rsa_keys.h"     // chứa modulus, exponent
#include "rsa2048.h"      // verify_firmware()
#include "bigint.h"       // mod_exp, bigint_t
#include "sha256.h"       // sha256_hash()
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

void diagnose_rsa_inputs(const uint8_t *signature, const uint8_t *modulus, uint32_t exponent) {
    printf("\n=== RSA INPUT DIAGNOSIS ===\n");
    
    printf("Signature (first 32 bytes):\n");
    for (int i = 0; i < 32; i++) {
        printf("%02X ", signature[i]);
        if ((i + 1) % 16 == 0) printf("\n");
    }
    
    printf("\nModulus (first 32 bytes):\n");
    for (int i = 0; i < 32; i++) {
        printf("%02X ", modulus[i]);
        if ((i + 1) % 16 == 0) printf("\n");
    }
    
    printf("\nExponent: 0x%08X (%u)\n", exponent, exponent);
    
    // Test if we can convert to bigint
    bigInt_t sig_test, mod_test, exp_test;
    
    printf("\nTesting bigint conversions:\n");
    if (bigint_from_bytes(&sig_test, signature, 256) == BIGINT_OK) {
        printf("✅ Signature conversion OK\n");
    } else {
        printf("❌ Signature conversion FAILED\n");
    }
    
    if (bigint_from_bytes(&mod_test, modulus, 256) == BIGINT_OK) {
        printf("✅ Modulus conversion OK\n");
    } else {
        printf("❌ Modulus conversion FAILED\n");
    }
    
    if (bigint_from_uint32(&exp_test, exponent) == BIGINT_OK) {
        printf("✅ Exponent conversion OK\n");
    } else {
        printf("❌ Exponent conversion FAILED\n");
    }
}

void test_basic_bigint_operations() {
    printf("[TEST] Testing basic bigint operations...\n");
    
    bigInt_t a, b, result;
    
    // Test 1: Simple multiplication
    bigint_from_uint32(&a, 123);
    bigint_from_uint32(&b, 456);
    
    if (bigint_mul(&result, &a, &b) == BIGINT_OK) {
        printf("[TEST] 123 * 456 = %u (should be 56088)\n", result.words[0]);
    }
    
    // Test 2: Simple modular exponentiation
    bigint_from_uint32(&a, 3);  // base
    bigint_from_uint32(&b, 4);  // exponent
    bigInt_t mod;
    bigint_from_uint32(&mod, 100); // modulus
    
    if (bigint_mod_exp(&result, &a, &b, &mod) == BIGINT_OK) {
        printf("[TEST] 3^4 mod 100 = %u (should be 81)\n", result.words[0]);
    } else {
        printf("[TEST] Modular exponentiation failed\n");
    }
}

int main() {
    test_basic_bigint_operations();
    printf("[INFO] Opening firmware.bin...\n");

    FILE *f = fopen("./genkey/firmware.bin", "rb");
    if (!f) {
        perror("[ERROR] Failed to open firmware.bin");
        return 1;
    }

    // Lấy đúng kích thước thực của firmware
    fseek(f, 0, SEEK_END);
    size_t firmware_size = ftell(f);
    fseek(f, 0, SEEK_SET);

    printf("[INFO] Firmware size = %zu bytes\n", firmware_size);

    // Cấp phát đúng kích thước
    uint8_t *firmware_data = malloc(firmware_size);
    if (!firmware_data) {
        perror("[ERROR] malloc");
        fclose(f);
        return 1;
    }

    size_t bytes_read = fread(firmware_data, 1, firmware_size, f);
    fclose(f);

    if (bytes_read != firmware_size) {
        fprintf(stderr, "[ERROR] fread size mismatch\n");
        free(firmware_data);
        return 1;
    }

    // Debug: print first 32 bytes
    printf("[DEBUG] First 32 bytes of firmware:\n");
    for (size_t i = 0; i < 32 && i < firmware_size; i++) {
        printf("%02X ", firmware_data[i]);
    }
    printf("\n");

    // Compute and print SHA256 hash of firmware
    uint8_t hash[32];
    sha256_hash(firmware_data, firmware_size, hash);

    printf("[DEBUG] SHA256 of firmware:\n");
    for (int i = 0; i < 32; i++)
        printf("%02x", hash[i]);
    printf("\n");

    // Info about keys and signature
    printf("[INFO] Signature size: %d bytes\n", SIGNATURE_SIZE);
    printf("[INFO] Modulus size: %d bytes\n", RSA_KEY_SIZE);
    printf("[INFO] Public exponent: %u\n", rsa_exponent);

    // Signature verification
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

    free(firmware_data);
    return (result == RSA_VERIFY_OK) ? 0 : 1;
}
