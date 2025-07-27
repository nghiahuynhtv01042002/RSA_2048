#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include "sha256.h"

int main() {
    FILE *f = fopen("./genkey/firmware.bin", "rb");
    if (!f) {
        perror("fopen");
        return 1;
    }

    fseek(f, 0, SEEK_END);
    size_t len = ftell(f);
    fseek(f, 0, SEEK_SET);

    uint8_t *buf = malloc(len);
    if (!buf) {
        perror("malloc");
        fclose(f);
        return 1;
    }

    fread(buf, 1, len, f);
    fclose(f);

    uint8_t hash[32];
    sha256_hash(buf, len, hash);

    printf("SHA256: ");
    for (int i = 0; i < 32; i++)
        printf("%02x", hash[i]);
    printf("\n");

    free(buf);
    return 0;
}
