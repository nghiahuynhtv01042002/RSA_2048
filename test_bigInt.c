#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "bigint.h"

// In bigInt (debug)
void print_bigint(const bigInt_t *a, const char *label) {
    printf("%s (len=%u): 0x", label, a->length);
    for (int i = a->length - 1; i >= 0; --i) {
        printf("%08X", a->words[i]);
    }
    printf("\n");
}

void test_zero_and_from_uint32() {
    bigInt_t a;
    bigint_zero(&a);
    assert(bigint_is_zero(&a));

    bigint_from_uint32(&a, 1234);
    assert(a.words[0] == 1234);
    assert(a.length == 1);
}

void test_copy_and_compare() {
    bigInt_t a, b;
    bigint_from_uint32(&a, 0xABCD1234);
    bigint_copy(&b, &a);
    assert(bigint_compare(&a, &b) == 0);
}

void test_addition() {
    bigInt_t a, b, res;
    bigint_from_uint32(&a, 1);
    bigint_from_uint32(&b, 2);
    bigint_add(&res, &a, &b);
    assert(res.words[0] == 3);
}

void test_subtraction() {
    bigInt_t a, b, res;
    bigint_from_uint32(&a, 5);
    bigint_from_uint32(&b, 3);
    bigint_sub(&res, &a, &b);
    assert(res.words[0] == 2);
}

void test_shift_left() {
    bigInt_t a;
    bigint_from_uint32(&a, 1);
    bigint_shift_left(&a, 1);
    assert(a.words[0] == 2);

    bigint_shift_left(&a, 31);
    assert(a.words[0] == 0);
    assert(a.words[1] == 1);
}

void test_shift_right() {
    bigInt_t a;
    bigint_from_uint32(&a, 0x80000000);
    a.length = 2;
    a.words[1] = 1;
    bigint_shift_right(&a, 1);
    assert(a.words[0] == 0xC0000000); // check shifted bits
}

void test_multiplication() {
    bigInt_t a, b, res;
    bigint_from_uint32(&a, 3);
    bigint_from_uint32(&b, 4);
    bigint_mul(&res, &a, &b);
    assert(res.words[0] == 12);
}

void test_divmod() {
    bigInt_t num, den, quot, rem;
    bigint_from_uint32(&num, 17);
    bigint_from_uint32(&den, 5);
    bigint_divmod(&quot, &rem, &num, &den);
    assert(quot.words[0] == 3);
    assert(rem.words[0] == 2);
}

void test_mod() {
    bigInt_t a, m, res;
    bigint_from_uint32(&a, 11);
    bigint_from_uint32(&m, 4);
    bigint_mod(&res, &a, &m);
    assert(res.words[0] == 3);
}

void test_mod_exp() {
    bigInt_t base, exp, mod, res;
    bigint_from_uint32(&base, 4);
    bigint_from_uint32(&exp, 13);
    bigint_from_uint32(&mod, 497);
    bigint_mod_exp(&res, &base, &exp, &mod);
    assert(res.words[0] == 445); // 4^13 mod 497 = 445
}

void test_from_to_bytes() {
    bigInt_t a;
    uint8_t buf[256];
    size_t len = sizeof(buf);
    uint8_t input[] = {0x12, 0x34, 0x56, 0x78};
    bigint_from_bytes(&a, input, sizeof(input));
    assert(a.words[0] == 0x12345678);

    len = sizeof(buf);
    bigint_to_bytes(&a, buf, &len);
    assert(len == 4);
    assert(memcmp(buf, input, 4) == 0);
}

int main() {
    test_zero_and_from_uint32();
    test_copy_and_compare();
    test_addition();
    test_subtraction();
    test_shift_left();
    test_shift_right();
    test_multiplication();
    test_divmod();
    test_mod();
    test_mod_exp();
    test_from_to_bytes();

    printf("✅ All bigint tests passed!\n");
    return 0;
}
