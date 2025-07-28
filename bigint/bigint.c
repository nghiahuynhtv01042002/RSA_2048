#include "bigint.h"
#include <string.h>
#include <stdio.h>
bigIntStatus_t bigint_zero(bigInt_t *a){
  if(!a) return BIGINT_ERR_NULL;
  memset(a->words, 0, BIGINT_MAX_WORDS * BIGINT_WORD_BYTES);
  a->length = 1;
  return BIGINT_OK;
}

bigIntStatus_t bigint_from_uint32(bigInt_t *a, uint32_t val){
  if(!a) return BIGINT_ERR_NULL;
  bigint_zero(a);
  a->words[0] = val;
  if (val == 0) {
    a->length = 1;  // Keep length = 1 for zero
  } else {
    a->length = 1;
  }
  return BIGINT_OK;
}


// Essential for RSA: Load big integer from byte array (big-endian)
bigIntStatus_t bigint_from_bytes(bigInt_t *a, const uint8_t *bytes, size_t byte_len) {
    if (!a || !bytes) return BIGINT_ERR_NULL;
    if (byte_len > BIGINT_MAX_WORDS * 4) return BIGINT_ERR_OVERFLOW;
    
    bigint_zero(a);
    
    // Load bytes in big-endian order
    for (size_t i = 0; i < byte_len; i++) {
        size_t word_idx = (byte_len - 1 - i) / 4;
        size_t byte_pos = (byte_len - 1 - i) % 4;
        a->words[word_idx] |= ((uint32_t)bytes[i]) << (byte_pos * 8);
    }
    
    // Set length
    a->length = (byte_len + 3) / 4;
    bigint_normalize(a);
    
    return BIGINT_OK;
}

// Convert big integer to byte array (big-endian)
bigIntStatus_t bigint_to_bytes(const bigInt_t *a, uint8_t *bytes, size_t target_len) {
    if (!a || !bytes) return BIGINT_ERR_NULL;
    
    // Initialize output buffer with zeros
    memset(bytes, 0, target_len);
    
    if (bigint_is_zero(a)) {
        return BIGINT_OK;  // Already zero-filled
    }
    
    // Calculate how many bytes we actually need
    size_t actual_bytes_needed = 0;
    for (int word_idx = a->length - 1; word_idx >= 0; word_idx--) {
        uint32_t word = a->words[word_idx];
        if (word_idx == a->length - 1) {
            // For the most significant word, find the actual number of bytes
            if (word & 0xFF000000) actual_bytes_needed = word_idx * 4 + 4;
            else if (word & 0x00FF0000) actual_bytes_needed = word_idx * 4 + 3;
            else if (word & 0x0000FF00) actual_bytes_needed = word_idx * 4 + 2;
            else actual_bytes_needed = word_idx * 4 + 1;
            break;
        }
    }
    
    // Check if the number is too big for target length
    if (actual_bytes_needed > target_len) {
        return BIGINT_ERR_OVERFLOW;
    }
    
    // Fill bytes from right to left (big-endian)
    size_t byte_idx = target_len - 1;
    
    // Process each word from least significant to most significant
    for (int word_idx = 0; word_idx < a->length && byte_idx < target_len; word_idx++) {
        uint32_t word = a->words[word_idx];
        
        // Extract bytes from word (little-endian to big-endian conversion)
        for (int byte_in_word = 0; byte_in_word < 4 && byte_idx < target_len; byte_in_word++) {
            bytes[byte_idx] = (uint8_t)(word >> (byte_in_word * 8));
            if (byte_idx == 0) break;  // Prevent underflow
            byte_idx--;
        }
    }
    
    return BIGINT_OK;
}

void bigint_normalize(bigInt_t *a) {
    if (!a) return;
    while (a->length > 1 && a->words[a->length - 1] == 0) {
        a->length--;
    }
}
bigIntStatus_t bigint_copy(bigInt_t *dst, const bigInt_t *src){
  if (!dst || !src) return BIGINT_ERR_NULL;
  memcpy(dst->words, src->words, BIGINT_WORD_BYTES * BIGINT_MAX_WORDS);
  dst->length = src->length;
  return BIGINT_OK;
}

bool bigint_is_zero(const bigInt_t *a){
  if(!a) return true;
  for(int i = 0; i < a->length ; ++i){
    if(a->words[i]) return false;
  }
  return true;
}

/**
 * Compares two big integers in magnitude (unsigned comparison).
 * 
 * @param a Pointer to the first big integer. **Must not be NULL** (unchecked for performance).
 * @param b Pointer to the second big integer. **Must not be NULL** (unchecked for performance).
 * @return 
 *    1  if |a| > |b|
 *    -1 if |a| < |b|
 *    0  if |a| == |b|
 * 
**/ 
int bigint_compare(const bigInt_t *a, const bigInt_t *b){
  
  if(a->length < b->length) return -1;
  if(a->length > b->length) return 1;
  for (int i = a->length - 1; i >= 0; i--) {
      if (a->words[i] > b->words[i]) return 1;
      if (a->words[i] < b->words[i]) return -1;
  }
  return 0;
}

bigIntStatus_t bigint_add(bigInt_t *res, const bigInt_t *a, const bigInt_t *b) {
  if (!res || !a || !b) return BIGINT_ERR_NULL;

  size_t max_len = (a->length > b->length) ? a->length : b->length;
  // Check for potential overflow
  if (max_len >= BIGINT_MAX_WORDS) return BIGINT_ERR_OVERFLOW;
  
  uint32_t carry = 0;
  size_t i;
  for (i = 0; i < max_len || carry; ++i) {
      if (i >= BIGINT_MAX_WORDS) return BIGINT_ERR_OVERFLOW;
      
      uint32_t aw = (i < a->length) ? a->words[i] : 0;
      uint32_t bw = (i < b->length) ? b->words[i] : 0;
      
      uint64_t sum = (uint64_t)aw + bw + carry;  // Use 64-bit to detect overflow
      res->words[i] = (uint32_t)sum;
      carry = (uint32_t)(sum >> 32);
  }
  res->length = i;
  return BIGINT_OK;
}

bigIntStatus_t bigint_sub(bigInt_t *res, const bigInt_t *a, const bigInt_t *b) {
    if (!res || !a || !b) return BIGINT_ERR_NULL;
    
    // Check if a < b (would result in negative, which we don't support)
    if (bigint_compare(a, b) < 0) {
        return BIGINT_ERR_OVERFLOW; // or define a new error for negative results
    }

    uint32_t borrow = 0;
    for (size_t i = 0; i < a->length; ++i) {
        uint32_t aw = a->words[i];
        uint32_t bw = (i < b->length) ? b->words[i] : 0;
        
        // Calculate difference with proper borrow handling
        uint64_t diff = (uint64_t)aw - bw - borrow;
        if (aw < bw + borrow) {
            diff += 0x100000000ULL;  // Add 2^32 when borrowing
            borrow = 1;
        } else {
            borrow = 0;
        }
        res->words[i] = (uint32_t)diff;
    }
    
    res->length = a->length;
    // Normalize result
    while (res->length > 1 && res->words[res->length - 1] == 0)
        res->length--;
    return BIGINT_OK;
}

bigIntStatus_t bigint_mul(bigInt_t *res, const bigInt_t *a, const bigInt_t *b) {
    if (!res || !a || !b) return BIGINT_ERR_NULL;
    
    // Check for overflow TRƯỚC khi multiplication
    if (a->length + b->length > BIGINT_MAX_WORDS) {
        printf("[DEBUG] Multiplication would overflow: %zu + %zu > %d\n", 
               a->length, b->length, BIGINT_MAX_WORDS);
        return BIGINT_ERR_OVERFLOW;
    }
    
    printf("[DEBUG] Multiplying %zu-word by %zu-word numbers\n", a->length, b->length);
    
    bigint_zero(res);
    
    for (size_t i = 0; i < a->length; ++i) {
        if (a->words[i] == 0) continue; // Skip zero words
        
        uint32_t carry = 0;
        for (size_t j = 0; j < b->length; ++j) {
            size_t pos = i + j;
            if (pos >= BIGINT_MAX_WORDS) {
                printf("[DEBUG] Position %zu exceeds BIGINT_MAX_WORDS\n", pos);
                return BIGINT_ERR_OVERFLOW;
            }
            
            uint64_t product = (uint64_t)a->words[i] * b->words[j];
            uint64_t sum = (uint64_t)res->words[pos] + (uint32_t)product + carry;
            res->words[pos] = (uint32_t)sum;
            carry = (uint32_t)((product >> 32) + (sum >> 32));
        }
        
        // Handle final carry
        if (carry) {
            size_t carry_pos = i + b->length;
            if (carry_pos >= BIGINT_MAX_WORDS) {
                printf("[DEBUG] Carry position %zu exceeds BIGINT_MAX_WORDS\n", carry_pos);
                return BIGINT_ERR_OVERFLOW;
            }
            res->words[carry_pos] = carry;
        }
    }
    
    res->length = a->length + b->length;
    // Normalize
    while (res->length > 1 && res->words[res->length - 1] == 0) {
        res->length--;
    }
    
    printf("[DEBUG] Multiplication result length: %zu\n", res->length);
    return BIGINT_OK;
}


bigIntStatus_t bigint_divmod(bigInt_t *quot, bigInt_t *rem, const bigInt_t *num, const bigInt_t *den) {
    if (!quot || !rem || !num || !den) return BIGINT_ERR_NULL;
    if (bigint_is_zero(den)) return BIGINT_ERR_DIV_ZERO;

    printf("[DEBUG] Starting divmod operation\n");
    
    bigint_zero(quot);
    bigIntStatus_t status = bigint_copy(rem, num);
    if (status != BIGINT_OK) return status;

    // Handle trivial cases
    if (bigint_compare(num, den) < 0) {
        printf("[DEBUG] Numerator < denominator, returning early\n");
        return BIGINT_OK; // quot = 0, rem = num (already copied)
    }

    // Simple subtraction method (slower but more reliable)
    printf("[DEBUG] Using subtraction method for division\n");
    int iterations = 0;
    const int MAX_DIV_ITERATIONS = 100000; // Giới hạn để tránh infinite loop
    
    while (bigint_compare(rem, den) >= 0 && iterations < MAX_DIV_ITERATIONS) {
        status = bigint_sub(rem, rem, den);
        if (status != BIGINT_OK) {
            printf("[DEBUG] Subtraction failed in divmod\n");
            return status;
        }
        
        // Increment quotient
        bigInt_t one;
        status = bigint_from_uint32(&one, 1);
        if (status != BIGINT_OK) return status;
        
        status = bigint_add(quot, quot, &one);
        if (status != BIGINT_OK) {
            printf("[DEBUG] Addition failed in divmod\n");
            return status;
        }
        
        iterations++;
        if (iterations % 1000 == 0) {
            printf("[DEBUG] Division iteration %d\n", iterations);
        }
    }
    
    if (iterations >= MAX_DIV_ITERATIONS) {
        printf("[DEBUG] Division hit maximum iterations\n");
        return BIGINT_ERR_OVERFLOW;
    }
    
    printf("[DEBUG] Division completed in %d iterations\n", iterations);
    return BIGINT_OK;
}

bigIntStatus_t bigint_mod(bigInt_t *res, const bigInt_t *a, const bigInt_t *m) {
    if (!res || !a || !m) return BIGINT_ERR_NULL;
    if (bigint_is_zero(m)) return BIGINT_ERR_DIV_ZERO;
    
    bigInt_t quot, rem;
    bigIntStatus_t status = bigint_divmod(&quot, &rem, a, m);
    if (status != BIGINT_OK) return status;
    
    return bigint_copy(res, &rem);
}

bigIntStatus_t bigint_shift_left(bigInt_t *a, size_t bits) {
    if (!a) return BIGINT_ERR_NULL;

    size_t word_shift = bits / 32;
    size_t bit_shift = bits % 32;

    // Check overflow for word shift
    if (word_shift > 0) {
        if (a->length + word_shift > BIGINT_MAX_WORDS) {
            return BIGINT_ERR_OVERFLOW;
        }
        
        // Shift words (from right to left to avoid overwriting)
        for (int i = (int)a->length - 1; i >= 0; --i) {
            a->words[i + word_shift] = a->words[i];
        }
        // Clear lower words
        for (size_t i = 0; i < word_shift; ++i) {
            a->words[i] = 0;
        }
        a->length += word_shift;
    }

    // Bit shift within words
    if (bit_shift > 0) {
        uint32_t carry = 0;
        for (size_t i = 0; i < a->length; ++i) {
            uint32_t new_carry = a->words[i] >> (32 - bit_shift);
            a->words[i] = (a->words[i] << bit_shift) | carry;
            carry = new_carry;
        }
        // Handle final carry
        if (carry) {
            if (a->length >= BIGINT_MAX_WORDS) {
                return BIGINT_ERR_OVERFLOW;
            }
            a->words[a->length++] = carry;
        }
    }

    return BIGINT_OK;
}

bigIntStatus_t bigint_shift_right(bigInt_t *a, size_t bits) {
  if (!a) return BIGINT_ERR_NULL;

  size_t word_shift = bits / 32;
  size_t bit_shift = bits % 32;

  if (word_shift >= a->length) {
      return bigint_zero(a);
  }
  
  // Shift words
  for (size_t i = 0; i < a->length - word_shift; ++i)
      a->words[i] = a->words[i + word_shift];
  
  // Clear upper words
  for (size_t i = a->length - word_shift; i < a->length; ++i)
      a->words[i] = 0;
      
  a->length -= word_shift;
  
  // Bit shift within words
  if (bit_shift > 0) {
    uint32_t carry = 0;
    for (int i = (int)a->length - 1; i >= 0; --i) {
        uint32_t new_carry = a->words[i] << (32 - bit_shift);
        a->words[i] = (a->words[i] >> bit_shift) | carry;
        carry = new_carry;
    }
  }
  
  // Normalize
  while (a->length > 1 && a->words[a->length - 1] == 0)
      a->length--;
  return BIGINT_OK;
}

bigIntStatus_t bigint_mod_exp(bigInt_t *res, const bigInt_t *base, const bigInt_t *exp, const bigInt_t *mod) {
    if (!res || !base || !exp || !mod) return BIGINT_ERR_NULL;
    if (bigint_is_zero(mod)) return BIGINT_ERR_DIV_ZERO;
    
    printf("[DEBUG] Starting optimized mod_exp\n");
    printf("[DEBUG] Base: %zu words, Exp: %zu words, Mod: %zu words\n", 
           base->length, exp->length, mod->length);
    
    // Check if BIGINT_MAX_WORDS is sufficient
    if (mod->length * 2 > BIGINT_MAX_WORDS) {
        printf("[ERROR] BIGINT_MAX_WORDS (%d) too small for RSA operations\n", BIGINT_MAX_WORDS);
        printf("[ERROR] Need at least %zu words\n", mod->length * 2);
        return BIGINT_ERR_OVERFLOW;
    }
    
    bigInt_t result, b, e;
    bigIntStatus_t status;
    
    // Initialize result = 1
    status = bigint_from_uint32(&result, 1);
    if (status != BIGINT_OK) return status;
    
    // Reduce base modulo mod first (quan trọng cho RSA)
    status = bigint_mod(&b, base, mod);
    if (status != BIGINT_OK) {
        printf("[DEBUG] Failed to reduce base mod mod\n");
        return status;
    }
    printf("[DEBUG] Base reduced to %zu words\n", b.length);
    
    status = bigint_copy(&e, exp);
    if (status != BIGINT_OK) return status;
    
    // Binary exponentiation
    int iteration = 0;
    const int MAX_ITERATIONS = 32 * exp->length; // Realistic limit
    
    while (!bigint_is_zero(&e) && iteration < MAX_ITERATIONS) {
        if (iteration % 100 == 0) {
            printf("[DEBUG] Iteration %d, exp length: %zu\n", iteration, e.length);
        }
        
        if (e.words[0] & 1) {  // If exp is odd
            bigInt_t temp;
            status = bigint_mul(&temp, &result, &b);
            if (status != BIGINT_OK) {
                printf("[DEBUG] Multiplication failed at iteration %d\n", iteration);
                return status;
            }
            
            status = bigint_mod(&result, &temp, mod);
            if (status != BIGINT_OK) {
                printf("[DEBUG] Modular reduction failed at iteration %d\n", iteration);
                return status;
            }
        }
        
        // Square base and reduce
        bigInt_t temp;
        status = bigint_mul(&temp, &b, &b);
        if (status != BIGINT_OK) {
            printf("[DEBUG] Base squaring failed at iteration %d\n", iteration);
            return status;
        }
        
        status = bigint_mod(&b, &temp, mod);
        if (status != BIGINT_OK) {
            printf("[DEBUG] Base mod reduction failed at iteration %d\n", iteration);
            return status;
        }
        
        // Divide exponent by 2
        status = bigint_shift_right(&e, 1);
        if (status != BIGINT_OK) return status;
        
        iteration++;
    }
    
    if (iteration >= MAX_ITERATIONS) {
        printf("[ERROR] Exceeded maximum iterations in mod_exp\n");
        return BIGINT_ERR_OVERFLOW;
    }
    
    printf("[DEBUG] Mod_exp completed after %d iterations\n", iteration);
    return bigint_copy(res, &result);
}
