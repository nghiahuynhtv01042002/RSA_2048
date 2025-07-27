#include "bigint.h"
#include <string.h>

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

bigIntStatus_t bigint_mul(bigInt_t *res, const bigInt_t *a, const bigInt_t *b) {
  if (!res || !a || !b) return BIGINT_ERR_NULL;
  
  // Check for overflow before multiplication
  if (a->length + b->length > BIGINT_MAX_WORDS) {
    return BIGINT_ERR_OVERFLOW;
  }
  
  bigint_zero(res);
  
  for (size_t i = 0; i < a->length; ++i) {
    if (a->words[i] == 0) continue; // Skip zero words for efficiency
    
    uint32_t carry = 0;
    for (size_t j = 0; j < b->length; ++j) {
      if (i + j >= BIGINT_MAX_WORDS) return BIGINT_ERR_OVERFLOW;
      
      uint64_t product = (uint64_t)a->words[i] * b->words[j];
      uint64_t sum = (uint64_t)res->words[i + j] + (uint32_t)product + carry;
      res->words[i + j] = (uint32_t)sum;
      carry = (uint32_t)((product >> 32) + (sum >> 32));
    }
    
    if (carry && i + b->length < BIGINT_MAX_WORDS) {
      res->words[i + b->length] = carry;
    } else if (carry) {
      return BIGINT_ERR_OVERFLOW;
    }
  }
  
  res->length = a->length + b->length;
  while (res->length > 1 && res->words[res->length - 1] == 0)
      res->length--;

  return BIGINT_OK;
}

bigIntStatus_t bigint_divmod(bigInt_t *quot, bigInt_t *rem, const bigInt_t *num, const bigInt_t *den) {
  if (!quot || !rem || !num || !den) return BIGINT_ERR_NULL;
  if (bigint_is_zero(den)) return BIGINT_ERR_DIV_ZERO;

  bigint_zero(quot);
  bigint_copy(rem, num);

  // Handle trivial cases
  if (bigint_compare(num, den) < 0) {
    return BIGINT_OK; // quot = 0, rem = num (already copied)
  }

  bigInt_t den_shifted;
  bigIntStatus_t status;

  while (bigint_compare(rem, den) >= 0) {
    size_t shift = 0;
    bigint_copy(&den_shifted, den);
    
    // Find the largest shift where den_shifted <= rem
    while (bigint_compare(rem, &den_shifted) >= 0) {
        bigInt_t temp;
        bigint_copy(&temp, &den_shifted);
        status = bigint_shift_left(&temp, 1);
        if (status != BIGINT_OK || bigint_compare(rem, &temp) < 0) {
            break;
        }
        bigint_copy(&den_shifted, &temp);
        shift++;
    }

    // Subtract den_shifted from remainder
    status = bigint_sub(rem, rem, &den_shifted);
    if (status != BIGINT_OK) return status;
    
    // Set the bit in quotient
    size_t word_idx = shift / 32;
    size_t bit_idx = shift % 32;
    if (word_idx < BIGINT_MAX_WORDS) {
        quot->words[word_idx] |= (1U << bit_idx);
        if (word_idx >= quot->length) {
            quot->length = word_idx + 1;
        }
    }
  }

  // Normalize quotient
  while (quot->length > 1 && quot->words[quot->length - 1] == 0)
      quot->length--;

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
 
// Essential for RSA: Modular exponentiation using binary method
bigIntStatus_t bigint_mod_exp(bigInt_t *res, const bigInt_t *base, const bigInt_t *exp, const bigInt_t *mod) {
  if (!res || !base || !exp || !mod) return BIGINT_ERR_NULL;
  if (bigint_is_zero(mod)) return BIGINT_ERR_DIV_ZERO;

  bigInt_t result, b, e;
  bigIntStatus_t status;
  
  // Initialize
  status = bigint_from_uint32(&result, 1);
  if (status != BIGINT_OK) return status;
  
  // Reduce base modulo mod first
  status = bigint_mod(&b, base, mod);
  if (status != BIGINT_OK) return status;
  
  status = bigint_copy(&e, exp);
  if (status != BIGINT_OK) return status;
  
  // Binary exponentiation with modular reduction
  while (!bigint_is_zero(&e)) {
    if (e.words[0] & 1) {  // If exp is odd
      bigInt_t temp;
      status = bigint_mul(&temp, &result, &b);
      if (status != BIGINT_OK) return status;
      
      status = bigint_mod(&result, &temp, mod);
      if (status != BIGINT_OK) return status;
    }
    
    // Square base and reduce
    bigInt_t temp;
    status = bigint_mul(&temp, &b, &b);
    if (status != BIGINT_OK) return status;
    
    status = bigint_mod(&b, &temp, mod);
    if (status != BIGINT_OK) return status;
    
    // Divide exponent by 2
    status = bigint_shift_right(&e, 1);
    if (status != BIGINT_OK) return status;
  }
  
  return bigint_copy(res, &result);
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