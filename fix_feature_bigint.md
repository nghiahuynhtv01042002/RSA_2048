``` c
// Fixed version of bigint_to_bytes that ensures fixed-length output
bigIntStatus_t bigint_to_bytes_fixed_length(const bigInt_t *a, uint8_t *bytes, size_t target_len) {
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

// Updated RSA verification function with fixed byte conversion
rsa_verify_result_t rsa_verify_signature_fixed(
    const uint8_t *message, size_t message_len,
    const uint8_t *signature, size_t sig_len,
    const uint8_t *modulus, size_t mod_len,
    uint32_t exponent
) {
    bigInt_t sig_bigint, mod_bigint, exp_bigint, result_bigint;
    bigIntStatus_t status;
    
    // Validate inputs
    if (!message || !signature || !modulus || 
        message_len == 0 || sig_len != mod_len) {
        return RSA_VERIFY_ERROR;
    }
    
    // Convert signature to bigint (big-endian)
    status = bigint_from_bytes(&sig_bigint, signature, sig_len);
    if (status != BIGINT_OK) return RSA_VERIFY_ERROR;
    
    // Convert modulus to bigint (big-endian) 
    status = bigint_from_bytes(&mod_bigint, modulus, mod_len);
    if (status != BIGINT_OK) return RSA_VERIFY_ERROR;
    
    // Convert exponent to bigint
    status = bigint_from_uint32(&exp_bigint, exponent);
    if (status != BIGINT_OK) return RSA_VERIFY_ERROR;
    
    // Perform RSA public key operation: signature^exponent mod modulus
    status = bigint_mod_exp(&result_bigint, &sig_bigint, &exp_bigint, &mod_bigint);
    if (status != BIGINT_OK) return RSA_VERIFY_ERROR;
    
    // Convert result back to bytes with FIXED LENGTH
    uint8_t decrypted[256];
    status = bigint_to_bytes_fixed_length(&result_bigint, decrypted, mod_len);
    if (status != BIGINT_OK) return RSA_VERIFY_ERROR;
    
    // Now decrypted has exactly mod_len bytes with leading zeros if needed
    
    // Verify PKCS#1 v1.5 padding for SHA-256
    // Check padding structure: 0x00 0x01 FF...FF 0x00 DigestInfo Hash
    if (decrypted[0] != 0x00 || decrypted[1] != 0x01) {
        return RSA_VERIFY_PADDING_ERROR;
    }
    
    // Find separator (0x00) after padding bytes (0xFF)
    size_t separator_pos = 0;
    for (size_t i = 2; i < mod_len; i++) {
        if (decrypted[i] == 0x00) {
            separator_pos = i;
            break;
        } else if (decrypted[i] != 0xFF) {
            return RSA_VERIFY_PADDING_ERROR;
        }
    }
    
    if (separator_pos == 0 || separator_pos < 10) { // Need at least 8 padding bytes
        return RSA_VERIFY_PADDING_ERROR;
    }
    
    // Verify DigestInfo structure
    size_t digest_info_pos = separator_pos + 1;
    size_t expected_digest_info_len = RSA_PKCS1_SHA256_PREFIX_LEN + SHA256_DIGEST_SIZE;
    
    if (digest_info_pos + expected_digest_info_len != mod_len) {
        return RSA_VERIFY_PADDING_ERROR;
    }
    
    // Check DigestInfo prefix
    if (memcmp(decrypted + digest_info_pos, RSA_PKCS1_SHA256_PREFIX, 
               RSA_PKCS1_SHA256_PREFIX_LEN) != 0) {
        return RSA_VERIFY_PADDING_ERROR;
    }
    
    // Extract hash from decrypted signature
    uint8_t *sig_hash = decrypted + digest_info_pos + RSA_PKCS1_SHA256_PREFIX_LEN;
    
    // Compute hash of message
    uint8_t message_hash[SHA256_DIGEST_SIZE];
    sha256_hash(message, message_len, message_hash);
    
    // Compare hashes
    if (memcmp(sig_hash, message_hash, SHA256_DIGEST_SIZE) == 0) {
        return RSA_VERIFY_OK;
    } else {
        return RSA_VERIFY_INVALID_SIGNATURE;
    }
}
```