#!/usr/bin/env python3
"""
Script to verify RSA key arrays from C file against provided key information
"""

# RSA arrays from C file
rsa_modulus_c = [
    0xC0, 0x86, 0x2E, 0x5B, 0xE3, 0xB6, 0x83, 0xBE, 0xEC, 0x15, 0x41, 0x19, 0x0F, 0x3E, 0xEB, 0x79,
    0x65, 0xF0, 0xD7, 0xE2, 0xB8, 0xA7, 0x64, 0xCF, 0x38, 0xBC, 0x86, 0xF6, 0x7F, 0x62, 0xF4, 0xE2,
    0x26, 0xCF, 0x81, 0xEF, 0x3A, 0xCC, 0xCB, 0x12, 0xC9, 0x67, 0x1B, 0x42, 0xEF, 0xA9, 0xB9, 0xD2,
    0x54, 0x43, 0x4E, 0x14, 0xEE, 0x94, 0x69, 0xD5, 0xC3, 0x67, 0xF0, 0x32, 0xC7, 0x29, 0xB9, 0x11,
    0x2F, 0x07, 0xBA, 0x8C, 0xDF, 0x00, 0x04, 0xA6, 0x9D, 0x69, 0xF2, 0x5D, 0x30, 0x81, 0xF0, 0xE2,
    0x14, 0x40, 0x96, 0xAE, 0x34, 0xBB, 0xE0, 0xF6, 0xEE, 0xA2, 0x1F, 0x23, 0x61, 0x0B, 0x6B, 0xB0,
    0x20, 0xA3, 0x87, 0x6A, 0xE3, 0x4C, 0xED, 0x51, 0x3F, 0x36, 0x1E, 0x78, 0xBB, 0xB5, 0xB5, 0x20,
    0xEB, 0xE5, 0xF4, 0xE2, 0x01, 0xC5, 0x0D, 0x7E, 0x18, 0xAB, 0x02, 0xB8, 0xF5, 0xFC, 0x9B, 0x1D,
    0x12, 0xAD, 0xD0, 0x99, 0x4E, 0x2B, 0x55, 0x10, 0x54, 0x49, 0x91, 0x16, 0xC1, 0xD0, 0x2C, 0x96,
    0x98, 0x68, 0xED, 0x77, 0x30, 0xCB, 0x75, 0xAA, 0x4B, 0x98, 0x37, 0x7E, 0x8B, 0xB0, 0x6E, 0x2D,
    0x17, 0x36, 0xD3, 0x2B, 0x0F, 0xB7, 0x75, 0x5F, 0x8D, 0x03, 0x21, 0xC2, 0x88, 0x10, 0x26, 0x35,
    0x76, 0x19, 0xF0, 0x6A, 0xCB, 0x3A, 0x94, 0x37, 0xAF, 0x41, 0xB6, 0x9A, 0xD2, 0x29, 0xE5, 0x7B,
    0xFA, 0xBE, 0xB7, 0x87, 0x38, 0x61, 0x24, 0xEE, 0x4B, 0xEF, 0x3E, 0x52, 0x47, 0x0C, 0x46, 0xA3,
    0x94, 0xBC, 0xC8, 0x76, 0xE7, 0xAD, 0x28, 0xEF, 0x24, 0x8B, 0x7B, 0x0D, 0xE1, 0xF5, 0x16, 0x58,
    0x11, 0x99, 0x55, 0x56, 0x58, 0xED, 0x56, 0x8D, 0xD1, 0x61, 0x54, 0x0D, 0x32, 0x8F, 0xD4, 0xFD,
    0x58, 0x65, 0x22, 0xDB, 0xAB, 0x15, 0x64, 0x3B, 0xD9, 0x89, 0xC7, 0x6B, 0x69, 0x4B, 0x99, 0x97
]

# Expected modulus from key_info (hex string converted to bytes)
expected_modulus_hex = "C0862E5BE3B683BEEC1541190F3EEB7965F0D7E2B8A764CF38BC86F67F62F4E226CF81EF3ACCCB12C9671B42EFA9B9D254434E14EE9469D5C367F032C729B9112F07BA8CDF0004A69D69F25D3081F0E2144096AE34BBE0F6EEA21F23610B6BB020A3876AE34CED513F361E78BBB5B520EBE5F4E201C50D7E18AB02B8F5FC9B1D12ADD0994E2B551054499116C1D02C969868ED7730CB75AA4B98377E8BB06E2D1736D32B0FB7755F8D0321C2881026357619F06ACB3A9437AF41B69AD229E57BFABEB787386124EE4BEF3E52470C46A394BCC876E7AD28EF248B7B0DE1F516581199555658ED568DD161540D328FD4FD586522DBAB15643BD989C76B694B9997"

# RSA exponent from C file
rsa_exponent_c = 0x10001

# Expected exponent
expected_exponent = 65537  # 0x10001

def hex_string_to_bytes(hex_str):
    """Convert hex string to list of bytes"""
    return [int(hex_str[i:i+2], 16) for i in range(0, len(hex_str), 2)]

def bytes_to_hex_string(byte_list):
    """Convert list of bytes to hex string"""
    return ''.join([f'{b:02X}' for b in byte_list])

def verify_modulus():
    """Verify RSA modulus"""
    print("=== KIỂM TRA RSA MODULUS ===")
    
    # Convert expected hex string to bytes
    expected_modulus_bytes = hex_string_to_bytes(expected_modulus_hex)
    
    print(f"Độ dài modulus trong C file: {len(rsa_modulus_c)} bytes")
    print(f"Độ dài modulus expected: {len(expected_modulus_bytes)} bytes")
    
    # Compare
    if rsa_modulus_c == expected_modulus_bytes:
        print("✅ MODULUS ĐÚNG!")
        return True
    else:
        print("❌ MODULUS SAI!")
        
        # Find differences
        print("\nSo sánh chi tiết:")
        for i, (actual, expected) in enumerate(zip(rsa_modulus_c, expected_modulus_bytes)):
            if actual != expected:
                print(f"  Byte {i}: C file = 0x{actual:02X}, Expected = 0x{expected:02X}")
        
        # Show first few bytes for comparison
        print(f"\nC file modulus (first 16 bytes): {bytes_to_hex_string(rsa_modulus_c[:16])}")
        print(f"Expected modulus (first 16 bytes): {expected_modulus_hex[:32]}")
        
        return False

def verify_exponent():
    """Verify RSA exponent"""
    print("\n=== KIỂM TRA RSA EXPONENT ===")
    
    print(f"Exponent trong C file: 0x{rsa_exponent_c:X} ({rsa_exponent_c})")
    print(f"Expected exponent: 0x{expected_exponent:X} ({expected_exponent})")
    
    if rsa_exponent_c == expected_exponent:
        print("✅ EXPONENT ĐÚNG!")
        return True
    else:
        print("❌ EXPONENT SAI!")
        return False

def verify_modulus_from_openssl():
    """Verify modulus against OpenSSL format"""
    print("\n=== KIỂM TRA VỚI OPENSSL FORMAT ===")
    
    # OpenSSL modulus format (with leading 00: removed)
    openssl_hex = """00:c0:86:2e:5b:e3:b6:83:be:ec:15:41:19:0f:3e:
    eb:79:65:f0:d7:e2:b8:a7:64:cf:38:bc:86:f6:7f:
    62:f4:e2:26:cf:81:ef:3a:cc:cb:12:c9:67:1b:42:
    ef:a9:b9:d2:54:43:4e:14:ee:94:69:d5:c3:67:f0:
    32:c7:29:b9:11:2f:07:ba:8c:df:00:04:a6:9d:69:
    f2:5d:30:81:f0:e2:14:40:96:ae:34:bb:e0:f6:ee:
    a2:1f:23:61:0b:6b:b0:20:a3:87:6a:e3:4c:ed:51:
    3f:36:1e:78:bb:b5:b5:20:eb:e5:f4:e2:01:c5:0d:
    7e:18:ab:02:b8:f5:fc:9b:1d:12:ad:d0:99:4e:2b:
    55:10:54:49:91:16:c1:d0:2c:96:98:68:ed:77:30:
    cb:75:aa:4b:98:37:7e:8b:b0:6e:2d:17:36:d3:2b:
    0f:b7:75:5f:8d:03:21:c2:88:10:26:35:76:19:f0:
    6a:cb:3a:94:37:af:41:b6:9a:d2:29:e5:7b:fa:be:
    b7:87:38:61:24:ee:4b:ef:3e:52:47:0c:46:a3:94:
    bc:c8:76:e7:ad:28:ef:24:8b:7b:0d:e1:f5:16:58:
    11:99:55:56:58:ed:56:8d:d1:61:54:0d:32:8f:d4:
    fd:58:65:22:db:ab:15:64:3b:d9:89:c7:6b:69:4b:
    99:97"""
    
    # Clean up OpenSSL format
    clean_hex = openssl_hex.replace(':', '').replace('\n', '').replace(' ', '').upper()
    # Remove leading 00
    if clean_hex.startswith('00'):
        clean_hex = clean_hex[2:]
    
    print(f"OpenSSL modulus (cleaned): {clean_hex}")
    print(f"Expected modulus:          {expected_modulus_hex}")
    print(f"C file modulus:            {bytes_to_hex_string(rsa_modulus_c)}")
    
    if clean_hex == expected_modulus_hex:
        print("✅ OpenSSL format khớp với expected!")
    else:
        print("❌ OpenSSL format không khớp!")

def main():
    """Main verification function"""
    print("KIỂM TRA RSA KEY ARRAYS")
    print("=" * 50)
    
    modulus_ok = verify_modulus()
    exponent_ok = verify_exponent()
    verify_modulus_from_openssl()
    
    print("\n" + "=" * 50)
    print("KẾT QUẢ TỔNG QUAN:")
    
    if modulus_ok and exponent_ok:
        print("🎉 TẤT CẢ ARRAYS TRONG C FILE ĐỀU ĐÚNG!")
    else:
        print("⚠️  CÓ LỖI TRONG ARRAYS:")
        if not modulus_ok:
            print("   - RSA Modulus sai")
        if not exponent_ok:
            print("   - RSA Exponent sai")

if __name__ == "__main__":
    main()