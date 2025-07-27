# Xác minh chữ ký số của firmware sử dụng RSA-2048

Xác minh chữ ký số của firmware sử dụng RSA-2048 là một quá trình quan trọng để đảm bảo tính toàn vẹn và xác thực của firmware trước khi nó được cập nhật hoặc chạy trên thiết bị. Dưới đây là giải thuật chi tiết để xác minh firmware với RSA-2048:

## 1. Giải thuật xác minh chữ ký RSA-2048

Giả sử ta có:

- **Firmware (dữ liệu gốc):** \( M \)
- **Chữ ký số của firmware:** \( S \) (được tạo ra bằng cách ký trên hash của \( M \) sử dụng private key RSA)
- **Public key RSA:** \( (e, n) \), với \( n \) là modulus 2048-bit (256 bytes).

### Các bước xác minh:

1. **Tính giá trị hash của firmware:**
   - Sử dụng hàm hash (thường là SHA-256) để tính giá trị hash của firmware \( M \):
      
      H = SHA-256(M)
   
   - Kích thước của \( H \) là 32 bytes.

2. **Giải mã chữ ký số bằng public key:**
   - Chữ ký \( S \) là một số lớn (256 bytes với RSA-2048).
   - Giải mã \( S \) bằng public key \( (e, n) \) để lấy giá trị hash được ký:
      
      H' = S^e \mod n
   
   - Kết quả \( H' \) là một số lớn, thường được mã hóa theo định dạng PKCS#1 v1.5 hoặc PSS.

3. **Trích xuất giá trị hash từ \( H' \):**
   - Theo chuẩn PKCS#1 v1.5, \( H' \) có cấu trúc:
     ```
     0x00 0x01 [Padding (0xFF...)] 0x00 [ASN.1 DigestInfo] [Hash]
     ```
   - Trong đó:
     - Phần `ASN.1 DigestInfo` mô tả thuật toán hash (ví dụ SHA-256).
     - Phần `Hash` (32 bytes cho SHA-256) là giá trị hash mà ta cần so sánh.

4. **So sánh giá trị hash:**
   - So sánh \( H \) (hash tính từ firmware) với phần `Hash` trích xuất từ \( H' \):

     H = {Hash\_extracted\_from}(H') ??

   - Nếu khớp, chữ ký hợp lệ → Firmware không bị sửa đổi và được xác thực.
   - Nếu không khớp, chữ ký không hợp lệ → Firmware có thể đã bị giả mạo hoặc hỏng.
  
``` c
 void mod_exp(BigNum *result, const BigNum *a, const BigNum *b, const BigNum *n) {
    BigNum base = *a;
    BigNum exp = *b;
    BigNum res;
    big_num_from_int(&res, 1); // res = 1
    while (!big_num_is_zero(&exp)) {
        if (big_num_is_odd(&exp)) {
            // res = (res * base) % n
            BigNum tmp;
            big_num_mul(&tmp, &res, &base);
            big_num_mod(&res, &tmp, n);
        }
        // base = (base * base) % n
        BigNum tmp;
        big_num_mul(&tmp, &base, &base);
        big_num_mod(&base, &tmp, n);
        // exp = exp / 2
        big_num_shr(&exp, 1);
    }
    *result = res;
}
```