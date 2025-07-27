#!/bin/bash

# Tạo RSA private key 2048-bit
echo "Generating RSA private key..."
openssl genrsa -out private_key.pem 2048

# Tạo public key từ private key
echo "Extracting public key..."
openssl rsa -in private_key.pem -pubout -out public_key.pem

# Tạo chữ ký cho firmware.bin (SHA-256 + RSA)
echo "Signing firmware.bin..."
openssl dgst -sha256 -sign private_key.pem -out firmware.sig firmware.bin

# Verify chữ ký (để test)
echo "Verifying signature..."
openssl dgst -sha256 -verify public_key.pem -signature firmware.sig firmware.bin

# Extract modulus và public exponent thành hex format
echo "Extracting modulus and exponent..."
openssl rsa -in public_key.pem -pubin -text -noout > key_info.txt

# Extract modulus (bỏ ":" và newlines)
echo "Extracting modulus as hex array..."
openssl rsa -in public_key.pem -pubin -modulus -noout | sed 's/Modulus=//' > modulus.hex

# Extract exponent 
echo "Extracting exponent..."
openssl rsa -in public_key.pem -pubin -text -noout | grep "Exponent:" | awk '{print $2}' > exponent.txt

echo "Done! Files created:"
echo "- private_key.pem: RSA private key"
echo "- public_key.pem: RSA public key"  
echo "- firmware.sig: Signature file"
echo "- modulus.hex: Modulus in hex"
echo "- exponent.txt: Public exponent"