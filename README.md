# RSA2048 Execution Draft Project

This repository is a **draft project** that demonstrates basic usage of **RSA2048** with **OpenSSL** and **bash scripting**.  
It shows how to generate keys, sign a firmware binary, and test verification.

## Requirements

- Linux / WSL / macOS environment with **bash**
- [OpenSSL](https://www.openssl.org/) installed

## Scripts
Run it with:

``` bash 
bash autobuild.sh
```

### 1. `generate_keys.sh`
This script:
- Generates a 2048-bit RSA private key
- Extracts the public key
- Signs a test binary (`firmware.bin`)
- Verifies the signature
- Extracts modulus and public exponent (for embedding in C code)

Run it with:

```bash
cd ./genkey
bash generate_keys.sh
python python convert_keys.py 
```
### 2. build_test-rsa.sh

This script is used to build and run RSA verification tests.
(Implementation is still in progress – draft only.)

Run it with:
```
bash build_test-rsa.sh
```
## Example Run
``` bash
 $ bash autobuild.sh 
Generating RSA private key...
Extracting public key...
writing RSA key
Signing firmware.bin...
Verifying signature...
Verified OK
Extracting modulus and exponent...
Extracting modulus as hex array...
Extracting exponent...
Done! Files created:
- private_key.pem: RSA private key
- public_key.pem: RSA public key
- firmware.sig: Signature file
- modulus.hex: Modulus in hex
- exponent.txt: Public exponent
Converting RSA data to C arrays...

Reading modulus.hex...
Reading exponent.txt...
Reading firmware.sig...
Writing rsa_keys.h...
Writing rsa_keys.c...
✅ Done.
[INFO] Opening firmware.bin...
[INFO] Firmware size = 121412 bytes
[DEBUG] First 32 bytes of firmware:
4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF 00 00 B8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00
[DEBUG] SHA256 of firmware:
1fff5f4e21064281480911f5a96479b12c2d42e04f8b7e5cd91bd27ab0e907c9
[INFO] Signature size: 256 bytes
[INFO] Modulus size: 256 bytes
[INFO] Public exponent: 65537
[INFO] Verifying firmware signature...
[SUCCESS] Firmware signature is VALID
``` 

## Notes

⚠️ This is only a draft project.