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
## Notes

⚠️ This is only a draft project.