openssl dgst -sha256 ./genkey/firmware.bin
gcc -o checksha checksha.c ./sha256/sha256.c -I ./sha256
./checksha