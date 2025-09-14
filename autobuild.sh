cd ./genkey
# generate firmare binary file
gcc -o firmware.bin firmware.c
# generate public keys and private key 
./generate_keys.sh
# extract public keys and private key to header c file
python convert_keys.py 

cd ..
# Build test-rsa
./build_test-rsa.sh
#run test
./test-rsa.exe