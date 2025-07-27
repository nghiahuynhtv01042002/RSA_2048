
src="test-rsa.c sha256\sha256.c rsakeys\rsa_keys.c rsa2048\rsa2048.c bigint\bigint.c"
inc="-I sha256 -I rsakeys -I rsa2048 -I bigint"
out="test-rsa"
gcc -o $out $src $inc