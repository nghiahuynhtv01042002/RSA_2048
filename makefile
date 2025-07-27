CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -O2 -g
TARGET = rsa_verify_test
OBJS = bigint.o sha256.o rsa2048.o rsa_keys.o main.o

# Default target
all: keys $(TARGET)

# Generate RSA keys and signatures
keys: firmware.bin
	@echo "Generating RSA keys and signing firmware..."
	@chmod +x generate_keys.sh
	@./generate_keys.sh
	@echo "Converting keys and signature to C arrays..."
	@python3 convert_keys.py
	@echo "Keys generated and converted successfully!"

# Create dummy firmware if not exist
firmware.bin:
	@echo "Creating dummy firmware.bin for testing..."
	@dd if=/dev/urandom of=firmware.bin bs=1024 count=1 2>/dev/null || \
	 echo "This is a test firmware file" > firmware.bin

# Compile object files
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Link executable
$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) -o $(TARGET)

# Clean all build artifacts
clean:
	rm -f $(OBJS) $(TARGET) firmware.bin pubkey.h signature.h privkey.pem pubkey.pem signature.bin

.PHONY: all keys clean
