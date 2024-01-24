# Week 2: Cryptographic security and block ciphers

### Task 1

- Using Python pycryptodome library

```
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad

def encrypt_aes_ecb(plaintext, key):
    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
    return ciphertext

def encrypt_aes_cbc(plaintext, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
    return ciphertext

def encrypt_aes_ctr(plaintext, key, nonce):
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
    ciphertext = cipher.encrypt(plaintext)
    return ciphertext

# Task 1.1
plaintext = b'\x00' * AES.block_size * 2  # Two identical blocks of all zeroes
key = get_random_bytes(16)  # 128-bit key

# ECB Encryption
ciphertext_ecb = encrypt_aes_ecb(plaintext, key)

# CBC Encryption
iv_cbc = get_random_bytes(AES.block_size)  # Initialization Vector
ciphertext_cbc = encrypt_aes_cbc(plaintext, key, iv_cbc)

# CTR Encryption
nonce_ctr = get_random_bytes(8)  # Nonce
ciphertext_ctr = encrypt_aes_ctr(plaintext, key, nonce_ctr)

# Comparing results
print("ECB Ciphertext:", ciphertext_ecb.hex())
print("CBC Ciphertext:", ciphertext_cbc.hex())
print("CTR Ciphertext:", ciphertext_ctr.hex())

```

- Results

