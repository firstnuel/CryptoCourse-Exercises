# Week 2: Cryptographic security and block ciphers

### Task 1: Modes of operations in block ciphers

Task 1.1:
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
![ss1](https://github.com/firstnuel/CryptoCourse-Exercises/blob/main/Week%202/sc1.png)

- Explanation:

- In the ECB (Electronic Codebook) mode of encryption, identical blocks of plaintext will always encrypt to identical ciphertext blocks. This means that there is no diffusion of patterns in the encrypted data

- In the CBC (Cipher Block Chaining) mode of encryption, each block of plaintext is XORed with the previous ciphertext block before being encrypted. This ensures that identical plaintext blocks encrypt to different ciphertext blocks, thus diffusing patterns in the encrypted data. Additionally, an Initialization Vector (IV) is introduced to add randomness to the encryption process
  
- In the CTR (Counter) mode of encryption, a unique key stream is produced for each block by using a nonce (number used once) and a counter. The nonce and counter are combined to form the input to the cipher. The counter is initially set to zero and then incremented for every block encryption. The resulting output is XORed with the plaintext to produce the ciphertext 1

The nonce and salt are not the same. A nonce is typically used in conjunction with a counter (as in CTR mode) to ensure uniqueness, while a salt is used in password hashing to prevent rainbow table attacks.

Task 1.2:
- ECB mode does not provide semantic security, as patterns in plaintext are visible in the ciphertext.
  
- CBC mode provides better security than ECB, as the encryption of each block depends on the previous one.
  
- CTR mode provides parallelization and is not susceptible to the same padding oracle attacks as CBC.


Task 1.3:

- ECB and CBC introduce additional blocks for padding, making the ciphertext longer than the plaintext.
- CTR does not introduce additional blocks, so the ciphertext length is the same as the plaintext length.
