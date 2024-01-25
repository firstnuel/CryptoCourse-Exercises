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

----
### Task 2: Key generation

Task 2.1.1

The comparison of the results and the time taken for RSA key generation using OpenSSL's genrsa and genpkey commands reveals some differences:

1. Execution Time:

- genrsa (Legacy): 0.585 seconds
- genpkey (Newer): 16.012 seconds
  
The newer genpkey command took significantly more time compared to the legacy genrsa command. This increase in execution time could be attributed to additional operations or features introduced in the newer command.

2. Key Format:

- genrsa (Legacy): Generates a traditional unencrypted RSA private key.
- genpkey (Newer): Generates an encrypted RSA private key using AES-256.
  
The newer genpkey command by default generates an encrypted private key, adding a layer of security by requiring a passphrase for decryption. This can be an advantage in certain security contexts.

3. Public Key Extraction:

- Both legacy and newer commands support extracting the public key from the generated private key.
  
Conclusion:

The choice between genrsa and genpkey depends on specific requirements. If the key generation time is a critical factor and an encrypted private key is not needed, the legacy genrsa command might be preferred.
If enhanced security features such as encrypted private keys are required, the newer genpkey command is a suitable choice.

For ECDSA, Here are some observations
1. ECDSA (secp256r1):

- The private key is generated using the secp256r1 elliptic curve.
- The public key is derived from the private key.
  
2. EdDSA (Ed25519):

- The private key is generated using the Ed25519 elliptic curve.
- The public key is derived from the private key.
  
Comparison:

- Both ECDSA and EdDSA are elliptic curve digital signature algorithms, but they use different elliptic curves (secp256r1 for ECDSA and Ed25519 for EdDSA).
- Ed25519 is generally considered more secure and efficient than many other signature algorithms, including secp256r1. It provides strong security with shorter key lengths.
- The key generation times for both algorithms are relatively fast, with EdDSA (Ed25519) being slightly faster in this case.
It's important to note that the choice between ECDSA and EdDSA may depend on specific use cases, security considerations, and compatibility requirements. In practice, Ed25519 is often preferred due to its security properties and efficiency.

Task 2.1.2
- Legacy (genrsa): ``time openssl genrsa -out private_rsa_key_legacy.pem 4096``
- Newer (genpkey): ``time openssl genpkey -algorithm RSA -out private_rsa_key_new.pem -aes256``

Task 2.1.3

The curves secp256r1 (used in ECDSA) and Curve25519 (used in EdDSA) are different elliptic curves with distinct properties. Here are some practical differences between them:

1. Curve Shape:

- secp256r1: It is a NIST elliptic curve with a 256-bit prime modulus. The curve is defined over a prime field.
- Curve25519: It is a Montgomery curve with a prime order of 2^255 - 19. The curve is designed to be efficient and secure, particularly for use in cryptographic protocols.

2. Efficiency:

- secp256r1: ECDSA with secp256r1 requires more computational resources compared to EdDSA with Curve25519. The operations on prime fields (common in ECDSA) can be more computationally expensive.
- Curve25519: It is designed to be efficient, especially on devices with limited resources. The curve's structure allows for faster computations.
  
3. Security:

- secp256r1: It is considered secure and has been widely used in practice. However, concerns have been raised about the NIST curves and their potential vulnerabilities to certain types of attacks.
- Curve25519: It is designed to offer a high level of security. The curve's structure and choice of parameters aim to mitigate potential vulnerabilities found in other curves.

4.Ease of Implementation:

- secp256r1: Implementing ECDSA with secp256r1 involves more complex arithmetic operations on prime fields.
- Curve25519: Implementing EdDSA with Curve25519 is often considered more straightforward due to the curve's specific structure, making it suitable for various platforms.

5. Performance:

- secp256r1: Depending on the implementation, the performance of ECDSA with secp256r1 can vary, and it may require more processing power.
- Curve25519: EdDSA with Curve25519 tends to have better performance in terms of both speed and efficiency.
