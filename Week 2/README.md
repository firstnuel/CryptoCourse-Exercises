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
- secp256r1: ` time openssl ecparam -name secp256r1 -genkey -noout -out private_ecdsa_secp256r1.pem`
- Curve25519: `time openssl ecparam -name Curve25519 -genkey -noout -out private_ecdsa_curve25519.pem`
  
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

4. Ease of Implementation:

- secp256r1: Implementing ECDSA with secp256r1 involves more complex arithmetic operations on prime fields.
- Curve25519: Implementing EdDSA with Curve25519 is often considered more straightforward due to the curve's specific structure, making it suitable for various platforms.

5. Performance:

- secp256r1: Depending on the implementation, the performance of ECDSA with secp256r1 can vary, and it may require more processing power.
- Curve25519: EdDSA with Curve25519 tends to have better performance in terms of both speed and efficiency.

Task 2.1.4

Based on the execution times for key generation commands using OpenSSL, I observed some differences in the time it takes to generate keys for different algorithms. To summarize the observations:

1. RSA Key Generation:

- Legacy Command (genrsa): 0.52 seconds
- Newer Command (genpkey): 16.012 seconds
  
There is a significant time difference between the legacy and newer commands for RSA key generation. The newer command likely involves additional operations or security measures, contributing to the increased time.

2. ECDSA Key Generation (secp256r1 curve):

- ecparam Command: 0.01 seconds

The ECDSA key generation using the ecparam command for the secp256r1 curve is relatively fast.

3. EdDSA Key Generation (Curve25519 curve):

- genpkey Command: 0.01 seconds

The EdDSA key generation using the genpkey command for the Curve25519 curve is also fast.

In summary, there are significant time differences between the RSA key generation methods (genrsa and genpkey). However, for elliptic curve algorithms (ECDSA and EdDSA), the key generation times are relatively low and comparable. The exact times can vary based on the specific hardware and system configurations.

Task 2.1.5

DSA (Digital Signature Algorithm) and its elliptic curve variant ECDSA (Elliptic Curve Digital Signature Algorithm) have been considered problematic or weak in certain scenarios due to various reasons:

1. Key Length and Security Margins:

- DSA and ECDSA rely on discrete logarithm problems for their security. The key length chosen significantly impacts security. In some cases, shorter key lengths were used for performance reasons, making them vulnerable to attacks.

2. Random Number Generation:

- The generation of random numbers is crucial in DSA and ECDSA. If the random number generation is flawed or predictable, it can lead to the compromise of private keys.

3. Deterministic Signatures:

- DSA and ECDSA signatures can be deterministic if the same private key and message are used, leading to potential risks in certain contexts.
Quantum Computing Threat:

Both DSA and ECDSA are susceptible to attacks by quantum computers, which could solve certain mathematical problems (e.g., discrete logarithms) exponentially faster than classical computers.
In contrast, EdDSA (Edwards-curve Digital Signature Algorithm) with the Ed25519 curve is considered a better alternative for several reasons:

1. Simplicity and Security:

- EdDSA is designed to be simpler and more secure. It uses a twisted Edwards curve (Curve25519), which offers strong security properties.

2. Efficiency:

- EdDSA is efficient both in terms of computational speed and key generation. It provides good performance without sacrificing security.

3. Deterministic Signatures:

- EdDSA signatures are naturally deterministic, which eliminates certain classes of implementation errors and potential vulnerabilities.

4. Resistance to Side-Channel Attacks:

- EdDSA implementations are resistant to various side-channel attacks, making them more secure in practical deployment scenarios.

5. Quantum Resistance:

- EdDSA is believed to be resistant to attacks by quantum computers due to the underlying mathematical structure.

For these reasons, EdDSA, especially when used with the Ed25519 curve, is considered a more modern and secure alternative to DSA and ECDSA in many applications. It addresses some of the weaknesses and challenges associated with the older algorithms.


- Generated keys
- genrsa (Legacy):
  
  ``MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAoHCRhKyu7Pzj1zMKaWGd
J7qXpUV96Xyor34dOeCkFplzB0vZl6u6px3mCPQn8HWV8zoEC/MfG5QZJhyJzT8I
NTUQpnioXOU4kgLBkMAgZB2jXmD0wqK0Q/7IR/pMgZXlCR4eoSzo5s58Jjm5jOsf
YDT0WLxNnOree2e7InswlLgyc2ocj+0uZA1mf8/KK3RLJc9ifFvzs071cimACo2r
C+RxH5Noj7iqqlmq7I9evQr31d/0kEWQKNyIhi0t7ftjWpsTjBC/b2K/W3FLLx9f
yTiMx1JX85B+J/EvgXduWEvAfBdiHMe5vxzSm8gKsCXnVVXnDsgUzRLJ4AjNliqe
qF65EY6erGtVEs4WOpDMTHEoMXAED8lkr93cb+7/WiF+VDr7UGGIryjPUCe9gRTe
XO4m6HGmI7q6+vPPSY4iSk9hbtLqRocWJ+b2IspBv4W7arC763TKqmyvzrELgqE9
jWNY+Yr6n7IPM4KeriRNT+sxLC/KuUiqfCel8yXJ/FZDExAay+wopg7mLRdVpWP0
oILTmD3GFsyctVZyS8tdC1nXEIBYXgGb1wgHFYHgjjjZMSucrESMi/lqfQui2sNr
fMCULg9eP8xUsvaAobBf55tiqw13D4UEszmdWiQ3+NJ2ZpeTeWC06djd9YJsxQJ+
q1H/293tK0E4+q+2EslWRhMCAwEAAQ==``
- genrsa (Newer):
  
  ``MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAs2si3aIqJGmhRtyYVj2X
Uci7EmD0zaZbWtsh1sHOob5AV6GKkgPTwLidvqL5JMq91P195MzM+qOvNjTgJi3m
u6Z7yReRBi8PZCtPg6LcQMJ6Eqqv6FfYF3QsQUuM2q2rRD2/JRTItTMfWXhC2ug9
82skM7ZIYQNCIXNxG8+VPFuQ8VU7U1bFQkiWnxFYy1+VCv2CXl7/Lerozel0A3RB
jDVMIpIfG8AHz/riI2mj7QuAlIJzM0v8fyvaahPqju6/eWKJxAQtdP3x3tydfs3w
YINDyt9balBeePfG2FVHcmSW48bN/ZsJ/LiosJNVq8G32xqMJORaT/SyLKPLw1Uu
qQIDAQAB``

- ECDSA (secp256r1):

  `MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEZTJ0Ozh3QSiD7Sk+0Vd87+Y5hCQA
9FurI18WaB4kuwawR0g9XZZhDIs9SGhyfPddi80G2kPgYFs98fkInafySA==`

- EdDSA (Ed25519):
  
   `MCowBQYDK2VwAyEAGEua52QW4ayM7+51KibrJGd/WtF7X88PLtLx0rYYBKA=`
  
  ----
