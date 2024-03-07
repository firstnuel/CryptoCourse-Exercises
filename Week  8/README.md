# Week 8: Quantum computing
### Task 1: Feedback on the course

What did you like about the lectures?

- I liked the way the course was structured into weekly quizes that reflects the weekly lectuers and hands-on practice through the exercises.
  
What would you improve on the lectures?

- Overall I would say it was satisfactory but maybe a little more guide will help in tackling the exercises.
  
What did you like about the exercises?

- It was challenging but also provided a good learning and practice medium.
  
How would you improve the exercises?

- If it could be a litlle bit easier in my opinion.
  
Did you miss some type of an exercise or some content as an exercise?

- Not really.
  
What was missing from the course (i.e. what more would you have wanted from the course)?

- Nothing in my opinion.
  
What was the worst part of the course in your opinion?

- The book was quite large to study with for the time frame that we had.
  
Freeform feedback on the course

- None.

### Task 3:

3.1 Post-Quantum Cryptography Finalists Overview
The National Institute of Standards and Technology (NIST) has selected several finalists for its Post-Quantum Cryptography Standardization Process. These include algorithms for public-key encryption, key encapsulation mechanisms (KEMs), and digital signatures aimed at securing communications against the threat posed by quantum computing.

Hard Problems Basis

- CRYSTALS-KYBER: Public-key encryption/KEM, based on the hardness of lattice-based problems.
- CRYSTALS-DILITHIUM, FALCON, and SPHINCS+: Digital signatures. CRYSTALS-DILITHIUM and FALCON are based on lattice-based cryptography, while SPHINCS+ is a hash-based signature scheme.

Security Levels

The candidates are aiming for varying security levels as defined by NIST, which include measures to ensure the algorithms are secure against both classical and quantum attacks. The specific security levels aimed for by each algorithm can be detailed in NIST's publications, which categorize security strength similar to or better than current standards like AES and SHA-3 against quantum computing threats.

Parameter Sizes and Performance Metrics

Parameter sizes, key sizes, signature sizes, and performance metrics such as key generation time, signature generation time, and verification time for these algorithms are detailed in technical documents provided by NIST. These parameters are crucial for assessing the practicality and efficiency of implementing these algorithms in real-world systems.

3.2 Implementations and Support

Several systems, libraries, and applications have begun to support post-quantum cryptography algorithms:

- Entrust has announced support for the three digital signature algorithms moving forward in the competition through its PKI as a Service (PKIaaS)​​.

- Keyfactor mentions the latest version of SPHINCS+ and other Round 4 candidates like SIKE and Classic McEliece, indicating integration into SaaS-delivered PKI and certificate management solutions​​.

The decision to support specific post-quantum algorithms often stems from a desire to be at the forefront of cryptographic security, addressing the quantum threat, and meeting customer and regulatory requirements for future-proof encryption.

Refrences
- [Entrust: NIST POST-QUANTUM COMPETITION](https://www.entrust.com/blog/2022/08/nist-post-quantum-competition-and-the-round-3-finalists-are/)
- [KeyFactor: NIST Announces Round 3 Finalists for Post-Quantum Cryptography Competition](https://www.keyfactor.com/blog/nist-announces-round-3-finalists-for-post-quantum-cryptography-competition/)

### Task 3: (Option 2)
Security Level Analysis of WireGuard VPN

### Introduction

WireGuard is a cutting-edge VPN protocol that offers state-of-the-art cryptographic features with a focus on simplicity and performance. Unlike traditional VPN protocols, which can be complex and difficult to configure, WireGuard is designed to be easy to deploy and manage, making secure networking accessible to a wider audience. It is intended for use in various applications, from personal VPN services to securing corporate networks. The reason for selecting WireGuard is its innovative approach to VPN technology, combining modern cryptography with a lean codebase for improved security and speed.

### Cryptography

1. Protected Data: WireGuard protects all data in transit, including internet traffic, personal data, and metadata, ensuring confidentiality, integrity, and authenticity between client and server.
2. Algorithms Used:
  
- Encryption: ChaCha20 for symmetric encryption, providing strong confidentiality.
- Authentication: Poly1305 for message authentication, ensuring data integrity and authenticity.
- Key Exchange: Curve25519 for Elliptic Curve Diffie-Hellman (ECDH), facilitating secure key agreement.
- Hashing: BLAKE2s for hashing and keyed hashing operations, used in various protocol functions.
  
3. Key Lengths: ChaCha20 (256-bit keys), Curve25519 (providing security equivalent to ECDH with 3072-bit keys), and Poly1305 (128-bit keys).

4. Arguments for Cryptographic Choices: The selection of these cryptographic algorithms is based on their high performance, strong security properties, and resistance to timing attacks. WireGuard's simplicity and the use of modern cryptographic standards aim to reduce the attack surface, making the VPN protocol more secure and easier to audit.

### Analysis

WireGuard provides a high level of security for VPN users through its use of efficient and well-regarded cryptographic primitives. Its streamlined protocol design minimizes complexity, which often leads to fewer security vulnerabilities.

The cryptographic algorithms selected for WireGuard are considered secure by current standards and offer a good balance between performance and cryptographic strength. There is a strong emphasis on forward secrecy through the use of ephemeral keys.

Improvements in WireGuard's security could potentially focus on incorporating features like dynamic address management to enhance user privacy further. Additionally, ongoing research into post-quantum cryptography could be relevant for future versions to ensure long-term security against quantum computing threats.

References
- Donenfeld, J. A. (2017). WireGuard: Next Generation Kernel Network Tunnel. NDSS Symposium 2017.
- WireGuard. (2021). WireGuard Protocol Documentation.
- Bernstein, D. J., et al. (2012). ChaCha20 and Poly1305 for IETF Protocols.
