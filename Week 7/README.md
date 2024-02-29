# Week 7: TLS

### Task 1: Getting to know TLS versions

TLS 1.1

- **RFC 4346**: Introduced to address certain vulnerabilities found in TLS 1.0 and to improve the overall security of the protocol.
- **Changes from TLS 1.0**:
  - **Explicit Initialization Vectors (IVs)** for CBC mode to prevent the "IV attack", enhancing the security of block ciphers.
  - **Improved error message handling** to prevent information leaks and improve protocol negotiation.
  - **Defined support for IANA registration** of parameters for future use, ensuring better management of protocol extensions.
- **Mandatory Cipher Suites (TLS 1.1)**: At this time, there were no officially mandated suites, leading to potential compatibility issues. This lack of mandated suites highlighted the need for more standardized security requirements in future versions.

TLS 1.2

- **RFC 5246**: Marked a significant improvement over TLS 1.1, introducing stronger cryptographic primitives and more flexible protocol mechanisms.
- **Changes from TLS 1.1**:
  - **Pseudorandom function (PRF)** replaced the MD5/SHA-1 combination in the key derivation process, offering more robust security guarantees.
  - **Support for Authenticated Encryption with Additional Data (AEAD)** cipher suites was added, providing confidentiality, integrity, and authenticated encryption.
  - **Specified hash algorithms** used for signatures and other contexts, allowing for more secure and efficient cryptographic operations.
  - **Extensions mechanism defined**, enabling the protocol to be more easily updated and extended with new features.
- **Mandatory Cipher Suites (TLS 1.2)**: Introduced TLS_RSA_WITH_AES_128_CBC_SHA as a mandatory suite, setting a baseline for security requirements but later revisions may mandate others.

TLS 1.3

- **RFC 8446**: Represents a major overhaul of the protocol, focusing on streamlining the handshake process and removing outdated cryptographic features.
- **Changes from TLS 1.2**:
  - **Major streamlining of the handshake** for faster connection setup, allowing for 1-RTT (Round-Trip Time) or even 0-RTT connections, significantly improving performance.
  - **Removal of legacy cryptographic algorithms** such as RSA, RC4, DES, 3DES, MD5, and SHA-224, which were considered insecure or obsolete.
  - **Separation of key agreement and authentication algorithms** from cipher suites, simplifying the negotiation process and enhancing security.
  - **Encryption of all handshake messages** after the ServerHello, providing confidentiality and integrity protection for the handshake process itself.
- **Mandatory Cipher Suites (TLS 1.3)**:
  - **TLS_AES_256_GCM_SHA384** and **TLS_AES_128_GCM_SHA256**, mandating the use of modern, secure encryption methods.

Summary of Improvements

TLS 1.3 represents a significant advancement in the TLS protocol's security and efficiency. By streamlining the handshake process and adopting modern cryptographic standards, TLS 1.3 offers enhanced protection against eavesdropping and man-in-the-middle attacks. The removal of outdated algorithms and the introduction of mandatory cipher suites underscore the protocol's commitment to security. As the internet continues to evolve, the development of TLS reflects the ongoing effort to safeguard communications against emerging threats.

### Task 1.2 Table of Differences

| Feature                  | TLS 1.1                           | TLS 1.2                           | TLS 1.3                                         |
|--------------------------|-----------------------------------|-----------------------------------|-------------------------------------------------|
| RFC Number               | RFC 4346                          | RFC 5246                          | RFC 8446                                        |
| Handshake Efficiency     | Slower (2-RTT common)              | Faster (1-RTT common)             | Fastest (1-RTT, 0-RTT possible)                 |
| Legacy Algorithm Support | Yes                               | Limited                           | None                                            |
| Cipher Suites            | Flexible                          | AEAD Introduced                   | Mandated, streamlined                          |
| Mandatory Cipher Suite   | None at time of RFC               | TLS_RSA_WITH_AES_128_CBC_SHA      | TLS_AES_256_GCM_SHA384 <br> TLS_AES_128_GCM_SHA256 |
| Security                 | Some weaknesses                   | Improved                          | Significantly Stronger                         |
