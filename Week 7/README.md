
# TLS Versions, RFCs, and Differences

## 1.1 TLS 1.1

- **RFC 4346**: [https://tools.ietf.org/html/rfc4346](https://tools.ietf.org/html/rfc4346)
- **Changes from TLS 1.0**:
  - Explicit Initialization Vectors (IVs) for CBC mode to prevent the "IV attack".
  - Improved error message handling.
  - Defined support for IANA registration of parameters for future use.
- **Mandatory Cipher Suites (TLS 1.1)**: At this time, there were no officially mandated suites, leading to potential compatibility issues.

## 1.2 TLS 1.2

- **RFC 5246**: [https://tools.ietf.org/html/rfc5246](https://tools.ietf.org/html/rfc5246)
- **Changes from TLS 1.1**:
  - Pseudorandom function (PRF) replaced MD5/SHA-1 combination in the key derivation process.
  - Added support for Authenticated Encryption with Additional Data (AEAD) cipher suites.
  - Specified hash algorithms used for signatures and other contexts.
  - Extensions mechanism defined.
- **Mandatory Cipher Suites (TLS 1.2)**: TLS_RSA_WITH_AES_128_CBC_SHA (later revisions may mandate others)

## 1.3 TLS 1.3

- **RFC 8446**: [https://tools.ietf.org/html/rfc8446](https://tools.ietf.org/html/rfc8446)
- **Changes from TLS 1.2**:
  - Major streamlining of the handshake for faster connection setup (often 1-RTT or even 0-RTT)
  - Removal of legacy cryptographic algorithms (RSA, RC4, DES, 3DES, MD5, SHA-224)
  - Separation of key agreement and authentication algorithms from cipher suites.
  - Encryption of handshake messages after the ServerHello.
- **Mandatory Cipher Suites (TLS 1.3)**:
  - TLS_AES_256_GCM_SHA384
  - TLS_AES_128_GCM_SHA256

## 1.4 Table of Differences

| Feature                  | TLS 1.1                           | TLS 1.2                           | TLS 1.3                                         |
|--------------------------|-----------------------------------|-----------------------------------|-------------------------------------------------|
| RFC Number               | RFC 4346                          | RFC 5246                          | RFC 8446                                        |
| Handshake Efficiency     | Slower (2-RTT common)              | Faster (1-RTT common)             | Fastest (1-RTT, 0-RTT possible)                 |
| Legacy Algorithm Support | Yes                               | Limited                           | None                                            |
| Cipher Suites            | Flexible                          | AEAD Introduced                   | Mandated, streamlined                          |
| Mandatory Cipher Suite   | None at time of RFC               | TLS_RSA_WITH_AES_128_CBC_SHA      | TLS_AES_256_GCM_SHA384 <br> TLS_AES_128_GCM_SHA256 |
| Security                 | Some weaknesses                   | Improved                          | Significantly Stronger                         |
