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

References:

1. https://www.a10networks.com/glossary/key-differences-between-tls-1-2-and-tls-1-3/
2. https://www.wolfssl.com/a-comparison-of-differences-in-tls-1-1-and-tls-1-2/ 
-------
# Task 2

## Task 2.1

According to  my findings, TLS 1.2 has the most listed vulnerabilities. 

## Task 2.2

| Vulnerability | TLS 1.1 | TLS 1.2 | TLS 1.3 |
|---------------|---------|---------|---------|
| Name | CVE-2022-23408 (9.1 - Critical) | CVE-2022-23408 (9.1 - Critical) - Same as TLS 1.1|CVE-2021-22901 (8.1 - High)|
| How does the vulnerability work? | The vulnerability occurs in wolfSSL versions 5.x before 5.1.1 due to the use of non-random Initialization Vector (IV) values in certain situations. This affects connections using AES-CBC or DES3 with TLS 1.1 or 1.2 or DTLS 1.1 or 1.2. The issue stems from misplaced memory initialization in the BuildMessage function in internal.c. | Same as TLS 1.1 | The vulnerability exists in versions of curl from 7.75.0 through 7.76.1 and stems from a use-after-free flaw. Specifically, when a TLS 1.3 session ticket arrives over a connection, already freed memory can be utilized. This could potentially lead to remote code execution if exploited by a malicious server. |
| What cryptographic primitive (if any) is affected? | The vulnerability affects the Initialization Vector (IV) used in connections utilizing AES-CBC or DES3 encryption algorithms within the TLS 1.1 or 1.2 protocols. | Same as TLS 1.1 | This affects the TLS 1.3 session ticket handling mechanism in the curl library. | Appears at the implementation level, specifically within the code of the curl library. |
| At what level of abstraction does the vulnerability appear? | At the implementation level, specifically within the wolfSSL library's code. | Same as TLS 1.1 | This vulnerability impacts applications that use the affected versions of the curl library for performing HTTP requests and handling TLS connections. | 
| What types of applications does it impact? | Applications that use the wolfSSL library for TLS encryption and utilize AES-CBC or DES3 encryption algorithms within TLS 1.1 or 1.2 connections. | Same as TLS 1.1 | This vulnerability impacts applications that use the affected versions of the curl library for performing HTTP requests and handling TLS connections. |
| Can you find tools/code from the Internet that implement this attack? | Couldn't find any code implementing the vulnerability | Same as TLS 1.1 | I found a report on https://hackerone.com/reports/1180380 |
| Is there any news on this vulnerability being used in some data breach/attack? | No | No | No |

## Task 2.3

| Vulnerability | TLS 1.1 | TLS 1.2 | TLS 1.3 |
|---------------|---------|---------|---------|
| Name | CVE-2024-23656 | CVE-2023-6129 | CVE-2023-6129 - Same as TLS 1.2|
| How does the vulnerability work? | Dex, an identity service using OpenID Connect for authentication, serves HTTPS with insecure TLS 1.0 and TLS 1.1. Although cmd/dex/serve.go line 425 seemingly sets TLS 1.2 as the minimum version, the entire tlsConfig is ignored after the introduction of TLS cert reloader in v2.37.0. This results in TLS 1.0 and TLS 1.1 being used instead of TLS 1.2, exposing the application to security risks associated with weaker encryption. | exists in the POLY1305 MAC (message authentication code) implementation used by OpenSSL on PowerPC CPU-based platforms. The issue arises from a bug in how the POLY1305 MAC algorithm handles vector registers, leading to a potential corruption of the internal state of applications running on these platforms. Specifically, the implementation restores the contents of vector registers in a different order than they are saved, resulting in corruption of some of these registers when returning to the caller. | Same as TLS 1.2 |
| What cryptographic primitive (if any) is affected? | Inadequate encryption strength | This affects the POLY1305 MAC algorithm, which is a cryptographic primitive used for message authentication. | 
| At what level of abstraction does the vulnerability appear? | At the implementation level within the code of the Dex application, specifically in the handling of TLS configurations. | The vulnerability appears at the implementation level within the OpenSSL library, specifically in how the POLY1305 MAC algorithm is implemented and interacts with vector registers on PowerPC CPU-based platforms. | 
| What types of applications does it impact? | Applications that use the Dex identity service for authentication and serve content over HTTPS. Any applications relying on Dex versions 2.37.0 or earlier are susceptible to this issue. | Applications utilizing OpenSSL versions 3.0.0 to 3.0.12 or versions 3.1.0 to 3.1.4 on PowerPC CPU-based platforms are impacted by this vulnerability. This includes applications that utilize OpenSSL for secure communications, cryptographic operations, and other security-related functionalities. | 
| Can you find tools/code from the Internet that implement this attack? | Couldn't find any code implementing the vulnerability. | Couldn't find any code implementing the vulnerability. |
| Is there any news on this vulnerability being used in some data breach/attack? | No | No | No |

----------

# Task 3

## Task 3.1 

I chose to test the given website https://tlstest.rahtiapp.fi/. The terminal outputs are as follows.

```terminal 
arch@archlinux ~/Documents/crypto/ex7 % openssl s_client -connect tlstest.rahtiapp.fi:443 -tls1
Connecting to 193.167.189.101
CONNECTED(00000003)
4017E1CF9D7F0000:error:0A0000BF:SSL routines:tls_setup_handshake:no protocols available:ssl/statem/statem_lib.c:153:
---
no peer certificate available
---
No client certificate CA names sent
---
SSL handshake has read 0 bytes and written 7 bytes
Verification: OK
---
New, (NONE), Cipher is (NONE)
This TLS version forbids renegotiation.
Compression: NONE
Expansion: NONE
No ALPN negotiated
Early data was not sent
Verify return code: 0 (ok)
---
1 arch@archlinux ~/Documents/crypto/ex7 % openssl s_client -connect tlstest.rahtiapp.fi:443 -tls1_1
Connecting to 193.167.189.101
CONNECTED(00000003)
40A75BE28B7F0000:error:0A0000BF:SSL routines:tls_setup_handshake:no protocols available:ssl/statem/statem_lib.c:153:
---
no peer certificate available
---
No client certificate CA names sent
---
SSL handshake has read 0 bytes and written 7 bytes
Verification: OK
---
New, (NONE), Cipher is (NONE)
This TLS version forbids renegotiation.
Compression: NONE
Expansion: NONE
No ALPN negotiated
Early data was not sent
Verify return code: 0 (ok)
---
1 arch@archlinux ~/Documents/crypto/ex7 % openssl s_client -connect tlstest.rahtiapp.fi:443 -tls1_2
Connecting to 193.167.189.101
CONNECTED(00000003)
depth=2 C=US, O=Internet Security Research Group, CN=ISRG Root X1
verify return:1
depth=1 C=US, O=Let's Encrypt, CN=R3
verify return:1
depth=0 CN=tlstest.rahtiapp.fi
verify return:1
---
Certificate chain
 0 s:CN=tlstest.rahtiapp.fi
   i:C=US, O=Let's Encrypt, CN=R3
   a:PKEY: rsaEncryption, 4096 (bit); sigalg: RSA-SHA256
   v:NotBefore: Feb 21 15:09:33 2024 GMT; NotAfter: May 21 15:09:32 2024 GMT
 1 s:C=US, O=Let's Encrypt, CN=R3
   i:C=US, O=Internet Security Research Group, CN=ISRG Root X1
   a:PKEY: rsaEncryption, 2048 (bit); sigalg: RSA-SHA256
   v:NotBefore: Sep  4 00:00:00 2020 GMT; NotAfter: Sep 15 16:00:00 2025 GMT
---
Server certificate
-----BEGIN CERTIFICATE-----
MIIF8TCCBNmgAwIBAgISBIYaWo3mQpYrtyvX7Zj/E6/TMA0GCSqGSIb3DQEBCwUA
MDIxCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1MZXQncyBFbmNyeXB0MQswCQYDVQQD
EwJSMzAeFw0yNDAyMjExNTA5MzNaFw0yNDA1MjExNTA5MzJaMB4xHDAaBgNVBAMT
E3Rsc3Rlc3QucmFodGlhcHAuZmkwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIK
AoICAQC+F6oH+X9991qtaCm3R7oVoCkkrSQsQrUxafNkJNs1Y1oHoHymprGAfP6c
22/1tnqm7UtZQAwH6bJ0T61gs/8DLYEg+/C6vN5lBD17WeobIL1q9IHPKjXFcGe1
OQbxkMXUKPmOSSqgrlIdYyS8U4KN7R1rFO1GMK+9Ynk8gNTHRArCZgmCDyg0j4F+
dP9HqCr99FrFyMYB5vjm8PFqOjE6HtGhpLC2xEGwOgGfp7g3BGihyUVEFfJFpQzM
FsDjnupB74wbZqxXsGSxOan6RWOGpO002gaWoZ/ZG8H/SbCs6sIC4UHne5a/U2SE
b8tSWVly0X2t7xbkvezW4UvaVwsfOqkeBcZFrptNRORHVVFhl9C7R0fI0xZe4yLG
xXX1llqwcJtelqFiddXEv8pJuVjm0y1mfBUh9rdkzgoJudbw7QmBx+g297fZDbTA
92K6jO/5jJheVhdRQelBqc++JcLyE02jwAoukJNMsJxLEzMQPBq7pVOAzG9P84io
Bj9lkMWY/89nMSlVxNHyBRsN/fSepLi4YO2DFdzqadQkg5CQC/hvSvY7HeEbtuOF
2zXgEju6xJID2xf+oq/T91R9Js+NyrSSEjkX3X3PDKeKNHsH7ZZtvusU1eXbQwtM
kEsZNd9NburM7eRDAsu5S2oHcZRQU7/ujezWJuF5BObRAGqoKwIDAQABo4ICEzCC
Ag8wDgYDVR0PAQH/BAQDAgWgMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcD
AjAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBSeariyvZM/3YlivtjzBU8VaWIxFTAf
BgNVHSMEGDAWgBQULrMXt1hWy65QCUDmH6+dixTCxjBVBggrBgEFBQcBAQRJMEcw
IQYIKwYBBQUHMAGGFWh0dHA6Ly9yMy5vLmxlbmNyLm9yZzAiBggrBgEFBQcwAoYW
aHR0cDovL3IzLmkubGVuY3Iub3JnLzAeBgNVHREEFzAVghN0bHN0ZXN0LnJhaHRp
YXBwLmZpMBMGA1UdIAQMMAowCAYGZ4EMAQIBMIIBAgYKKwYBBAHWeQIEAgSB8wSB
8ADuAHUAO1N3dT4tuYBOizBbBv5AO2fYT8P0x70ADS1yb+H61BcAAAGNzG3wnAAA
BAMARjBEAiBC/l/U/jyP9iPu4GPFMKHS9iwueMkay7/8M0vtNa+0wQIgA2TwurCm
+aR6vWmgajDmMB9k0c87uDkTdermT7RoWdoAdQCi4r/WHt4vLweg1k5tN6fcZUOw
xrUuotq3iviabfUX2AAAAY3MbfC+AAAEAwBGMEQCIDqsxw/JsqDWJ96VdfTEy7E1
7jJ4vKl2o6XoykxdahLEAiBGbx8J0mUZL98N2VAqUQIgj2wqnj/d03foI5DOjJ/Z
ujANBgkqhkiG9w0BAQsFAAOCAQEARq5RFkT/ixYymG8CsM6tOWmbbrIIFWch7Sxy
wsAcKBbHEDZGxM2rXdT9hwThbK3lP+xYcmnNjiC07x/hjscxQKqyjYlYHREy5/zF
7TTrn4RrjldljGXv1nYFzJFCduxZVLQ4UDVsf/47MIxoCp+GtQ5a8tGIdE+G13Hn
aGE0aUjeH0ATt1sb6pdEE3yHgllwcNSOWrQ9o1j5YVUcy6vSHIUy2DCIppmxOMjO
1qhbahvtSRAfMdFfNbZD0pMLAxXcgLfKMwkAZB7+/emNj4bxbyzs3+d/XkKEfVn1
vU/OKlpo3/gJT0iS3lbGrSi/wN4R9YozCZDRFzySKucj63EHqQ==
-----END CERTIFICATE-----
subject=CN=tlstest.rahtiapp.fi
issuer=C=US, O=Let's Encrypt, CN=R3
---
No client certificate CA names sent
Peer signing digest: SHA256
Peer signature type: RSA
Server Temp Key: ECDH, prime256v1, 256 bits
---
SSL handshake has read 3760 bytes and written 348 bytes
Verification: OK
---
New, TLSv1.2, Cipher is ECDHE-RSA-AES256-GCM-SHA384
Server public key is 4096 bit
Secure Renegotiation IS supported
Compression: NONE
Expansion: NONE
No ALPN negotiated
SSL-Session:
    Protocol  : TLSv1.2
    Cipher    : ECDHE-RSA-AES256-GCM-SHA384
    Session-ID: 27DF5A5A182A0DC842047A4B4FD3D498C69CD65F12AAAD14A0B962C0BEEB8208
    Session-ID-ctx: 
    Master-Key: 2E96C8E7C2826F6C4640CF3ACDEBA45044845B7840C3C4CFD8B4B944D06677261CA727705C3D6C120E082B6108B49C93
    PSK identity: None
    PSK identity hint: None
    SRP username: None
    TLS session ticket lifetime hint: 300 (seconds)
    TLS session ticket:
    0000 - b1 65 7b df a4 db 23 63-01 e8 aa 3a ac 05 e1 a9   .e{...#c...:....
    0010 - 7c 72 41 ce d9 a4 a2 76-13 5a e6 c1 00 a7 fb 2a   |rA....v.Z.....*
    0020 - 31 f0 53 f4 9a 7f 18 42-01 05 fb 95 ab 35 5f 54   1.S....B.....5_T
    0030 - 73 6b 4d ba c2 e4 57 4d-62 96 a4 e4 5b 4f 0d ed   skM...WMb...[O..
    0040 - 48 34 07 cf 1a 34 db 0d-02 89 09 ee b9 4e 99 96   H4...4.......N..
    0050 - 81 7c 79 fc 8c 4d 61 33-ab ba 36 ea 65 ab ca 89   .|y..Ma3..6.e...
    0060 - a1 d6 a0 8f f4 12 a0 fe-44 e0 2e c7 5d 41 cd 7e   ........D...]A.~
    0070 - 27 57 ba ff 3b 3f d9 5b-89 ee 2e 40 79 39 72 c0   'W..;?.[...@y9r.
    0080 - 0a cf 7c 5c a8 98 aa 22-f5 b3 e0 6d 08 5e 36 63   ..|\..."...m.^6c
    0090 - b6 82 67 74 95 93 55 22-f8 55 e7 b7 76 f1 4f fd   ..gt..U".U..v.O.
    00a0 - 9e 98 69 b2 a1 ea 72 47-65 b3 ee 97 c5 b5 da c5   ..i...rGe.......

    Start Time: 1709229918
    Timeout   : 7200 (sec)
    Verify return code: 0 (ok)
    Extended master secret: no
---
400710213C7F0000:error:0A000126:SSL routines::unexpected eof while reading:ssl/record/rec_layer_s3.c:641:
1 arch@archlinux ~/Documents/crypto/ex7 % openssl s_client -connect tlstest.rahtiapp.fi:443 -tls1_3
Connecting to 193.167.189.101
CONNECTED(00000003)
40576AC1517F0000:error:0A000410:SSL routines:ssl3_read_bytes:ssl/tls alert handshake failure:ssl/record/rec_layer_s3.c:861:SSL alert number 40
---
no peer certificate available
---
No client certificate CA names sent
---
SSL handshake has read 7 bytes and written 257 bytes
Verification: OK
---
New, (NONE), Cipher is (NONE)
This TLS version forbids renegotiation.
Compression: NONE
Expansion: NONE
No ALPN negotiated
Early data was not sent
Verify return code: 0 (ok)
---
1 arch@archlinux ~/Documents/crypto/ex7 % 
```

- The only supported TLS version is TLS 1.2. 
- The supported cipher suite is `ECDHE-RSA-AES256-GCM-SHA384`. 

## Task 3.3


The vulnerabilities reported are mentioned below in table. These vulnerabilities did not come across in earlier tasks.  

| Vulnerability | Severity | What does it allows attackers to do? |
|---------------|----------|--------------------------------------|
| CVE-2014-0160 | 7.5 High | Retrieving sensitive information from the memory of the affected system, such as private keys, user credentials, and other potentially confidential data. |
| CVE-2015-0204 | N/A | Allows remote SSL servers to conduct RSA-to-EXPORT_RSA downgrade attacks and facilitate brute-force decryption by offering a weak ephemeral RSA key in a noncompliant role, related to the "FREAK" issue. |
| CVE-2015-4000 | 3.7 Low | Allows man-in-the-middle attackers to conduct cipher-downgrade attacks. |
| CVE-2013-2566 | 5.99 Medium | It makes easier for remote attackers to conduct plaintext-recovery attacks via statistical analysis of ciphertext in a large number of sessions that use the same plaintext |


