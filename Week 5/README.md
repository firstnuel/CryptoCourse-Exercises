# Week 5: Hard problems and RSA

### Task 1: RSA encryption and signatures with OpenSSL

Task 1.1
- [Generated Key(public)](./public_key.pem)
- Message : "Hello, Emmanuel!"
- Command used to generate keys
  
  `openssl genpkey -algorithm RSA -out private_key.pem -pkeyopt rsa_keygen_bits:2048`
  
  `openssl rsa -pubout -in private_key.pem -out public_key.pem`

- [Encrypted Message](./encrypted_message.bin)
- Command used to encrypt message(message was stored in a message.txt file)

  `openssl pkeyutl -encrypt -inkey public_key.pem -pubin -in message.txt -out encrypted_message.bin`

Task 1.2
- [Generated Key(public)](./public_key.pem)
- Message : "Hello, Emmanuel!"
- [Generated Signature](./signature.sign)
- Commands used to generate the signature.

  `openssl dgst -sha256 -sign private_key.pem -out signature.sign message.txt/`
