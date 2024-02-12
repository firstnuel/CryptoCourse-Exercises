# Week 5: Hard problems and RSA

### Task 1: RSA encryption and signatures with OpenSSL

Task 1.1
- [Generated Key(public)](./public_key.pem)

  `MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsb5mhs7f8m8KbbD0i+R9
XeYlXbFpiP7GzE+OyCtBR1E54mEmHt8j/WbktonXIPoR0GPN4eeOvnuvacPwHHU2
aR4Vgxo5fBUgaNXXz+liTip6ojl0wR9AyljhhXZrcCNnA6KxZe6Ppq3aW7TRXm8q
GjV2ESk+3f2zlyGnTlxYlopclhnK9KHs/R17wxfBORgTt3WSSb4ijgoepLP8rKtS
cLVy99mYfQaIUnL1GhZmTiwJAro+sTvSCt0Z4A1T1N/AkeAYB0gJ3jYJie8/zrZj
BH318j97uhCXe/u1DUeuC1OY1hFh3PDL0ksiXX4yTwPRCKeDhtTUC8ATS5BpoYVt
YwIDAQAB`

- Message : "Hello, Emmanuel!"
- Command used to generate keys
  
  `openssl genpkey -algorithm RSA -out private_key.pem -pkeyopt rsa_keygen_bits:2048`
  
  `openssl rsa -pubout -in private_key.pem -out public_key.pem`

- [Encrypted Message](./encrypted_message.bin)
- Command used to encrypt message(message was stored in a message.txt file)

  `openssl pkeyutl -encrypt -inkey public_key.pem -pubin -in message.txt -out encrypted_message.bin`

Task 1.2
- 
