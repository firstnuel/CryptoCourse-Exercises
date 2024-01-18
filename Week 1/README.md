# Week 1: Encryption and randomness

### Task 1.1 Produce a ciphertext that will decode into "No Rauli" under the same secret one-time pad as the original ciphertext was produced.
- "Hi Kimmo" in binary: 

$$ 01001000_\ 01101001_\ 00100000_\ 01001011_\ 01101001_\ 01101101_\ 01101101_\ 01101111 = P_1$$

- "No Rauli" in binary:

$$01001110_\ 01101111_\ 00100000_\ 01010010_\ 01100001_\ 01110101_\ 01101100_\ 01101001 = P_2$$

- The XOR between of two plaintexts is:

$$00000110_\ 00000110_\ 00000000_\ 00011001_\ 00001000_\ 00011000_\ 00000001_\ 00000110 = X$$

This should be equal to the XOR of the cipher of "No Rauli" and the cipher of "No Kimmo". Therefore XOR between them 

00000110_\ 00000110_\ 00000000_\ 00011001_\ 00001000_\ 00011000_\ 00000001_\ 00000110 = X
01101001_\ 00010101_\ 01011111_\ 01001110_\ 00100000_\ 00011100_\ 10101101_\ 01100001 = C_1
XOR
01101111_\ 00010011_\ 01011111_\ 01010111_\ 00101000_\ 00000100_\ 10101100_\ 01100111 = C_2

- Hex: 0x6f135f572804ac67