# Week 6: Diffie-Hellman-Merkle

### Task 1: Naive DH and MitM

Diffie-Hellman key exchange can be considered a cornerstone of modern public-key cryptography, enabling parties to establish a shared secret over an insecure channel. However, without proper authentication, it's vulnerable to man-in-the-middle (MitM) attacks.

Task 1.1: Implement MitM Attack

Implement a scenario where Alice and Bob attempt to establish a key exchange, but Eve intercepts and modifies their messages to establish two distinct exchanges with each of them. This demonstrates how Eve can decrypt and proxy messages without detection.

- Implementation Overview

1. **Alice and Bob** initiate a DH key exchange.
2. **Eve** intercepts the exchange, establishing separate key exchanges with Alice and Bob.
3. Eve decrypts, potentially modifies, and forwards messages, remaining undetected.

- Python Simulation

Below is a simplified script to demonstrate the MitM attack on the DH exchange:

```python
from Crypto.Util.number import getPrime, GCD
from Crypto.Random import get_random_bytes
import hashlib

def generate_safe_prime(bits):
    q = getPrime(bits - 1)
    p = 2*q + 1
    return p, q

def mitm_attack(p, g):
    # Simulating private key generation and interception by Eve
    a_private, b_private = get_random_bytes(16), get_random_bytes(16)
    e_a_private, e_b_private = get_random_bytes(16), get_random_bytes(16)
    
    # Alice's and Bob's public keys are intercepted and replaced by Eve's
    A, B = pow(g, int.from_bytes(a_private, 'big'), p), pow(g, int.from_bytes(b_private, 'big'), p)
    E_A, E_B = pow(g, int.from_bytes(e_a_private, 'big'), p), pow(g, int.from_bytes(e_b_private, 'big'), p)
    
    # Eve establishes shared secrets with Alice and Bob
    s_e_a, s_e_b = pow(B, int.from_bytes(e_a_private, 'big'), p), pow(A, int.from_bytes(e_b_private, 'big'), p)
    key_e_a, key_e_b = hashlib.sha256(str(s_e_a).encode()).digest(), hashlib.sha256(str(s_e_b).encode()).digest()
    
    return key_e_a, key_e_b

# Parameters and execution
g, bits = 2, 2048
p, _ = generate_safe_prime(bits)
key_e_a, key_e_b = mitm_attack(p, g)
print("Eve's keys for Alice:", key_e_a, key_e_b)
print("Eve's keys for Bob:", key_e_b)
```
![sc1](./sc1.png)

Task 1.2: Effect of g and p on Eavesdropping

The selection of \(g\) and \(p\) significantly impacts the security of the DH exchange. A large prime \(p\) and a suitable generator \(g\) are essential for a secure setup, preventing easy eavesdropping.

Task 1.3: Mitigation of MitM in Modern Systems

Modern systems use various methods to mitigate MitM attacks, including certificate authorities, public key infrastructure, and perfect forward secrecy. These mechanisms ensure secure and authenticated communication even over insecure channels.
