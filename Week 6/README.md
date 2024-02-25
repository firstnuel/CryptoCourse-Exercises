# Week 6: Diffie-Hellman-Merkle

### Task 1: Naive DH and MitM

Diffie-Hellman key exchange can be considered a cornerstone of modern public-key cryptography, enabling parties to establish a shared secret over an insecure channel. However, without proper authentication, it's vulnerable to man-in-the-middle (MitM) attacks.

**Task 1.1: Implement MitM Attack**

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
print("Eve's keys for Alice:", key_e_a)
print("Eve's keys for Bob:", key_e_b)
```
![sc1](./sc1.png)


**Task 1.2: Selection of \(g\) and \(p\) in DH Key Exchange**

The security of the Diffie-Hellman key exchange depends significantly on the choice of the generator \(g\) and the prime modulus \(p\). A safe prime \(p = 2q + 1\), where \(q\) is also prime, is ideal because it ensures a large subgroup order, reducing the susceptibility to discrete logarithm attacks. The choice of \(g\) affects the efficiency and security of the protocol. \(g\) should be chosen so that it generates a large subgroup of order \(q\) within Z(p).

Poor selection of these parameters can lead to vulnerabilities. For instance, if \(p\) is not a safe prime, the protocol may be vulnerable to subgroup attacks. Similarly, a small \(g\) or \(p\) can make the protocol susceptible to brute-force attacks.

**Task 1.3: Modern Solutions to MitM Problems in Systems like TLS**

Modern cryptographic protocols, such as TLS, address the Man-in-the-Middle (MitM) vulnerability by incorporating authentication mechanisms alongside key exchange protocols. These mechanisms can include:

1. **Certificate Authorities (CAs)**: TLS uses certificates issued by trusted Certificate Authorities to verify the identity of the parties. This ensures that the public key belongs to the entity it claims to be from, preventing an attacker from inserting their key into the exchange.
  
2. **Public Key Infrastructure (PKI)**: PKI provides a framework for managing public keys and certificates, ensuring secure communication over the internet. It includes issuing, renewing, and revoking certificates.

3. **Perfect Forward Secrecy (PFS)**: PFS ensures that even if long-term keys are compromised, past communications cannot be decrypted. This is achieved by using ephemeral key pairs for each session, which are not stored long-term.

By integrating these and other security measures, modern systems significantly reduce the risk of MitM attacks, ensuring secure communications even over public and potentially insecure channels.

------

### Task 2: DH with a very unsafe prime

2.1 Order of Alice's Share

The order is the smallest \(d\) for which \(A^d \equiv 1 \mod p\).  A straightforward approach to find (d) is a brute-force search from 1 up to p−1, but this can be optimized with knowledge of group theory or using algorithms designed for such purposes.

````py
# Function to read a value from a file
def read_value_from_file(file_path):
    with open(file_path, 'r') as file:
        return int(file.read().strip())

# Replace these paths with the actual paths to your files
prime = './unsafe_p.txt'
generator = './generator.txt'
public share = './unsafe_ga.txt'

def find_order(public_share, generator, prime):
    d = 1
    while True:
        # Alice's share^d mod p
        result = pow(public_share, d, prime)
        if result == 1:
            return d
        d += 1

# Order of Alice's share
order = find_order(public_share, generator, prime)
print("Order:", order)
````
The output of the code is as follows:

![sc](./sc2.png)

The order is 101. 

Task 2.2 Possibilities for the Shared Secret

The number of possible shared secrets corresponds to the order of the subgroup, not depending on the secret exponent.
- The fact that Alice's share has an order of 101 indicates that there are 101 elements in the subgroup of the group produced by the generator modulo the prime that is made up of all conceivable values for the common shared secret. The order of the subgroup—101 in this case—determines the number of possible values for the common shared secret. As a result, the common shared secret has 101 possible values.

- Bob's options are limited to the 101-element subgroup that Alice's share creates as a potential value for the common shared secret. As a result, regardless of Bob's choice of secret exponent, the number of choices stays the same.


Task 2.3

We can utilize trial division with small primes until the division is no longer even in order to determine the various factors of (p-1). (p-1) is our starting point, and we divide it by little primes till we get 1.

````
p-1 = 2906347176960734841102915400715931684676738386917551293602548940017089151563020096075793145507544909799419325859795323626093294797601295362066222447438952667031315410724883975028255045041250967003021649815634917672723512152046317329813204370731220675839985347995496026203846545595056245788546987335750260208358284546291147473293252515791139722473131884086360496749320657551127839785289082610236625397838417994044140052064528157551457620578232391435991791325758463549417841949376589453031999388696831078873411074599909633778369511252614215116845902011637486786496344033030211520607498474074348716583103427724802387789604245206457732417620741922128269046960386975413294794633781512968490642838333805952796503387711844405306514987765843460355064766744241388139564882514479660485760706796398091343123973467734371818224366218814091320885248000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001
````
We can start dividing (p-1) by small primes until we reach 1:

1. Divide by 2:
````
(p-1)/2 = (2906347176960734841102915400715931684676738386917551293602548940017089151563020096075793145507544909799419325859795323626093294797601295362066222447438952667031315410724883975028255045041250967003021649815634917672723512152046317329813204370731220675839985347995496026203846545595056245788546987335750260208358284546291147473293252515791139722473131884086360496749320657551127839785289082610236625397838417994044140052064528157551457620578232391435991791325758463549417841949376589453031999388696831078873411074599909633778369511252614215116845902011637486786496344033030211520607498474074348716583103427724802387789604245206457732417620741922128269046960386975413294794633781512968490642838333805952796503387711844405306514987765843460355064766744241388139564882514479660485760706796398091343123973467734371818224366218814091320885248000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001) / 2 = 14531735884803674205514577003579658423383691934587756468012744700085445757815100480378965727537724548997096629298976618130466473988006476810331112237194763335156577053624419875141275225206254835015135015105108249078174588368717560780231586649066021853656103379199926739977480131019232727975281228942734901301041791422731455737366466262578955698612365659420431802483746603287755639126445413051183198926445413039192010730140787757252903104161961957151911951903957128792317747072697422401530264052552787252891161961956787795956628792317703242792317703242752894156578852882379162854071075581041448240119234877081482621858172231
 ````  

This is not an even number.
````
Factors of (p-1) are 2 and  14531735884803674205514577003579658423383691934587756468012744700085445757815100480378965727537724548997096629298976618130466473988006476810331112237194763335156577053624419875141275225206254835015135015105108249078174588368717560780231586649066021853656103379199926739977480131019232727975281228942734901301041791422731455737366466262578955698612365659420431802483746603287755639126445413051183198926445413039192010730140787757252903104161961957151911951903957128792317747072697422401530264052552787252891161961956787795956628792317703242792317703242752894156578852882379162854071075581041448240119234877081482621858172231.
````
Based on this factorization, we can find the subgroups of above order value. 

Let's say,
````
o1 = 2
o2 = 14531735884803674205514577003579658423383691934587756468012744700085445757815100480378965727537724548997096629298976618130466473988006476810331112237194763335156577053624419875141275225206254835015135015105108249078174588368717560780231586649066021853656103379199926739977480131019232727975281228942734901301041791422731455737366466262578955698612365659420431802483746603287755639126445413051183198926445413039192010730140787757252903104161961957151911951903957128792317747072697422401530264052552787252891161961956787795956628792317703242792317703242752894156578852882379162854071075581041448240119234877081482621858172231
````
The generators are:

1. For the subgroup of order o1 --> $ G = g^{(p-1)\over o1}$ 

2. For the subgroup of order o2 --> $G = g^{(p-1)\over o2}$

where g is the original generator and p is the prime number.


Task 2.4 Security Level Based on Bit Length of \(p\)

```python
bit_length_of_p = p.bit_length()
```

The security level is influenced by the bit length of \(p\) and the size of the subgroup used for DH exchange.



-----
### Task 3: ElGamal & Malleability

**3.1: Exploiting ElGamal's Malleability**

ElGamal encryption is known for its malleability property, which means that given an encrypted message, it's possible to modify it into another valid encrypted message without decrypting it. Specifically, if you have an encrypted message c = (g^k, m . h^k) where m is the message, h is the recipient's public key, and g^k is a random ephemeral key, you can create a new ciphertext c^1 = (g^k, m^1 . h^k) that will decrypt to a different message m^1 without needing the private key.

This property can be exploited to alter the encrypted financial figures in your scenario. By multiplying the (y) part of the ciphertext by an appropriate factor (which corresponds to the public key raised to a power that represents the desired modification), you can adjust the encrypted figures so that they decrypt to the correct values.

**3.2: Preventing Malleability**

To combat malleability in ElGamal encryption, one could:

1. **Implement Authentication Mechanisms:** Implement digital signatures or Message Authentication Codes (MACs) alongside the encrypted message to ensure the integrity and authenticity of the message. Any modification to the ciphertext would invalidate the signature or MAC, alerting the recipient to the tampering.

2. **Use Cryptographic Hash Functions:** Combining the ciphertext with a hash of the plaintext before encryption can also prevent malleability. The recipient can decrypt the message, recompute the hash of the plaintext, and compare it to the decrypted hash to verify integrity.


