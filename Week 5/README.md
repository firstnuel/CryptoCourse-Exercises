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
----
### Task 2: Message and signature verification

Task 2.1

Using a Python script that iteratively goes through each message in a messages.txt file, each public key in a public_keys folder, and each signature in a signatures folder, verifying the signature for the message with the public key. Using subprocess to execute `openssl dgst -sha256 -verify public_key.pem -signature signature.sign message.txt` but automating it.

- [Python Script used](./verify.py)

- Results

S/n | Message | Public key(s) | Signature file(s)
---|---|---|---
1| Wisdom is easily acquired when hiding under the bed with a saucepan on your head. | public_key2.pem | signature6.sign
2| Thirty years later, she still thought it was okay to put the toilet paper roll under rather than over. | public_key4.pem | signature13.sign
3| It had been sixteen days since the zombies first attacked. | public_key3.pem | signature2.sign
4| The knives were out and she was sharpening hers. | public_key5.pem | signature8.sign
5| Watching the geriatric men’s softball team brought back memories of 3 yr olds playing t-ball. | public_key4.pem | signature11.sign
6| As the rental car rolled to a stop on the dark road, her fear increased by the moment. | public_key3.pem | signature16.sign
7| Standing on one's head at job interviews forms a lasting impression. | public_key2.pem | signature7.sign
8| Standing on one's head at job interviews forms a lasting impression. | public_key1.pem | signature4.sign
9| It was a really good Monday for being a Saturday. | public_key5.pem | signature14.sign
10| Warm beer on a cold day isn't my idea of fun. | public_key1.pem | signature17.sign
11| He fumbled in the darkness looking for the light switch, but when he finally found it there was someone already there. | public_key5.pem | signature3.sign
12| The bird had a belief that it was really a groundhog. | public_key5.pem | signature9.sign
13| He knew it was going to be a bad day when he saw mountain lions roaming the streets. | public_key2.pem | signature10.sign
14| He appeared to be confusingly perplexed. | public_key2.pem | signature15.sign
15| Hit me with your pet shark! | public_key3.pem | signature1.sign
16| She wondered what his eyes were saying beneath his mirrored sunglasses. | public_key1.pem | signature18.sign
17| He had a vague sense that trees gave birth to dinosaurs. | public_key4.pem | signature12.sign
18| My dentist tells me that chewing bricks is very bad for your teeth. | public_key4.pem | signature20.sign
19| I'm confused: when people ask me what's up, and I point, they groan. | public_key1.pem | signature5.sign
20| I'd rather be a bird than a fish. | public_key3.pem | signature19.sign



Task 2.2

The "textbook" RSA (without padding, directly encrypting the message with the private key) is not secure for several reasons:

- No Padding: Textbook RSA does not include padding, which makes it deterministic and susceptible to chosen-plaintext attacks. An attacker could potentially use this determinism to forge signatures on messages that have a predictable structure.

- Replay Attacks: Without a mechanism to ensure the uniqueness of each signed message (like timestamps or sequence numbers), an attacker could reuse a valid signature in a different context.

- Message Recovery: For short messages, textbook RSA allows an attacker to recover the original message from the signature without needing the private key, simply by raising the signature to the power of the public exponent.

- Lack of Integrity Protection: Textbook RSA does not inherently provide integrity protection. An attacker could alter an unsigned portion of a message without affecting the signature's validity.

- To mitigate these vulnerabilities, practical RSA implementations use padding schemes (such as PKCS#1 v1.5 or OAEP for encryption, and PSS for signing) and often combine RSA with hash functions to sign the hash of the message rather than the message itself. This approach provides additional security properties, including resistance to chosen-plaintext attacks and ensuring that the operation is not deterministic.
-------

### Task 4: Roll your own public key cryptosystem

Task 4.1

- Hard Problem: The chosen hard problem for this cryptosystem is the **Graph Isomorphism Problem** (GIP). In GIP, the challenge is to determine whether two finite graphs are isomorphic, meaning there is a bijection between the vertex sets of the two graphs that preserves the adjacency relationship.

- Evidence of Hardness: The Graph Isomorphism Problem is considered hard because, despite extensive research, no polynomial-time algorithm has been found for solving it in the general case. Its complexity class is somewhere between P and NP-complete, making it a candidate for cryptographic applications due to its non-deterministic polynomial (NP) hardness for certain instances.

- Usage for Encryption: In this system, the public key would be a graph \(G\) and its isomorphic counterpart \(G'\), where \(G'\) is a scrambled version of \(G\) using a secret transformation. To encrypt a message, the sender uses the public key to map the message onto a series of graph transformations that correspond to \(G'\). The private key, known only to the receiver, can efficiently reverse these transformations, leveraging the specific isomorphism used to create \(G'\) from \(G\).

Task 4.2
- Pseudocode for Encryption
````
def encrypt_message(message, public_key):
    # Assuming public_key is (G, G'), where G' is an isomorphic graph to G
    G, G_prime = public_key
    encrypted_message = []

    for char in message:
        # Map each character to a transformation in G'
        transformation = map_char_to_transformation(char, G_prime)
        encrypted_message.append(transformation)

    return encrypted_message

def map_char_to_transformation(char, graph):
    # Simplified example of mapping a char to a graph transformation
    return some_transformation_based_on_char_and_graph(char, graph)
````
- Complexity: The complexity of the encryption process depends on the efficiency of mapping characters to graph transformations and the complexity of applying these transformations. It is expected to be polynomial in the size of the message and the graph but may vary based on the specific implementation of the graph isomorphism challenge.

Task 4.3 

- Side-Channel Attacks: If the encryption or decryption process has varying execution times or uses different amounts of resources depending on the input, it may be vulnerable to side-channel attacks that infer information based on these variations.
- Man-in-the-Middle (MitM) Attacks: Without a secure way of exchanging public keys, an attacker could intercept communications, substituting their own public keys to decrypt and possibly alter messages before re-encrypting and sending them to the intended recipient.
- Algorithmic Attacks: If a polynomial-time algorithm for GIP is discovered, it would compromise the security of this cryptosystem.

Task 4.4

The Graph Isomorphism Problem has been considered for cryptographic applications, notably in a study proposing practical post-quantum signature schemes based on isomorphism problems of trilinear forms. This scheme, inspired by zero-knowledge protocols for graph isomorphism, aims to offer an alternative for post-quantum digital signatures, highlighting the cryptographic potential of isomorphism problems​

Refrences
- [Practical Post-Quantum Signature Schemes from Isomorphism Problems of Trilinear Forms](https://eprint.iacr.org/2022/267)
- [The Graph Isomorphism Problem](https://era.library.ualberta.ca/items/f8153faa-71bf-4b64-9eb4-f0c6d3b529dd)
