# Week 4: Keyed hashes and authenticated encryption

### Task 1: Brute forcing a short authentication tag

Using Python's `cryptography` library, which supports both GCM (Galois/Counter Mode) and CCM (Counter with CBC-MAC) modes of operation for AES (Advanced Encryption Standard).  GCM would be the used mode due to its wide adoption and performance benefits.

The standard minimum tag length for GCM in most libraries is 12 bytes, but fot tis task i conceptually choose to focus on a shorter part of the tag (e.g., the first 1 or 2 bytes) to illustrate the brute force method. However, it's crucial to understand that in real-world applications, using such a short tag length severely compromises security, making it vulnerable to forgery attacks.

First, we'll encrypt a message using AES in GCM mode with a full tag and then simulate the short tag length by considering only the first part of it. Next, we'll attempt to brute force another message that results in the same truncated authentication tag. This involves generating random messages, encrypting them with the same key and nonce, and comparing the generated tag's relevant portion with that of the original message.

- Source code used
  ````py
  from cryptography.hazmat.primitives.ciphers.aead import AESGCM
  import os, random, string
  
  # Generate a random key for AES-256 GCM
  key = AESGCM.generate_key(bit_length=256)
  
  # Initialize AESGCM instance with the generated key
  aesgcm = AESGCM(key)
  
  # Prepare nonce and message
  nonce = os.urandom(12)  # 96-bit nonce for GCM
  message = b"hello crypto"
  
  # Encrypt the message using AES-GCM
  encrypted = aesgcm.encrypt(nonce, message, None)
  
  # Extract the ciphertext and tag from the encrypted output
  ciphertext, tag_full = encrypted[:-16], encrypted[-16:]
  tag_short = tag_full[:2]  # Simulate a short tag for demonstration
  
  # Function to generate a random message of fixed length
  def generate_random_message(length=16):
      return ''.join(random.choices(string.ascii_letters + string.digits, k=length)).encode()
  
  # Attempt to brute force
  attempts = 0
  found = False
  while not found:
      if attempts > 100000:
          break
      random_message = generate_random_message()
      random_encrypted = aesgcm.encrypt(nonce, random_message, None)
      random_tag_full = random_encrypted[-16:]
      random_tag_short = random_tag_full[:2]
      if random_tag_short == tag_short:
          found = True
          break
      attempts += 1
  
  print(f"key: {key.hex()}")
  print(f"nonce: {nonce.hex()}")
  print(f"Original Message: {message.decode()}")
  print(f"Brute-Forced Message: {random_message.decode()}")
  print(f"Authentication Full Tag: {random_tag_full.hex()}")
  print(f"Authentication Tag (first 2 bytes): {tag_short.hex()}")
  print(f"Number of Attempts: {attempts}")
  ````
- [sc1](./sc1.png)
  
Results
- key: 6f81ef48667c117c19d8b2b34da90bbfd5b243048c853bb44b5c84871df3aca7
- nonce: 83cc67d90a96e82cb2096f7b
- Original Message: hello crypto
- Brute-Forced Message: 6jcYLck57n08Oc8l
- Authentication Full Tag: e20ba18cb12575e6d70f6ac1047b50dc
- Authentication Tag (first 2 bytes): e20b
- Number of Attempts: 24083
