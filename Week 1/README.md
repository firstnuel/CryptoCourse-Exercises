# Week 1: Encryption and randomness

### Task 1

- "Hi Kimmo" in binary: 

$$ 01001000_\ 01101001_\ 00100000_\ 01001011_\ 01101001_\ 01101101_\ 01101101_\ 01101111 = P_1$$

- "No Rauli" in binary:

$$ 01001110_\ 01101111_\ 00100000_\ 01010010_\ 01100001_\ 01110101_\ 01101100_\ 01101001 = P_2$$

- The XOR between of two plaintexts is:

$$00000110_\ 00000110_\ 00000000_\ 00011001_\ 00001000_\ 00011000_\ 00000001_\ 00000110 = X$$

This should be equal to the XOR of the cipher of "No Rauli" and the cipher of "No Kimmo". Therefore XOR between them 

$$ 00000110_\ 00000110_\ 00000000_\ 00011001_\ 00001000_\ 00011000_\ 00000001_\ 00000110 = X$$

$$ 01101001_\ 00010101_\ 01011111_\ 01001110_\ 00100000_\ 00011100_\ 10101101_\ 01100001 = C_1$$

XOR

$$ 01101111_\ 00010011_\ 01011111_\ 01010111_\ 00101000_\ 00000100_\ 10101100_\ 01100111 = C_2$$

- Hex: 0x6f135f572804ac67
-----

### Task 2

- Decrypted text -  "Cryptography rearranges power. It configures who can do what, from what. This makes cryptography an inherently political tool, and it confers on the field an intrinsically moral dimension. The Snowden revelations motivate a reassessment of the political and moral positioning of cryptography. They lead one to ask if our inability to effectively address mass surveillance constitutes a failure of our field. I believe that it does. I call for a community-wide effort to develop more effective means to resist mass surveillance. I plead for a reinvention of our disciplinary culture to attend not only to puzzles and math but also to the societal implications of our work."

- Secret Key: RANDOM
  
- The plain text is from the abstract of "The Moral Character of Cryptographic Work" by Phillip Rogaway, University of California, Davis. 
  
I used a python code i found on Github that decrypts the Vigenere cipher by creating an inverse key and applying the Vigenere encryption operation in reverse order. This process reveals the original plaintext. The logic the code utilizes to decrypt the cipher text is as follows:

- Repeating Key: The Vigenere cipher uses a repeating key to encrypt the plaintext. This repetition introduces patterns in the ciphertext, making it susceptible to frequency analysis.

- Frequency Analysis: The script takes advantage of the fact that each letter in the key is independent, allowing for analysis of the frequency distribution at different starting offsets.

- Weakness in Encryption: While Vigenere is a polyalphabetic cipher, its weaknesses arise from the fact that each letter in the key independently encrypts the corresponding plaintext letter. This makes it possible to analyze and decrypt portions of the text independently.

- Frequency Matching: The script constructs potential keys by matching the frequency distribution of letters in the decrypted text with the expected frequency distribution of English letters.

- Iterative Approach: The script iterates over possible key lengths and constructs the best key for each length. This approach allows for a systematic analysis of different key possibilities.

In summary, the Vigenere cipher was decryptable in this case due to its inherent weaknesses when using a repeating key. The script leverages frequency analysis to identify patterns and systematically decrypt the ciphertext. 

- the code
```
  import itertools
  import string
  import sys
  import textwrap

  ####################################################################################################
  # Vigenere encryption and decryption functions
  ####################################################################################################
  
  def vigenere(plaintext, key, a_is_zero=True):
      key = key.lower()
      if not all(k in string.ascii_lowercase for k in key):
          raise ValueError("Invalid key {!r}; the key can only consist of English letters".format(key))
      key_iter = itertools.cycle(map(ord, key))
      return "".join(
          chr(ord('a') + (
              (next(key_iter) - ord('a') + ord(letter) - ord('a'))  # Calculate shifted value
              + (0 if a_is_zero else 2)  # Account for non-zero indexing
          ) % 26) if letter in string.ascii_lowercase  # Ignore non-alphabetic chars
          else letter
          for letter in plaintext.lower()
      )

  def vigenere_decrypt(ciphertext, key, a_is_zero=True):
      # Decryption is encryption with the inverse key
      key_ind = [ord(k) - ord('a') for k in key.lower()]
      inverse = "".join(chr(ord('a') +
                           ((26 if a_is_zero else 22) -
                            (ord(k) - ord('a'))
                            ) % 26) for k in key)
      return vigenere(ciphertext, inverse, a_is_zero)
  
  def test_vigenere(text, key, a_is_zero=True):
      ciphertext = vigenere(text, key, a_is_zero)
      plaintext = vigenere_decrypt(ciphertext, key, a_is_zero)
      assert plaintext == text, "{!r} -> {!r} -> {!r} (a {}= 0)".format(
          text, ciphertext, plaintext, "" if a_is_zero else "!"
      )
  
  # Test that the Vigenere encrypt and decrypt work (or are at least inverses)
  for text in ["rewind", "text with spaces", "pun.ctuation", "numb3rs"]:
      for key in ["iepw", "aceaq", "safe", "pwa"]:
          test_vigenere(text, key, True)
          test_vigenere(text, key, False)
  
  # Now that we're sure that all the Vigenere stuff is working...
  
  ####################################################################################################
  # Cipher solver
  ####################################################################################################
  
  ENGLISH_FREQ = (0.0749, 0.0129, 0.0354, 0.0362, 0.1400, 0.0218, 0.0174, 0.0422, 0.0665, 0.0027, 0.0047,
                  0.0357, 0.0339, 0.0674, 0.0737, 0.0243, 0.0026, 0.0614, 0.0695, 0.0985, 0.0300, 0.0116,
                  0.0169, 0.0028, 0.0164, 0.0004)
  
  
  def compare_freq(text):
      if not text:
          return None
      text = [t for t in text.lower() if t in string.ascii_lowercase]
      freq = [0] * 26
      total = float(len(text))
      for l in text:
          freq[ord(l) - ord('a')] += 1
      return sum(abs(f / total - E) for f, E in zip(freq, ENGLISH_FREQ))
  
  
  def solve_vigenere(text, key_min_size=None, key_max_size=None, a_is_zero=True):
      best_keys = []
      key_min_size = key_min_size or 1
      key_max_size = key_max_size or 20
  
      text_letters = [c for c in text.lower() if c in string.ascii_lowercase]
  
      for key_length in range(key_min_size, key_max_size):
          key = [None] * key_length
          for key_index in range(key_length):
              letters = "".join(itertools.islice(text_letters, key_index, None, key_length))
              shifts = []
              for key_char in string.ascii_lowercase:
                  shifts.append(
                      (compare_freq(vigenere_decrypt(letters, key_char, a_is_zero)), key_char)
                  )
              key[key_index] = min(shifts, key=lambda x: x[0])[1]
          best_keys.append("".join(key))
      best_keys.sort(key=lambda key: compare_freq(vigenere_decrypt(text, key, a_is_zero)))
      return best_keys[:2]
  
  
    CIPHERTEXT = "TRLSHAXRNSVKIENUFMEGRVDANEELHOFNSLUGIEFZVATAAGCIYAGIFADWUDHFYIFPOWVSPUMBKOTUOBYYNQWZYEEHBFCYCRZUKIPDZFFOYDBPZTPRBRVRFRBFYESLSXUAALBFIIAVWORLYBAAIAYGWYVNFLCZKHRVBANDRQFQMEYDHUFNFPCFZVNWSMIENVGQJSZHBFFFGKSBFLVWWORLNQRYFRNODAJIGLCZZNTRTOIYCWCSIACKMFYELOSMUOAHHARSXLTALRVQONZLVWMFFESISOKIIHZKRDQUSEJMNVGELRIHWXCAAFSOFNFWWFLTRVORRIYXFQFFBXFRZEYGWNVLVHJQKHNWWFUORVWORLYICDRCBPAGEIGBKUUERITAITGRRQMEYRDYFRRHTRVCGLJQDENQGFFRRVWEKMNVGELRIHWXCAAFSUGLRDRRFRNUSUEVRQHUFNBICGIDVVQUGLVQODPCHOHGIEGROFKEAGBAKOAOMFFPHCNXVSNQRYRTUEIFRLFRHAKHRVCOZEGDZUDPYLQMKIBQGAWOHUKAIK"
    
    
    print ("Solving Vigenere cipher:")
    print ("*" * 80)
    print( textwrap.fill(CIPHERTEXT, 80))
    print ("*" * 80)
    for key in reversed(solve_vigenere(CIPHERTEXT)):
        print( "")
        print ("Found key: {!r}".format(key))
        print ("Solution:")
        print( "=" * 80)
        print (textwrap.fill(vigenere_decrypt(CIPHERTEXT, key)))
        print ("=" * 80)
```
----
Task 3

- /dev/random: This device generates blocking entropy. It blocks (waits) until it believes it has gathered sufficient entropy to generate a truly random number. If the entropy pool is empty, reading from /dev/random will be blocked until there is enough entropy available. This can create delays if the system does not produce enough entropy.

In contrast, /dev/urandom is non-blocking. It will always return data, even if there is insufficient entropy available. If the entropy pool is empty, /dev/urandom generates data with a cryptographically safe pseudorandom number generator. The distinction is that if the entropy pool is empty, the numbers created by /dev/urandom may be less unpredictable than really random numbers.

Recent Changes in Kernel
In recent Linux kernels, the behavior of /dev/random and /dev/urandom has been modified to address concerns about the blocking behavior of /dev/random. The changes aim to make /dev/random more predictable and avoid potential application stalls due to lack of entropy.

The two devices are now linked to the same entropy pool. In other words, reads from both /dev/random and /dev/urandom will derive their randomness from the same pool. If the entropy pool is initialized, both devices will provide high-quality random numbers. If the pool is uninitialized, both will use a pseudorandom number generator until there is enough entropy.

This change is practical because it acknowledges that, in many situations, the blocking behavior of /dev/random was causing unnecessary delays and didn't necessarily result in higher-quality randomness. /dev/urandom remains the preferred choice for most applications, as it provides a good balance between security and availability. Applications that specifically require blocking until "true randomness" is available may still opt to use /dev/random.
