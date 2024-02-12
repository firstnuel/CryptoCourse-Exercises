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
