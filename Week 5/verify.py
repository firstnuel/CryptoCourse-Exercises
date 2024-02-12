import subprocess
import os

# Define the directories and file paths
messages_file_path = './messages.txt'
public_keys_dir = './public_keys'
signatures_dir = './signatures'

# Read all messages
with open(messages_file_path, 'r') as messages_file:
    messages = messages_file.readlines()

# Iterate through each message
for message in messages:
    message = message.strip()
    message_file_path = '/tmp/message.txt'
    
    # Save the message to a temporary file (required for OpenSSL command)
    with open(message_file_path, 'w') as message_file:
        message_file.write(message)
    
    # Iterate through each public key
    for public_key_filename in os.listdir(public_keys_dir):
        public_key_path = os.path.join(public_keys_dir, public_key_filename)
        
        # Iterate through each signature
        for signature_filename in os.listdir(signatures_dir):
            signature_path = os.path.join(signatures_dir, signature_filename)
            
            # Prepare the OpenSSL command
            cmd = [
                'openssl', 'dgst', '-sha256', '-verify',
                public_key_path, '-signature',
                signature_path, message_file_path
            ]
            
            # Execute the command
            result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
            # Check if the verification was successful
            if 'Verified OK' in result.stdout.decode('utf-8'):
                with open('verified.txt', 'a') as verified_file:
                    verified_file.write(f"{message} | {public_key_filename} | {signature_filename}\n")
              

# Clean up the temporary message file
os.remove(message_file_path)
