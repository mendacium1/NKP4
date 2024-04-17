import socket
from Crypto.Hash import SHA256
from Crypto.Cipher import ChaCha20_Poly1305
import zlib
import json
import sys

# Initialize cryptographic components
secret = "ein geheimnis".encode()  # This line simulates the unknown secret on the server side
key = "testkey"
key = SHA256.new(key.encode()).digest()

def createResponse(plaintext):
    cipher = ChaCha20_Poly1305.new(key=key)
    ciphertext, tag = cipher.encrypt_and_digest(zlib.compress(plaintext + b"secret=" + secret))
    json_keys = ["nonce", "ciphertext", "tag"]
    json_values = [cipher.nonce.hex(), ciphertext.hex(), tag.hex()]
    response = json.dumps(dict(zip(json_keys, json_values))).encode("utf-8")
    return response

def simulate_request(request):
    response = createResponse(request)
    response = json.loads(response.decode())
    response_length = len(response['ciphertext'])  # We use the length of the ciphertext as the metric
    return response_length

# Systematic request sending and response length analysis
possible_characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 "
guessed_secret = ""

# Assuming the secret is no more than 20 characters for practical purposes
while len(guessed_secret) < 64:
    min_length = float('inf')
    best_char = ''
    for char in possible_characters:
        test_guess = guessed_secret + char
        response_length = simulate_request(b"secret=" + test_guess.encode())
        if response_length < min_length:
            min_length = response_length
            best_char = char

    # Add the best character found in this iteration to the guessed secret
    guessed_secret += best_char
    print(f"Current best guess for the secret: '{guessed_secret}'")

    # Heuristic break condition: if no improvement in compression, likely end of secret
    if best_char == ' ':
        break

print(f"Final guessed secret: '{guessed_secret}'")

