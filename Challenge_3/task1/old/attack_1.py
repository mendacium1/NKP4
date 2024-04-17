import socket
from Crypto.Hash import SHA256
from Crypto.Cipher import ChaCha20_Poly1305
import zlib
import json
import sys

secret = "tolles secret".encode()
key = "testkey"
key = SHA256.new("testkey".encode()).digest()

def createResponse(plaintext):
    cipher = ChaCha20_Poly1305.new(key=key)
    ciphertext, tag = cipher.encrypt_and_digest(zlib.compress(plaintext + b" secret=" + secret))
    json_keys = ["nonce", "ciphertext", "tag"]
    json_values = [cipher.nonce.hex(), ciphertext.hex(), tag.hex()]
    response = json.dumps(dict(zip(json_keys, json_values))).encode("utf-8")
    return response

# Beginn des Angriffs
base_plaintext = b"knownpartofplaintext"
possible_characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
guessed_secret = ""

# Annahme einer maximalen Länge des secrets, hier z.B. 10 Zeichen
for _ in range(10):
    lengths = {}
    # Teste jeden möglichen nächsten Buchstaben des secrets
    for char in possible_characters:
        test_secret = (guessed_secret + char).encode()
        modified_plaintext = base_plaintext + b" secret=" + test_secret
        response = createResponse(modified_plaintext)
        response_length = len(response)
        lengths[char] = response_length

    # Suche den Buchstaben, der die kürzeste Antwortlänge hervorbringt
    min_char = min(lengths, key=lengths.get)
    guessed_secret += min_char
    print(f"Current best guess for the secret: {guessed_secret}")

print(f"Final guessed secret: {guessed_secret}")
