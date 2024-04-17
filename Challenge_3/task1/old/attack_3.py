import socket
from Crypto.Hash import SHA256
from Crypto.Cipher import ChaCha20_Poly1305
import zlib
import json
import sys

# Sicherheitsparameter und Initialisierungen
secret = "tolles secret".encode()
key = "testkey"
key = SHA256.new(key.encode()).digest()
base_plaintext = b"knownpartofplaintext"
possible_characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

def createResponse(plaintext):
    cipher = ChaCha20_Poly1305.new(key=key)
    ciphertext, tag = cipher.encrypt_and_digest(zlib.compress(plaintext + b" secret=" + secret))
    json_keys = ["nonce", "ciphertext", "tag"]
    json_values = [cipher.nonce.hex(), ciphertext.hex(), tag.hex()]
    response = json.dumps(dict(zip(json_keys, json_values))).encode("utf-8")
    return response

def get_response_length(guessed):
    test_secret = guessed.encode()
    modified_plaintext = base_plaintext + b" secret=" + test_secret
    response = createResponse(modified_plaintext)
    return len(response)

base_length = get_response_length("")
previous_length = base_length
guessed_secret = ""
no_change_count = 0

# Schleife bis keine signifikanten Längenänderungen mehr auftreten
while no_change_count < 3:  # Erlaubt drei Iterationen ohne Änderung als Endbedingung
    lengths = {}
    for char in possible_characters:
        test_guess = guessed_secret + char
        response_length = get_response_length(test_guess)
        lengths[char] = response_length

    min_char = min(lengths, key=lambda x: (lengths[x], x))
    if lengths[min_char] <= previous_length:
        guessed_secret += min_char
        previous_length = lengths[min_char]
        no_change_count = 0  # Zurücksetzen des Zählers bei erfolgreicher Änderung
        print(f"Current best guess for the secret: {guessed_secret}")
    else:
        no_change_count += 1  # Zähler erhöhen, wenn keine Verbesserung

print(f"Final guessed secret: {guessed_secret}")

