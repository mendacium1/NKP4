import socket
from Crypto.Hash import SHA256
from Crypto.Cipher import ChaCha20_Poly1305
import zlib
import json
import sys

secret = "tolles secret".encode()
key = "testkey"
key = SHA256.new(key.encode()).digest()

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
secret_length = len(secret)  # Wir nehmen an, dass wir die Länge des Secrets kennen

# Funktion zum Ermitteln der Antwortlänge basierend auf einem geratenen Secret
def get_response_length(guessed):
    test_secret = guessed.encode()
    modified_plaintext = base_plaintext + b" secret=" + test_secret
    response = createResponse(modified_plaintext)
    return len(response)

# Initialisierung der Längenliste für die Basisanfrage
base_length = get_response_length(guessed_secret)

# Angriffsschleife mit Backtracking
for position in range(1000):
    lengths = {}
    for char in possible_characters:
        test_guess = guessed_secret + char
        response_length = get_response_length(test_guess)
        lengths[char] = response_length

    # Finde den Buchstaben, der die kürzeste Antwortlänge hervorbringt
    min_char = min(lengths, key=lambda x: (lengths[x], x))
    # Aktualisiere das erratene Secret nur, wenn die neue Länge kleiner ist als die Basislänge
    if lengths[min_char] <= base_length:
        guessed_secret += min_char
        base_length = lengths[min_char]  # Setze die neue Basislänge
    else:
        break  # Beende die Schleife, wenn keine Verbesserung gefunden wird

    print(f"Current best guess for the secret: {guessed_secret}")

print(f"Final guessed secret: {guessed_secret}")

