import socket
from Crypto.Hash import SHA256
from Crypto.Cipher import ChaCha20_Poly1305
import zlib
import json
import sys

# Establish a connection to the server
server_address = ('193.170.192.172', 31337)
sock = socket.socket()
sock.connect(server_address)

def simulate_request(request):
    # Send the request and receive a response
    sock.sendall(request)
    response = sock.recv(1024)
    response = json.loads(response.decode())
    response_length = len(response['ciphertext'])
    return response_length

possible_characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 "
guessed_secret = ""
last_min_length = float('inf')

# Loop until we reach a reasonable length of the guessed secret or a break condition is met
while len(guessed_secret) < 64:
    improvement_found = False
    
    # Test all combinations of the next two characters
    for char1 in possible_characters:
        for char2 in possible_characters:
            test_guess = guessed_secret + char1 + char2
            response_length = simulate_request(b"secret=" + test_guess.encode())
            
            # If the new combination provides a shorter response, it is a better guess
            if response_length < last_min_length:
                last_min_length = response_length
                best_new_guess = test_guess
                improvement_found = True

    # If improvement was found, update the guessed secret
    if improvement_found:
        guessed_secret = best_new_guess
        print(f"Current best guess for the secret: '{guessed_secret}'")
    else:
        # Break the loop if no improvement was found with any new character pairs
        break

print(f"Final guessed secret: '{guessed_secret}'")

# Close the socket connection
sock.close()

