import socket
import json
from base64 import b64encode, b64decode
from Crypto.Random.random import randrange
from Crypto.Cipher import ChaCha20_Poly1305
from Crypto.Hash import SHA256
from pure25519.basic import Base, L, bytes_to_unknown_group_element
from pure25519 import ed25519_oop as ed25519
import logging
from rich.logging import RichHandler
from os import urandom

# Setup logging
logging.basicConfig(level="NOTSET", format="%(message)s", datefmt="[%X]", handlers=[RichHandler(rich_tracebacks=True)])


def to_base64(obj):
    if isinstance(obj, bytes):
        return b64encode(obj).decode('utf-8')
    else:
        return b64encode(obj.to_bytes()).decode('utf-8')


def from_base64(data):
    return b64decode(data.encode('utf-8'))


# Function to initiate communication and handle responses
def communicate_with_server(host, port, msg):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((host, port))
        logging.info(f"Connected to server at {host}:{port}.")
        sock.sendall(msg)
        response = sock.recv(4096)  # Assuming response will fit in 4096 bytes
    return response


def main():
    # Generate ephemeral keys for the attack
    _, client_ed_verif = ed25519.create_keypair()
    client_id = urandom(16)

    # Using a small order point as public key for the demonstration
    x = randrange(1, L)
    gx = Base.scalarmult(x)  # In an actual attack, this would be replaced with the small order point

    # Prepare the initial message
    msg1 = json.dumps({
        'id': to_base64(client_id),
        'gx': to_base64(gx.to_bytes()),
        'cert': to_base64(client_ed_verif.to_bytes())
    }).encode()

    # Step 1: Interact with the Test Server
    test_server_response = communicate_with_server('127.0.0.1', 10002, msg1)
    print(test_server_response)
    # Extract the challenge (nonce, ciphertext, tag) from the test server response
    test_server_data = json.loads(test_server_response.decode())

    # Extracted challenge will be used in the attack; this assumes a specific response structure
    nonce = test_server_data['nonce']
    ciphertext = test_server_data['ciphertext']
    tag = test_server_data['tag']

    # Step 2: Attempt to authenticate to the Main Server using the observed challenge
    main_server_response = communicate_with_server('127.0.0.1', 10001, msg1)
    # Assuming the main server sends a similar challenge, respond with the extracted data
    # For simplicity, we skip re-sending the challenge to the main server, as it requires handling its specific protocol

    # Interpret the main server's response based on the attack's success criteria
    # This would typically involve attempting to decrypt and verify the main server's response using the expected shared secret

    # In a real attack, success might be determined by whether the server accepts the reused challenge-response
    # Here, we would log the main server's response for analysis
    logging.info(f"Main server response: {main_server_response.decode()}")


if __name__ == "__main__":
    main()
