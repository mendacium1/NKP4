import socket
import json
from base64 import b64encode, b64decode
from Crypto.Cipher import ChaCha20_Poly1305
from Crypto.Hash import SHA256
from pure25519.basic import Base, bytes_to_unknown_group_element, L
from pure25519 import ed25519_oop as ed25519
import logging
from rich.logging import RichHandler

# Initialize logging
logging.basicConfig(level="NOTSET", format="%(message)s", datefmt="[%X]", handlers=[RichHandler(rich_tracebacks=True)])

def to_base64(obj):
    if isinstance(obj, bytes):
        return b64encode(obj).decode('utf-8')
    else:
        return b64encode(obj.to_bytes()).decode('utf-8')

def from_base64(data):
    return b64decode(data.encode('utf-8'))

# Communication function
def communicate_with_server(host, port, message):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((host, port))
        logging.info(f"Connected to {host}:{port}")
        sock.sendall(message)
        response = sock.recv(4096)  # Adjust buffer size as necessary
        logging.info("Received response")
        return response

# Main function
def main():
    # Use a small order point as public key
    small_order_point = Base.scalarmult(2)  # Example: using a small scalar

    # Step 1: Communicate with the Test Server using the small order point
    test_server_host, test_server_port = '127.0.0.1', 10002
    client_private_key, client_public_key = ed25519.create_keypair()
    msg1 = json.dumps({
        'id': to_base64(client_public_key.to_bytes()),
        'gx': to_base64(small_order_point.to_bytes()),
        'cert': to_base64(client_public_key.to_bytes())
    }).encode()
    test_server_response = communicate_with_server(test_server_host, test_server_port, msg1)
    logging.info(f"Test Server Response: {test_server_response}")

    # Extract gy from Test Server's response and compute the shared secret
    response_data = json.loads(test_server_response.decode())
    gy = bytes_to_unknown_group_element(from_base64(response_data['gy']))
    # Here, you would normally compute gxy, but with small order point, it's not applicable in the same way

    # Step 2: Impersonate the Test Server and communicate with the Main Server
    main_server_host, main_server_port = '127.0.0.1', 10001
    # Use the test server's ID and mimic its role to communicate with the main server
    test_server_id = response_data['id']  # Assuming you got the test server's ID somehow (e.g., from server_keys.json or the response)
    msg2 = json.dumps({
        'id': "yk+UwQVNKbpPXo98Xti99oS5cL882AMEGH2MThgQ8mkQVqMO9LVS//OiRJ+6gNLC8WOsjawvV1gOqnN3KZ+jTg==",  # Impersonate the test server
        'gx': to_base64(small_order_point.to_bytes()),  # Reuse the small order point
        'cert': to_base64(client_public_key.to_bytes())  # Use your cert; in a real attack, you'd need the test server's cert
    }).encode()
    main_server_response = communicate_with_server(main_server_host, main_server_port, msg2)
    logging.info(f"Main Server Response: {main_server_response}")

    # In a real scenario, further steps would depend on the protocol specifics of the main server

if __name__ == "__main__":
    main()
