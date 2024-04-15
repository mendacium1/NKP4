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

def from_base64(data):#
    return b64decode(data.encode('utf-8'))

def generate_client_keys():
    client_ed_sign, client_ed_verif = ed25519.create_keypair()
    client_id = urandom(16)

    client_id_b64 = b64encode(client_id).decode('utf-8')
    client_sign_key_b64 = b64encode(client_ed_sign.to_bytes()).decode('utf-8')
    client_verif_key_b64 = b64encode(client_ed_verif.to_bytes()).decode('utf-8')

    keys = {
        'client_id': client_id_b64,
        'client_sign_key': client_sign_key_b64,
        'client_verif_key': client_verif_key_b64,
    }

    with open('client_keys.json', 'w') as json_file:
        json.dump(keys, json_file)

    print("Client keys and ID have been generated and stored in client_keys.json")


# Assuming this function is called to generate client keys
generate_client_keys()

# Load client parameters (ID and key pair)
with open('client_keys.json') as json_file:
    params = json.load(json_file)
    client_id = b64decode(params['client_id'])
    logging.info(f"Loaded client ID: {client_id}.")
    ed_sign = ed25519.SigningKey(b64decode(params['client_sign_key']))
    logging.info("Client signing key loaded.")
    ed_verif = ed_sign.get_verifying_key()
    logging.info("Client verification key extracted.")

# Compute g^x and integer i from client ID, x is your private key
x = randrange(L)
gx = Base.scalarmult(x)  # Here you would replace gx with your small order point if experimenting
i = int(SHA256.new(client_id).hexdigest(), base=16) % L
gi = Base.scalarmult(i)

def main():
    print("\n----------INTERACTING WITH TESTSERVER----------\n")
    host = '127.0.0.1'
    testserver_port = 10002

    # Construct the first message
    msg1 = json.dumps({
        'id': to_base64(client_id),
        'gx': to_base64(gx.to_bytes()),
        'cert': to_base64(ed_verif.to_bytes())
    }).encode()

    # Create a socket and connect to the server
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host, testserver_port))
    logging.info(f"Connected to testserver at {host}:{testserver_port}.")

    sock.sendall(msg1)
    logging.info(f"Sent msg1: {msg1}")

    # Receive and process the server's response
    response = sock.recv(1024)
    logging.info(f"Received server response: {response}")
    response_data = json.loads(response.decode())
    testserver_id= response_data['id']
    print(testserver_id)
    gy = bytes_to_unknown_group_element(from_base64(response_data['gy']))
    gxy = gy.scalarmult(x)  # Correctly compute the shared secret
    key = SHA256.new(gxy.to_bytes()).digest()  # Derive the key from the shared secret
    logging.info(f"Computed shared key: {key.hex()}")

    # Prepare and send the third message
    nonce = randrange(1 << 64)
    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce.to_bytes(12, 'little'))
    plaintext3 = gi.to_bytes() + ed_sign.sign(SHA256.new(key).digest())
    ciphertext3, tag3 = cipher.encrypt_and_digest(plaintext3)

    msg3 = json.dumps({
        'nonce': to_base64(nonce.to_bytes(12, 'little')),
        'ciphertext': to_base64(ciphertext3),
        'tag': to_base64(tag3)
    }).encode()
    sock.sendall(msg3)
    logging.info(f"Sent msg3: {msg3}")

    # Receive and verify the server's final message
    final_response = sock.recv(1024)
    logging.info(f"Received final response from server: {final_response}")
    final_data = json.loads(final_response.decode())
    nonce = from_base64(final_data['nonce'])
    ciphertext4 = from_base64(final_data['ciphertext'])
    tag4 = from_base64(final_data['tag'])

    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    try:
        plaintext4 = cipher.decrypt_and_verify(ciphertext4, tag4)
        print("plaintext4\n" + str(plaintext4))
        logging.info("Server's final message decrypted and verified successfully.")
    except ValueError as e:
        logging.error("Decryption or verification failed.")

    print("\n----------INTERACTING WITH MAIN SERVER----------\n")
    main_server_port = 10001  # Main server port

    # Reuse the test server's id ('friendlyid') for the main server communication
    # This implies the client impersonates the test server or uses its identity in this context
    msg1_main_server = json.dumps({
        'id': testserver_id,  # Use the testserver_id extracted from server_keys.json or similar
        'gx': to_base64(gx.to_bytes()),  # Reuse the same gx
        'cert': to_base64(ed_verif.to_bytes())  # Assume testserver's verification key acts as 'cert'
    }).encode()

    # Open a new socket connection to the main server
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as main_server_sock:
        main_server_sock.connect((host, main_server_port))
        logging.info(f"Connected to main server at {host}:{main_server_port}.")

        # Send the initial message to the main server
        main_server_sock.sendall(msg1_main_server)
        logging.info(f"Sent msg1 to main server: {msg1_main_server}")

        # Receive and process the main server's response (expecting 'gy')
        response_main = main_server_sock.recv(1024)
        logging.info(f"Received response from main server: {response_main}")
        response_data_main = json.loads(response_main.decode())

        # Assuming the main server sends a similar structure in its response, extract 'gy'
        gy_main = bytes_to_unknown_group_element(from_base64(response_data_main['gy']))

        # Use the previously derived key for communication with the main server
        # Note: The actual steps here would depend on how the main server expects the protocol to proceed.
        # For demonstration, let's assume it's similar to the test server interaction.

        # Craft and send a follow-up message or respond to a challenge from the main server
        # This could involve reusing 'msg3' or crafting a new message based on the main server's protocol

        # Finally, handle the main server's final response or complete the protocol as required


if __name__ == "__main__":
    main()
