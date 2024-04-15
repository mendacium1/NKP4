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

# -- logging setup
logging.basicConfig(
    level="NOTSET",
    format="%(message)s",
    datefmt="[%X]",
    handlers=[RichHandler(rich_tracebacks=True)]
)
# logging --

def to_base64(obj):
    if isinstance(obj, bytes):
        return b64encode(obj).decode('utf-8')
    else:
        return b64encode(obj.to_bytes()).decode('utf-8')

def from_base64(data):
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

host = '127.0.0.1'
port = 10002

# Create a socket and connect to the server
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((host, port))
logging.info(f"Connected to server at {host}:{port}.")

# Prepare and send the first message
msg1 = json.dumps({
    'id': to_base64(client_id),
    'gx': to_base64(gx.to_bytes()),
    'cert': to_base64(ed_verif.to_bytes())
}).encode()
sock.sendall(msg1)
logging.info(f"Sent msg1: {msg1}")

# Receive and process the server's response
response = sock.recv(1024)
logging.info(f"Received server response: {response}")
response_data = json.loads(response.decode())
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

sock.close()
logging.info("Connection closed.")
