import socket
import json
from base64 import b64encode, b64decode
from Crypto.Hash import SHA256
from Crypto.Cipher import ChaCha20_Poly1305
from Crypto.Random import get_random_bytes
from Crypto.Random.random import randrange
from pure25519.basic import Base, L
from pure25519 import ed25519_oop as ed25519

def to_base64(obj):
    if isinstance(obj, bytes):
        return b64encode(obj).decode('utf-8')
    else:
        return b64encode(obj.to_bytes()).decode('utf-8')

# Generate the client's key pair
client_signing_key, client_verifying_key = ed25519.create_keypair()

# Simulate client ID
client_id = b"ClientIDExample"
client_id_b64 = to_base64(client_id)

# Generate g^x for the client using a random scalar within the order of the base point
x = randrange(1, L)
gx = Base.scalarmult(x)

# Prepare the first message (id_I, g^x, cert)
msg1 = {
    'id': client_id_b64,
    'gx': to_base64(gx),
    'cert': to_base64(client_verifying_key.to_bytes())
}
msg1_encoded = json.dumps(msg1).encode()

# Server address and port
#server_address = ('nkp.mhgb.net', 10002)
server_address = ('localhost', 10002)
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
    sock.connect(server_address)
    print(f"Connected to {server_address}")

    # Send the first message
    sock.sendall(msg1_encoded)

    # Process server's response and continue the protocol...
    # The remainder of the code would follow as previously outlined,
    # adapting to correctly handle cryptographic operations and network communication.

finally:
    sock.close()

