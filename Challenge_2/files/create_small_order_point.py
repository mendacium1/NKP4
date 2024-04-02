import socket
import json
from base64 import b64encode
from Crypto.Hash import SHA256
from Crypto.Cipher import ChaCha20_Poly1305
from Crypto.Random import get_random_bytes
from pure25519.basic import Base, L
from pure25519 import ed25519_oop as ed25519

def to_base64(obj):
    if isinstance(obj, bytes):
        return b64encode(obj).decode('utf-8')
    else:
        return b64encode(obj.to_bytes()).decode('utf-8')

# Generiere das Schlüsselpaar des Clients
client_signing_key, client_verifying_key = ed25519.create_keypair()

# Simuliere die Client-ID
client_id = b"ClientIDExample"
client_id_b64 = to_base64(client_id)

# Serveradresse und Port
server_address = ('localhost', 10002)
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
    sock.connect(server_address)
    print(f"Verbunden mit {server_address}")

    for x in range(1, 11):
        # Generiere g^x für den Client mit einem festen Skalar innerhalb der Ordnung des Basispunktes
        gx = Base.scalarmult(x)

        # Bereite die erste Nachricht vor (id_I, g^x, cert)
        msg1 = {
            'id': client_id_b64,
            'gx': to_base64(gx),
            'cert': to_base64(client_verifying_key.to_bytes())
        }
        msg1_encoded = json.dumps(msg1).encode()

        # Sende die erste Nachricht
        sock.sendall(msg1_encoded)
        
        # Hier könnten Sie die Antwort des Servers verarbeiten...
        # Für dieses Beispiel wird dies übersprungen.

        # Setze die Verbindung zurück für den nächsten Durchlauf
        sock.close()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(server_address)

finally:
    sock.close()

