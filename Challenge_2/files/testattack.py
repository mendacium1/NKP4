import socket
import json
from base64 import b64encode, b64decode
from Crypto.Hash import SHA256
from Crypto.Cipher import ChaCha20_Poly1305
from Crypto.Random import get_random_bytes
from pure25519.basic import Base, L, bytes_to_element
from pure25519 import ed25519_oop as ed25519
import logging

# Konfigurieren des Logging
logging.basicConfig(level=logging.INFO)

def to_base64(obj):
    if isinstance(obj, bytes):
        return b64encode(obj).decode('utf-8')
    else:
        return b64encode(obj.to_bytes()).decode('utf-8')

def create_small_order_point():
    # Beispiel: Verwendung eines Punktes kleiner Ordnung der Größe 8
    small_order_point_hex = "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa"
    small_order_point_bytes = bytes.fromhex(small_order_point_hex)

    # Konvertieren der Byte-Darstellung in ein Element auf der Kurve
    small_order_point = bytes_to_element(small_order_point_bytes)

    # Verwendung des Punktes für eine kryptografische Operation
    # Zum Beispiel könnte hier eine Demonstration einer Operation folgen,
    # die diesen Punkt verwendet, wie das Senden eines kryptografischen Schlüssels
    # oder das Signieren einer Nachricht.
    print(small_order_point)

    return small_order_point

def communicate_with_test_server(server_address, port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((server_address, port))
        logging.info("Verbunden mit dem Testserver.")

        # Erzeugen eines "Small Order Point" als ephemeral public key
        gx = create_small_order_point()
        
        # Senden einer initialen Nachricht mit dem Small Order Point
        msg1 = json.dumps({
            'id': to_base64(b"ClientID"),  # Ihre Client-ID
            'gx': to_base64(gx.to_bytes()),  # Ephemeral public key
            'cert': to_base64(ed25519.create_keypair()[1].to_bytes())  # Zufälliger Verifizierungsschlüssel
        }).encode()

        sock.sendall(msg1)
        logging.info("Initialnachricht gesendet.")

        # Empfangen der Antwort vom Testserver
        response = sock.recv(4096)
        logging.info("Antwort vom Testserver erhalten: {}".format(response.decode()))

        # Hier würden Sie die Antwort des Testservers verarbeiten, um die Challenge zu extrahieren

def impersonate_test_server_to_actual_server(actual_server_address, actual_server_port, extracted_info):
    # Diese Funktion würde die Verbindung zum eigentlichen Server herstellen
    # und die extrahierte Information (z.B. eine Signatur) verwenden,
    # um sich als Testserver auszugeben.
    pass

if __name__ == "__main__":
    test_server_address = 'localhost'
    test_server_port = 10002

    actual_server_address = 'localhost'
    actual_server_port = 10001

    # Schritt 1: Kommunikation mit dem Testserver
    communicate_with_test_server(test_server_address, test_server_port)

    # Schritt 2: Vortäuschen der Identität des Testservers gegenüber dem eigentlichen Server
    # Die Variable `extracted_info` sollte Informationen enthalten, die vom Testserver extrahiert wurden.
    # impersonate_test_server_to_actual_server(actual_server_address, actual_server_port, extracted_info)

