import socket
import Crypto
import zlib
import json


def createResponse(self, plaintext):
    cipher = Crypto.Chipher.ChaCha20_Poly1305.new(key=self.key)
    ciphertext, tag = cipher.encrypt_and_digest(zlib.compress(plaintext + b" secret = "
                                                              + self.secret))
    json_keys = ["nonce", "ciphertext", "tag"]
    json_values = [cipher.nonce.hex(), ciphertext.hex(), tag.hex()]
    response = json.dumps(dict(zip(json_keys, json_values))).encode("utf-8")
    return response

if __name__ == '__main__':
    server_address = ('localhost', 10000)
    print(f"Connecting to {server_address}...")

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(server_address)
    sock.sendall("test1")

    sock.recv(1024)

    sock.close()
