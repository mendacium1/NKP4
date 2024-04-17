import json
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto import Util


secret = "geheimnis".encode()
key = "testkey"
key = SHA256.new(key.encode()).digest()

def createResponse(plaintext):
    iv = "kollercounter"
    iv = iv.encode()
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(Util.Padding.pad(plaintext + b"secret2=" + secret, 16))
    jsonkeys = ["iv","ciphertext"]
    jsonvalues = [cipher.iv.hex(), ciphertext.hex()]
    response = json.dumps(dict(zip(jsonkeys,jsonvalues))).encode("utf-8")
    iv = ciphertext[-16:]
    return response

def createResponse(self, plaintext):
    cipher = Crypto.Cipher.AES.new(self.key, Crypto.Cipher.AES.MODE_CBC, self.iv)
    ciphertext = cipher.encrypt(Crypto.Util.Padding.pad(plaintext + b"secret2=" + self.secret, 16))
    jsonkeys = ["iv", "ciphertext"]
    jsonvalues = [cipher.iv.hex(), ciphertext.hex()]
    response = json.dumps(dict(zip(jsonkeys,jsonvalues))).encode("utf-8")
    self.iv = ciphertext[-16:]
    return response

