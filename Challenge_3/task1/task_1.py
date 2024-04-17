import json
import socket
import zlib
from string import ascii_letters

# Der Server, zu dem wir uns verbinden
SERVER_HOST = '193.170.192.172'
SERVER_PORT = 31337
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((SERVER_HOST, SERVER_PORT))

msg1 = "secret="    # durch zlib wird "'secret=' + b'secret='" zu "secret="

def send_and_get_len(char):
    msg = ("secret=" + char).encode()
    sock.send(msg)
    response = json.loads(sock.recv(4096))
    ciphertext_len = len(response["ciphertext"])
    return(ciphertext_len)

string = ""
for i in range(8):
    d = dict()
    for char in ascii_letters:
        d[char] = send_and_get_len(string + char)
        print(f"len: {d[char]}\ttrying: {string + char}")

    res = dict((v,k) for k,v in d.items())
    if len(res) < 2:
        d=dict()
        for char in ascii_letters:
            d[char+char] = send_and_get_len(string + char + char)
            print(f"len: {d[char+char]}\ttrying: {string + char + char}")
        string += str(min(d, key=d.get))
    else:
        string += min(d, key=d.get)
print(f"Das secret lautet: {string}")
