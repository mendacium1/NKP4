from socket import socket, AF_INET, SOCK_STREAM
from string import printable
from string import ascii_letters,digits,punctuation
import json
from operator import xor

host = "193.170.192.172"
port = 80
aes_cbc_iv = "ec4c6db60363c9b6f63a22778c60612d"

def get_response_oracle(cipher, socket):
    # Erstellung des Formates für das Orakel 
    oracle_format = {"AES-CBC-IV": aes_cbc_iv,
                     "AES-CBC-Ciphertext": cipher}
    formated_message = bytes(json.dumps(oracle_format), encoding="utf-8")
    # senden zum Orakle
    socket.sendall(formated_message)
    response = socket.recv(1024) 
    #print(str(response, encoding="utf-8"))
    return str(response, encoding="utf-8")



sock = socket(AF_INET, SOCK_STREAM)
sock.connect((host,port))
standard_cipher = "c87ed0072b1acf50899f978df9a26a52758bbe70222b16d213853af643e232cde0d64c371dfd38f01649f6f866aa9d31506bed455ac93d1cf98624808c5a74abf6fe53d1093d6de8c7e4895f6a3feb30761ed76e43d5fbd457c9aef512ed6332"

# Position Padding finden
    # vorletzter Block
    # Veränderung des vorletzten Blocks von hinten nach vorne                                                                                                                                                 |f6fe53d1093d6de8c7e4895f6a3feb30|761ed76e43d5fbd457c9aef512ed6332
    #{"AES-CBC-IV": "ec4c6db60363c9b6f63a22778c60612d", "AES-CBC-Ciphertext": "c87ed0072b1acf50899f978df9a26a52758bbe70222b16d213853af643e232cde0d64c371dfd38f01649f6f866aa9d31506bed455ac93d1cf98624808c5a74abf6fe5f6fe53d1093d6de8c7e4895f6a3feb3076e43d5fbd457c9aef512ed6332"}
#                                                                                                                                         |                              |                                |
cipher = "c87ed0072b1acf50899f978df9a26a52758bbe70222b16d213853af643e232cde0d64c371dfd38f01649f6f866aa9d31506bed455ac93d1cf98624808c5a74abf6fe53d1093d6de8c7e4895f6a3feb30761ed76e43d5fbd457c9aef512ed6332"
#                                                                                                                                                    |               c7             |                                |
cipher_padding_07 = "c87ed0072b1acf50899f978df9a26a52758bbe70222b16d213853af643e232cde0d64c371dfd38f01649f6f866aa9d31506bed455ac93d1cf98624808c5a74abf6fe53d1093d6de8c8e4895f6a3feb30761ed76e43d5fbd457c9aef512ed6332"
print(f"Standard Cipher {get_response_oracle(cipher,sock)}")
print(f"Padding gefunden an Position 7 {get_response_oracle(cipher_padding_07,sock)}")

sock.close()

