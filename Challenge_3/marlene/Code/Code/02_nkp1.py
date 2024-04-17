from socket import socket, AF_INET, SOCK_STREAM
import json

host = "193.170.192.172"
port = 80

with socket(AF_INET, SOCK_STREAM) as connection:
    connection.connect((host,port))
    cipher = {"AES-CBC-IV": "ec4c6db60363c9b6f63a22778c60612d", "AES-CBC-Ciphertext": "c87ed0072b1acf50899f978df9a26a52758bbe70222b16d213853af643e232cde0d64c371dfd38f01649f6f866aa9d31506bed455ac93d1cf98624808c5a74abf6fe53d1093d6de8c7e4895f6a3feb30761ed76e43d5fbd457c9aef512ed6332"}
    cipher_m = json.dumps(cipher)
    connection.sendall(bytes(cipher_m, encoding="utf-8"))
    response = connection.recv(1024) 
    response = response.decode("utf-8")
    print("sent: {}".format(response))    
    