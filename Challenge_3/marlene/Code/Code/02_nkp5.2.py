import socket
import json
from operator import xor

aes_cbc_iv = "ec4c6db60363c9b6f63a22778c60612d"

host = "193.170.192.172"
port = 80
padding = ""
anfragen = 0

def check_pkcs7_padding(response, value):
    # schönere Darstellung 
        # HTTP/1.1 301 Moved Permanently
        # Location: https://www.moneybit.at/login
    decode_response = str(response, "utf-8")
    # 400 == Bad Request
        # Padding ist nicht korrekt
    if "400" in decode_response:
        return False
    # 404 == Not Found
        # Padding ist korrekt
    if "404" in decode_response:
        return True
        # 301 == Moved Permanently
            # Anfangszustand - Padding ist korrekt
    if "301" in decode_response and value != 0:
        return True
        
def get_response_oracle(cipher, socket):
    # Erstellung des Formates für das Orakel 
    oracle_format = {"AES-CBC-IV": aes_cbc_iv,
                     "AES-CBC-Ciphertext": cipher}
    formated_message = bytes(json.dumps(oracle_format), encoding="utf-8")
    # senden zum Orakle
    socket.sendall(formated_message)
    response = socket.recv(1024) 
    return response

def manipulate_padding(padding_list, cipher_list, cipher_original):
    # manipulate padding
    padding_new= []
    m = ""
    start_char = -33
    padding_len = len(padding_list) + 1

    cipher_original_list = list(cipher_original)
    # gehen string durch und berechnen den neuen Padding
    for value in padding_list:
        # wählen immer 2 Zeichen aus dem Chiffrat aus
        hex_value = cipher_original[start_char-1] + cipher_original_list[start_char]
        # berechnen 2 Zeichen XOR mit der Position des Paddings
        key_value = xor(int(value,16), (padding_len-1))
        print(f"{key_value} = {value} XOR {padding_len-1}")
        # berechnen  Erg. XOR neuem Padding
        new_hex_value = format(xor(key_value, padding_len), "02x")
        print(f"{new_hex_value} = {key_value} XOR {padding_len}")
        # berechnen Erg. XOR den ursprünglichen 2 Zeichen
        m_value = xor(key_value, int(hex_value,16))
        # konvertiere den NAinhalt in Unicode
        m = chr(m_value) + m
        padding_new.append(new_hex_value)
        cipher_list[start_char-1] = new_hex_value[0]
        cipher_list[start_char] = new_hex_value[1]
        start_char -= 2
    return padding_new, "".join(cipher_list), m

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((host,port))
cipher = "c87ed0072b1acf50899f978df9a26a52758bbe70222b16d213853af643e232cde0d64c371dfd38f01649f6f866aa9d31506bed455ac93d1cf98624808c5a74abf6fe53d1093d6de8c7e4895f6a3feb30761ed76e43d5fbd457c9aef512ed6332"

cipher_list = list(cipher)
plaintext = ""
cipher_original = cipher
# Start vorletzter Block - hex (16*2)
start_char = -33
padding_list = list()
for i in range(16):
    for char in range(256):
        # Konvertierung der Nummer in hex (immer 2 Zeichen)
        char_hex = format(char,"02x")
        # ersetzen das ürsprüngliche Zeichen in der Cipher
            # mit dem neuen der das gewünschte Padding erzeugt
        cipher_list[start_char - 1] = char_hex[0]
        cipher_list[start_char] = char_hex[1]
        
        cipher = "".join(cipher_list)
        # schicken Cipher an Orakel
        anfragen += 1
        get_response = get_response_oracle(cipher, sock)
        
        # Überprüfen ob Padding richtig ist
        if(check_pkcs7_padding(get_response,i)):
            padding_list.append(char_hex)
            temp = manipulate_padding(padding_list, cipher_list, cipher_original)
            padding_list = temp[0]
            cipher = temp[1]
            m = temp[2]         
            print(f"Bearbeitete Cipher: {cipher[-64:-32]}")
            start_char-=2
            break
    print(f"Bisheriger entschlüsselter Klartext: {m}")
#break
plaintext = m + plaintext
print("_________________________")
print(f"Plaintext: {plaintext}")
print(anfragen)