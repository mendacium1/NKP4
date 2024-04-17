import socket
import json
from operator import xor
import base64

aes_cbc_iv = "ec4c6db60363c9b6f63a22778c60612d"

host = "193.170.192.172"
port = 80
padding = ""

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

def manipulate_padding(padding, cipher_list, cipher_original):
    padding_new= []
    m = ""
    # Startpunkt == vorletzter Block
        # nach den letzten 33 Zeichen ist Start (2*16 wegen hex)
    start_char = -33
    # bestimmt wo Padding bearbeitet werden soll
    padding_len = len(padding) + 1
    cipher_original_list = list(cipher_original)
    # gehen string durch und berechnen den neuen Padding
    for value in padding:
        # wählen immer 2 Zeichen aus dem Chiffrat aus
        hex_value = cipher_original[start_char-1] + cipher_original_list[start_char]
        # berechnen 2 Zeichen XOR mit der Position des Paddings
        key_value = xor(int(value,16), (padding_len-1))
        # berechnen  Erg. XOR neuem Padding
        new_hex_value = format(xor(key_value, padding_len), "02x")
        # berechnen Erg. XOR den ursprünglichen 2 Zeichen
        m_value = xor(key_value, int(hex_value,16))
        # konvertiere den NAinhalt in Unicode
        m = chr(m_value) + m
        padding_new.append(new_hex_value)
        cipher_list[start_char-1] = new_hex_value[0]
        cipher_list[start_char] = new_hex_value[1]
        start_char -= 2
    return padding_new, "".join(cipher_list), m

def find_plaintext(cipher, sock):
    cipher_list = list(cipher)
    plaintext = ""
    cipher_original = cipher
    anfragen = 0
    # Anzahl an Blöck = 6
        # Ohne den letzten Block
    number_blocks = (len(cipher)//32)
    print(f"Anzahl der Blöcke insgesamt {number_blocks}")
    # Durchlauf durch die Anzahl an Blöcke (Gesamt: 6)
    for b in range(number_blocks):
        print(f"Blocknummer: {b}")
        # Start vorletzter Block - hex (16*2)
        start_char = -33
        padding_list = list()
        # ersetzen das ürsprüngliche Zeichen in der Cipher
            # mit dem neuen der das gewünschte Padding erzeugt
        for value in range(16):
            # probieren Kombinationen durch um Padding zu finden
            for char in range(256):
                # Convertierung der nummer in hex (immer 2 Zeichen)
                char_hex = format(char,"02x")
                # ersetzen das ürsprüngliche Zeichen in der Cipher
                    # mit dem neuen
                cipher_list[start_char - 1] = char_hex[0]
                cipher_list[start_char] = char_hex[1]
                
                cipher = "".join(cipher_list)
                # schicken Cipher an Orakel
                get_response = get_response_oracle(cipher, sock)
                # Überprüfen ob Padding richtig ist
                anfragen += 1
                if(check_pkcs7_padding(get_response, value)):
                    padding_list.append(char_hex)
                    if b == 5:
                        temp = manipulate_padding(padding_list, cipher_list, cipher_original)
                        padding_list = temp[0]
                        cipher = temp[1]
                        m = temp[2]
                        print(f"Bearbeitete Cipher: {cipher[-64:-32]}")
                        start_char-=2
                        print(f"Bisheriger entschlüsselter Klartext: {m}")
                        break
                    else:
                        temp = manipulate_padding(padding_list, cipher_list, cipher_original)
                        padding_list = temp[0]
                        cipher = temp[1]
                        m = temp[2]
                        print(f"Bearbeitete Cipher: {cipher[-64:-32]}")
                        start_char-=2
                        print(f"Bisheriger entschlüsselter Klartext: {m}")
                        break
                           
        print(f"Anfragen pro Block {anfragen}")
        # werfen die letzten 16 Bytes weg - wenn sich der Block vergrößert
        cipher = "".join(list(standard_cipher)[:(-32*(b+1))])
        cipher_original = cipher
        print("_____________________________________")
        print(f"Verkürzte Cipher {cipher}")
        cipher_list = list(cipher)
        plaintext = m + plaintext
        print("_________________________")
        print(f"Nach Block {b} Plaintext: {plaintext}")
        
        if b == 4:
            temp = cipher
            cipher = aes_cbc_iv + temp
            cipher_original = cipher
            cipher_list = list(cipher)
        

    print(f"PLAINTEXT:\n {plaintext}") 
    print(f"Gesamtanzahl an Anfragen: {anfragen}")     
     


sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((host,port))
standard_cipher = "c87ed0072b1acf50899f978df9a26a52758bbe70222b16d213853af643e232cde0d64c371dfd38f01649f6f866aa9d31506bed455ac93d1cf98624808c5a74abf6fe53d1093d6de8c7e4895f6a3feb30761ed76e43d5fbd457c9aef512ed6332"
find_plaintext(standard_cipher,sock)


sock.close()





























