import socket
import json
import string
import requests

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def xor_bytes(a, b):
    a_n = a[:16]
    b_n = b[:16]
    x = bytes(x ^ y for x, y in zip(a_n, b_n))


    # Perform XOR while generating bytes from zipped a and b
    return x + a[16:]

def send_message(s, plaintext, initial_iv=None):
    """ Send a message over an existing socket connection and handle response. """

    # Convert plaintext to bytes if it's not
    if isinstance(plaintext, str):
        plaintext = plaintext.encode('utf-8')

    # If initial_iv is provided, calculate the new plaintext
    if initial_iv:
        plaintext = xor_bytes(plaintext, initial_iv)
        #print(f"send message:\t\t{plaintext.hex()}")

    # Send the plaintext
    s.sendall(plaintext)

    # Receive the response
    data = s.recv(1024)
    if not data:
        raise ValueError("No data received from the server.")

    try:
        # Assume the response is JSON with 'iv' and 'ciphertext'
        response_data = json.loads(data.decode('utf-8'))
    except json.JSONDecodeError:
        raise ValueError("Received data is not in valid JSON format.")

    return response_data

def pj(json_dict):
    return json.dumps(json_dict, indent=4, sort_keys=True)

def task_2(host, port):

    # Set up the socket connection
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))

        sec_size = len(b"secret2=")

        # get secret length in bytes:
        response_data = send_message(s, b" ")
        secret_length = len(response_data['ciphertext']) - sec_size

        byte_size = secret_length + (16 - (secret_length % 16))
        hex_size = byte_size * 2

        init_message = bytes.fromhex("00") * byte_size
        reference_message = bytes.fromhex("00") * (byte_size - sec_size - 1)
        init_bf_message = bytes.fromhex("00") * (byte_size - sec_size - 1) + b"secret2="


        secret2 = ""
        for j in range(0, 100):
            #print(f"init_message:\t\t{init_message.hex()}\t\tlen -> {len(init_message)}")
            #print(f"reference_message:\t{reference_message.hex()}\t\t\t\t\t\t\tlen -> {len(reference_message)}")
            #print(f"init_bf_message:\t{init_bf_message.hex()}\t\t\tlen -> {len(init_bf_message)}")
            #init reset
            init_iv = bytes.fromhex(send_message(s, init_message)['ciphertext'])[-16:]
            # get reference
            response_data = send_message(s, reference_message, init_iv)
            reference_cipher = response_data['ciphertext'][:hex_size]
            #print(f"reference_cipher:\t{reference_cipher}\t\tlen -> {len(reference_cipher)/2}")
            bf_iv = bytes.fromhex(response_data['ciphertext'])[-16:]

            """
            current_char = ""

            for char in string.printable:
                #print("------------------------------------------------------------------------------------------------")
                bf_message = init_bf_message + char.encode()
                #print(f"bf_message:\t\t\t{bf_message.hex()}\t\tlen -> {len(bf_message)}")

                response_data = send_message(s, bf_message, bf_iv)
                bf_iv = bytes.fromhex(response_data['ciphertext'])[-16:]
                #print(f"Check:\t\t\t\t{response_data['ciphertext'][:hex_size]}")
                #print(f"with:\t\t\t\t{reference_cipher}")
                if response_data['ciphertext'][:hex_size] == reference_cipher:
                    #print(f"{bcolors.OKGREEN}found it: {char}{bcolors.ENDC}")
                    current_char = char
                    break
            if current_char == "":
                print(f"{bcolors.FAIL}Done{bcolors.ENDC}")
                exit()
            reference_message = reference_message[:-1]
            init_bf_message = init_bf_message[1:] + current_char.encode()
            secret += current_char
            print(f"{bcolors.HEADER}secret=:\t{secret}{bcolors.ENDC}")
            """
            current_char = 0

            for char in range(0, 256):
                # print("------------------------------------------------------------------------------------------------")
                bf_message = init_bf_message + char.to_bytes(1, 'big')
                # print(f"bf_message:\t\t\t{bf_message.hex()}\t\tlen -> {len(bf_message)}")

                response_data = send_message(s, bf_message, bf_iv)
                bf_iv = bytes.fromhex(response_data['ciphertext'])[-16:]
                # print(f"Check:\t\t\t\t{response_data['ciphertext'][:hex_size]}")
                # print(f"with:\t\t\t\t{reference_cipher}")
                if response_data['ciphertext'][:hex_size] == reference_cipher:
                    # print(f"{bcolors.OKGREEN}found it: {char}{bcolors.ENDC}")
                    current_char = char
                    break
            if current_char == 0:
                print(f"{bcolors.FAIL}Done{bcolors.ENDC}")
                break
            reference_message = reference_message[:-1]
            init_bf_message = init_bf_message[1:] + current_char.to_bytes(1, 'big')
            secret2 += chr(current_char)
            print(f"{bcolors.HEADER}secret2={secret2}{bcolors.ENDC}")

def main():
    host = '193.170.192.172'
    port = 80
    cookie_2 = task_2(host, port)

    url = 'https://www.moneybit.at/challenge3.php'
    cookies = {
        'secret': 'Vanillle',
        'secret2': cookie_2
    }

    response = requests.get(url, cookies=cookies)
    print(response.text)

if __name__ == "__main__":
    main()
