import socket
import json

from itertools import cycle, islice


def xor_bytes(a, b):
    #max_len = max(len(a), len(b))
    
    print(f"a: {a.hex()}")
    print(f"b: {b.hex()}")
    # Cycle through the shorter byte string if lengths differ and ensure it has the same length as the longer string
    if len(a) > len(b):
        b = b[-len(a):]
    if len(a) > len(b):
        b = cycle(b)

    # Perform XOR while generating bytes from zipped a and b
    return bytes(x ^ y for x, y in zip(a, b))

def send_message(s, plaintext, initial_iv=None):
    """ Send a message over an existing socket connection and handle response. """

    # Convert plaintext to bytes if it's not
    if isinstance(plaintext, str):
        plaintext = plaintext.encode('utf-8')

    print(f"input plaintext: {plaintext.hex()}")
    # If initial_iv is provided, calculate the new plaintext
    if initial_iv:
        plaintext = xor_bytes(plaintext, initial_iv)

    print(f"xor'ed plaintext: {plaintext.hex()}")
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


def main():
    host = '193.170.192.172'
    port = 80
    initial_message = bytes.fromhex("00") * (32-len('secret2='))
    initial_message = bytes.fromhex("00") * (16)

    # Set up the socket connection
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))

        # Send the initial message and get the first response
        print(f"Sending inital message: {initial_message} -> len={len(initial_message)}")
        response_data = send_message(s, initial_message)
        print(f"Received response: {pj(response_data)}\nlen(response): {len(response_data['ciphertext'])}")
        #initial_iv = bytes.fromhex(response_data['iv'])
        initial_iv = bytes.fromhex(response_data['ciphertext'])[-16:]
        print(f"Calculated next IV: {initial_iv.hex()}")

        print("---------------------------------------------------")

        #Test if can create same ciphertext again
        print(f"Testing to get identical ciphertext: {initial_message}  -> len={len(initial_message)}\nwith {initial_iv.hex()}")
        response_data = send_message(s, initial_message, initial_iv)
        print(f"Received response: {pj(response_data)}\nlen(response): {len(response_data['ciphertext'])}")
        initial_iv = bytes.fromhex(response_data['ciphertext'])[-16:]
        print(f"Calculated next IV: {initial_iv.hex()}\n")

        response_data = send_message(s, initial_message, initial_iv)
        print(f"Identical response: {pj(response_data)}\nlen(response): {len(response_data['ciphertext'])}")
        initial_iv = bytes.fromhex(response_data['ciphertext'])[-16:]
        print(f"Calculated next IV: {initial_iv.hex()}")

        response_data = send_message(s, initial_message, initial_iv)
        print(f"Identical response: {pj(response_data)}\nlen(response): {len(response_data['ciphertext'])}")
        initial_iv = bytes.fromhex(response_data['ciphertext'])[-16:]
        print(f"Calculated next IV: {initial_iv.hex()}")
        
        print("---------------------------------------------------")

        print(f"Removing 1 byte to get first secret byte.\nbefore:\t{initial_message}")
        brute_force_bytes = initial_message[:-1]
        print(f"after:\t{brute_force_bytes}")
        response_data = send_message(s, brute_force_bytes, initial_iv)
        print(f"Received response: {pj(response_data)}")

        iv_store = initial_iv
        m_store = response_data['ciphertext']

        for char in range(0,255):
            test_bytes = brute_force_bytes + char.to_bytes(2, 'big')
            response_data = send_message(s, test_bytes, initial_iv)
            if response_data['ciphertext'] == m_store:
                print("found something")
            
        
"""        
        print("---------------------------------------------------")

        print(f"Removing 1 byte to get first secret byte.\nbefore:\t{initial_message}")
        brute_force_bytes = initial_message[:-1]
        print(f"after:\t{brute_force_bytes}")
        response_data = send_message(s, brute_force_bytes, initial_iv)
        print(f"Received response: {pj(response_data)}")

        print("---------------------------------------------------")

        print(f"Removing 1 byte to get first secret byte.\nbefore:\t{initial_message}")
        brute_force_bytes = initial_message[:-1]
        print(f"after:\t{brute_force_bytes}")
        response_data = send_message(s, brute_force_bytes, initial_iv)
        print(f"Received response: {pj(response_data)}")
        
        print("---------------------------------------------------")

        print(f"Removing 1 byte to get first secret byte.\nbefore:\t{initial_message}")
        brute_force_bytes = initial_message[:-1]
        print(f"after:\t{brute_force_bytes}")
        response_data = send_message(s, brute_force_bytes, initial_iv)
        print(f"Received response: {pj(response_data)}")
"""      

if __name__ == "__main__":
    main()
