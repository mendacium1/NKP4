import socket
import json

from itertools import cycle


def xor_bytes(a, b):
    """ Helper function to XOR two byte strings with support for repeating the shorter one. """
    # Cycle through the shorter byte string if lengths differ
    if len(a) > len(b):
        b = cycle(b)
    elif len(b) > len(a):
        a = cycle(a)

    # Perform XOR while generating bytes from zipped a and b
    return bytes(x ^ y for x, y in zip(a, b))


def send_message(s, plaintext, initial_iv=None):
    """ Send a message over an existing socket connection and handle response. """

    # Convert plaintext to bytes if it's not
    if isinstance(plaintext, str):
        plaintext = plaintext.encode('utf-8')

    # If initial_iv is provided, calculate the new plaintext
    if initial_iv:
        plaintext = xor_bytes(plaintext, initial_iv)
        print("Xor'ed plaintext: ", plaintext, "len: ", len(plaintext))

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


def main():
    host = '193.170.192.172'
    port = 80
    initial_message = b"0000000"

    # Set up the socket connection
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))

        # Send the initial message and get the first response
        response_data = send_message(s, initial_message)
        initial_iv = bytes.fromhex(response_data['iv'])

        #one time the same:
        print("Sending: ", initial_message)
        response_data = send_message(s, initial_message, initial_iv)
        print("Received IV:", response_data['iv'])
        print("Received Ciphertext:", response_data['ciphertext'])
        print("Last 16: ", response_data['ciphertext'][-16:])
        initial_iv = bytes.fromhex(response_data['ciphertext'])[-16:]
        print("------------------------------------")
        print("Sending: ", initial_message)
        response_data = send_message(s, initial_message, initial_iv)
        print("Received IV:", response_data['iv'])
        print("Received Ciphertext:", response_data['ciphertext'])
        print("Last 16: ", response_data['ciphertext'][-16:])
        initial_iv = bytes.fromhex(response_data['ciphertext'])[-16:]
        print("------------------------------------")

        initial_message = initial_message[:-1]

        # Use the initial_iv to ensure the ciphertext remains the same
        for _ in range(40):
            print("Sending: ", initial_message)
            response_data = send_message(s, initial_message, initial_iv)
            print("Received IV:", response_data['iv'])
            print("Received Ciphertext:", response_data['ciphertext'], "len: ", len(response_data['ciphertext']))
            print("Last 16: ", response_data['ciphertext'][-16:])
            initial_iv = bytes.fromhex(response_data['ciphertext'])[-16:]
            print("------------------------------------")

            mutable_bytes = bytearray(initial_message)
            mutable_bytes[-1] = (mutable_bytes[-1] + 1) % 255
            print("Trying with:", mutable_bytes[-1])
            initial_message = bytes(mutable_bytes)


if __name__ == "__main__":
    main()
