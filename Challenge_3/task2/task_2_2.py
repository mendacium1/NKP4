import socket
import json
from itertools import cycle
from time import sleep


def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def send_modified_message(s, modified_ciphertext, expected_iv):
    s.sendall(json.dumps({'iv': expected_iv.hex(), 'ciphertext': modified_ciphertext.hex()}).encode('utf-8'))
    data = s.recv(1024)
    return data


def detect_padding_oracle(host, port, ciphertext, iv):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))
        # Split the ciphertext into blocks
        block_size = 16
        blocks = [ciphertext[i:i + block_size] for i in range(0, len(ciphertext), block_size)]
        last_block = blocks[-1]
        second_last_block = blocks[-2]

        # Try modifying the last byte of the second-last block
        for byte in range(256):
            modified_block = bytearray(second_last_block)
            modified_block[-1] ^= byte  # Modify the last byte
            modified_iv = bytes(modified_block)

            # Send the modified block with the original last block as the new ciphertext
            new_ciphertext = bytes(modified_block + last_block)
            response = send_modified_message(s, new_ciphertext, iv)

            # Check the server's response to determine if the padding was correct
            if "padding error" not in response.decode():
                print(f"Valid padding found with byte: {byte}")
                break


def main():
    host = '193.170.192.172'
    port = 80
    # You need to obtain the ciphertext and IV from your earlier communication or by any other means
    ciphertext = bytes.fromhex(
        "cca128e3cbebc8f93f481545964c408f99d98124b33d943389aca68d78379ce63f7c90ffefc0e483360f30b69475e050ff3a5355ede4c9a2cb9f030e5ca0f026")
    iv = bytes.fromhex("4183b435dae6f79976fba6b9475a1f3d")

    detect_padding_oracle(host, port, ciphertext, iv)


if __name__ == "__main__":
    main()
