import socket
import json
from base64 import b64encode, b64decode
from Crypto.Hash import SHA256
from pure25519.basic import Base, L
from pure25519 import ed25519_oop as ed25519
from pure25519.basic import Base, Zero


def find_small_order_point(order):
    """
    Attempts to find a point of a given small order (2 or 4) on an elliptic curve.
    This function iteratively multiplies the base point by increasing scalars
    to check for points of the desired order.

    Args:
    - order (int): The order of the point to find (2 or 4).

    Returns:
    - bytes or None: The byte representation of a point with the specified order,
      or None if such a point is not found.
    """
    for i in range(1, 100000):  # Limit for demonstration; in practice, adjust as necessary.
        # Generate a candidate point by scalar multiplication of the base point
        candidate_point = Base.scalarmult(i)

        # Check if multiplying the candidate by its presumed order results in Zero
        if candidate_point.scalarmult(order) == Zero:
            print(f"Found a point of order {order}: Scalar {i}")
            return candidate_point.to_bytes()

    print(f"No point of order {order} found within the limit.")
    return None


# Try to find points of order 2 or 4 (Demonstration purposes)
point_order_2 = find_small_order_point(2)
print("Point of order 2:", point_order_2)

point_order_4 = find_small_order_point(4)
print("Point of order 4:", point_order_4)

# Assuming the existence of a "small order point" for demonstration purposes
SMALL_ORDER_POINT = b"\x00" * 32  # This is not a real small order point but serves as a placeholder


# Helper function to encode data to base64
def to_base64(obj):
    if isinstance(obj, bytes):
        return b64encode(obj).decode('utf-8')
    else:
        return b64encode(obj.to_bytes()).decode('utf-8')


# Main attacker function
def attack(server_a_address, server_b_address, attacker_id, attacker_sign_key):
    # Step 1: Connect to Server A and initiate handshake
    sock_a = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock_a.connect(server_a_address)

    # Generate ephemeral keys for the attack (using small order point)
    gx = SMALL_ORDER_POINT  # Attacker's public key, should be a valid small order point

    # Send initial message to Server A
    msg1_a = json.dumps({'id': to_base64(attacker_id), 'gx': to_base64(gx)}).encode()
    sock_a.sendall(msg1_a)

    # Receive response from Server A
    response_a = json.loads(sock_a.recv(1024).decode())
    gy_a = b64decode(response_a['gy'])  # Server A's ephemeral public key

    # Complete the handshake with Server A to steal the signature (omitted for brevity)
    # Normally, here you'd decrypt Server A's response, but given the placeholder values, we'll simulate it

    # Simulate obtaining Server A's signature on the constant challenge
    fake_signature = b"\x00" * 64  # Placeholder for the actual signature you'd obtain

    # Step 2: Connect to Server B and use Server A's identity
    sock_b = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock_b.connect(server_b_address)

    # Initiate handshake with Server B using the same small order point and the stolen signature
    msg1_b = json.dumps(
        {'id': to_base64(attacker_id), 'gx': to_base64(gx), 'signature': to_base64(fake_signature)}).encode()
    sock_b.sendall(msg1_b)

    # Receive response from Server B and continue as needed for the demonstration

    sock_a.close()
    sock_b.close()


if __name__ == "__main__":
    attacker_id = b"attacker"
    attacker_sign_key = ed25519.SigningKey.generate()  # For demonstration, a real attack would use specific keys

    server_a_address = ('127.0.0.1', 10002)  # Address for Server A
    server_b_address = ('127.0.0.1', 10001)  # Address for Server B

    attack(server_a_address, server_b_address, attacker_id, attacker_sign_key)
