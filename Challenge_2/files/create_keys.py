import json
from base64 import b64encode
from os import urandom
from pure25519 import ed25519_oop as ed25519


def generate_server_keys():
    # Generate key pairs for the server and the test server
    ed_sign_server, _ = ed25519.create_keypair()
    ed_sign_testserver, ed_verif_testserver = ed25519.create_keypair()

    # Generate random IDs
    server_id = urandom(16)
    testserver_id = urandom(16)

    # Convert to base64
    server_id_b64 = b64encode(server_id).decode('utf-8')
    testserver_id_b64 = b64encode(testserver_id).decode('utf-8')
    sign_key_b64_server = b64encode(ed_sign_server.to_bytes()).decode('utf-8')
    sign_key_b64_testserver = b64encode(ed_sign_testserver.to_bytes()).decode('utf-8')
    verif_key_b64_testserver = b64encode(ed_verif_testserver.to_bytes()).decode('utf-8')

    # Define a handshake success flag
    handshake_success = "test handshake successful"
    test_handshake_success_b64 = b64encode(handshake_success.encode('utf-8')).decode('utf-8')

    keys = {
        'server_id': server_id_b64,
        'server_sign_key': sign_key_b64_server,
        'testserver_id': testserver_id_b64,
        'testserver_sign_key': sign_key_b64_testserver,
        'testserver_verif_key': verif_key_b64_testserver,
        'flag': test_handshake_success_b64
    }

    with open('server_keys.json', 'w') as json_file:
        json.dump(keys, json_file)

    print("Server and test server keys and IDs have been generated and stored in server_keys.json")


generate_server_keys()


