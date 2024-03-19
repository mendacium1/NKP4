import json
from base64 import b64encode
from os import urandom
from pure25519 import ed25519_oop as ed25519

def generate_server_keys():
    # Generate the key pair
    ed_sign, ed_verif = ed25519.create_keypair()
    
    # Generate a random server ID or use a predefined one
    server_id = urandom(16)  # 16 bytes random ID, you can adjust the size or set a specific value
    
    # Convert the server ID, signing key, and verifying key to base64 to store them as strings
    server_id_b64 = b64encode(server_id).decode('utf-8')
    sign_key_b64 = b64encode(ed_sign.to_bytes()).decode('utf-8')
    # No need to store the verifying key as it can be derived from the signing key, but it's shown here for completeness
    verif_key_b64 = b64encode(ed_verif.to_bytes()).decode('utf-8')
    
    # Store the keys in a JSON file
    keys = {
        'id2': server_id_b64,
        'sign2': sign_key_b64,
        'verif2': verif_key_b64  # Optional, for reference only
    }
    
    with open('server_keys.json', 'w') as json_file:
        json.dump(keys, json_file)
    
    print("Server keys and ID have been generated and stored in server_keys.json")

generate_server_keys()

