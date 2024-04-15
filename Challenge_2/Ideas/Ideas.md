
## create keys
```python
import json  
from base64 import b64encode  
from os import urandom  
from pure25519 import ed25519_oop as ed25519  
  
def generate_server_keys():  
  
    ed_sign_1, ed_verif_1 = ed25519.create_keypair()  
  
    server_id_1 = urandom(16)  
    server_id_b64_1 = b64encode(server_id_1).decode('utf-8')  
    sign_key_b64_1 = b64encode(ed_sign_1.to_bytes()).decode('utf-8')  
    verif_key_b64_1 = b64encode(ed_verif_1.to_bytes()).decode('utf-8')  
  
  
    # Generate the key pair  
    ed_sign_2, ed_verif_2 = ed25519.create_keypair()  
      
    # Generate a random server ID or use a predefined one  
    server_id_2 = urandom(16)  # 16 bytes random ID, you can adjust the size or set a specific value  
        # Convert the server ID, signing key, and verifying key to base64 to store them as strings  
    server_id_b64_2 = b64encode(server_id_2).decode('utf-8')  
    sign_key_b64_2 = b64encode(ed_sign_2.to_bytes()).decode('utf-8')  
    # No need to store the verifying key as it can be derived from the signing key, but it's shown here for completeness  
    verif_key_b64_2 = b64encode(ed_verif_2.to_bytes()).decode('utf-8')  
      
    # Store the keys in a JSON file  
    keys = {  
        'id1': server_id_b64_1,  
        'sign1': sign_key_b64_1,  
        'verif1': verif_key_b64_1,  
        'id2': server_id_b64_2,  
        'sign2': sign_key_b64_2,  
        'verif2': verif_key_b64_2  # Optional, for reference only  
    }  
      
    with open('server_keys.json', 'w') as json_file:  
        json.dump(keys, json_file)  
      
    print("Server keys and ID have been generated and stored in server_keys.json")  
  
generate_server_keys()
```


## Protokoll

I = Initiator
R = Responder

msg1:
id = identifier
gx = public-key
cert = signature verification key



```
The Tendermint Protocol
1. I -> R: id_I, g^x
2. R -> I: id_R, g^y
	k = g^xy
3. I -> R: E_k( g^i, Sign_i(H(k)) )
4. R -> I: E_k( g^r, Sign_r(H(k)), flag )
where
    i = hash(id_I)
    r = hash(id_R)
```

