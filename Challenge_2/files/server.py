import socket
import threading

import json
from base64 import b64encode, b64decode

from pure25519.basic import bytes_to_unknown_group_element, Base, L, Zero
from pure25519 import ed25519_oop as ed25519

from Crypto.Random.random import randrange
from Crypto.Cipher import ChaCha20_Poly1305
from Crypto.Hash import SHA256

# -- logging
import logging
from rich.logging import RichHandler
logging.basicConfig(
    level="NOTSET",
    format="%(message)s",
    datefmt="[%X]",
    handlers=[RichHandler(rich_tracebacks=True)]
)
# logging --

"""
The Tendermint Protocol
1. I -> R: id_I, g^x
2. R -> I: id_R, g^y
	k = g^xy
3. I -> R: E_k( g^i, Sign_i(H(k)) )
4. R -> I: E_k( g^r, Sign_r(H(k)), flag )
where
    i = hash(id_I)
    r = hash(id_R)
"""

def to_base64( obj ):
	if isinstance( obj, bytes ):
		return b64encode( obj ).decode('utf-8')
	else:
		return b64encode( obj.to_bytes() ).decode('utf-8')

class InitiatorUnknownError(Exception):
	pass
class AuthenticationFailed(Exception):
	pass
class InvalidMessage(Exception):
	pass

class ThreadedServer(object):

	with open('server_keys.json') as json_file:
		params = json.load(json_file)
		# id and key pair for server
		serverid = b64decode( params['server_id'] )
		logging.info(f"Read server ID: {serverid}.")
		ed_sign = ed25519.SigningKey( b64decode( params['server_sign_key'] ) )
		logging.info("Read signing key.")
		ed_verif = ed_sign.get_verifying_key()
		logging.info("Extracted verification key.")
		# id and verification key for second server
		friendlyid = b64decode( params['testserver_id'] )
		print("friendlyid:\n" + str(friendlyid))
		logging.info(f"Read testserver ID: {friendlyid}.")
		friendly_ed_verif = ed25519.VerifyingKey( b64decode( params['testserver_verif_key'] ) )
		logging.info("Read testserver verification key.")
		# flag to be captured
		flag = bytes( params['flag'], 'utf-8' )
		logging.info(f"Read flag: {flag}.")

	# precompute numerical ids of the two servers
	r = int( SHA256.new( serverid ).hexdigest(), base=16 ) % L
	gr = Base.scalarmult(r)
	i = int( SHA256.new( friendlyid ).hexdigest(), base=16 ) % L
	gi = Base.scalarmult(i).to_bytes()

	def __init__(self, host, port):
		self.host = host
		self.port = port
		self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		self.sock.bind((self.host, self.port))
		logging.info(f"Listening on {host}:{port}.")

	def listen(self):
		self.sock.listen(5)
		while True:
			client, address = self.sock.accept()
			client.settimeout(60)
			logging.info(f"Connection from {address}.")
			threading.Thread(target = self.listenToClient,args = (client,address)).start()

	def response1( self, msg1, state ):
		"""
		server response to first message
		expects (all values are base64 encoded):
			{'id': ..., 'gx': ... }
			id (base64)    : ID of the protocol initiator
			gx (base64)    : initiators (g^x).to_bytes()
		delivers:
			{'id': ..., 'gy': ... }
			id (base64)    : own ID
			gy (base64)    : own (g^y).to_bytes()
		side effects:
			adds 'key' to the state dictionary
		"""
		logging.info( f'[rcv] msg1: {msg1}')

		# parse incoming message
		try:
			clientid = b64decode( json.loads( msg1.decode() )['id'] )
			gx = bytes_to_unknown_group_element( b64decode( json.loads( msg1.decode() )['gx'] ) )
			if gx == Zero:
                            # this would lead to a fixed key
                            logging.warning("received group identity")
                            raise InvalidMessage
		except:
			logging.warning( "Invalid message" )
			raise InvalidMessage

		logging.info( f"Request from {clientid}" )

		# only friendlyid is a valid client, abort handshake with other clients
		if clientid != self.friendlyid:
			logging.warning( "Request from unknown client ... aborting." )
			raise InitiatorUnknownError

		y = randrange( L )
		gy = Base.scalarmult(y)

		msg2 = json.dumps( {'id': to_base64( self.serverid ),
							'gy': to_base64( gy )}
							).encode()
		gxy = gx.scalarmult(y)

		key = SHA256.new( gxy.to_bytes() ).digest()
		logging.info( f'key (hex): {key.hex()}' )
		state["key"] = key
		
		logging.info( f'[snd] msg2: {msg2}')
		return msg2

	def response2( self, msg3, state ):
		"""
		server response to third message
		expects (all values are base64 encoded):
			{'nonce': ..., 'ciphertext': ..., 'tag': ... }
			nonce (base64)      : nonce used for encryption
			ciphertext (base64) : resulting ciphertext
            tag (base64)        : authentication tag
		delivers (all values are base64 encoded):
			{'nonce': ..., 'ciphertext': ..., 'tag': ... }
			nonce (base64)      : nonce used for encryption
			ciphertext (base64) : resulting ciphertext (encrypted flag)
			tag (base64)        : authentication tag
		"""
		logging.info( f'[rcv] msg3: {msg3}.')

		# parse incoming message
		try:
			nonce = b64decode( json.loads( msg3.decode() )['nonce'] )
			ciphertext3 = b64decode( json.loads( msg3.decode() )['ciphertext'] )

			tag3 = b64decode( json.loads( msg3.decode() )['tag'] )
		except:
			logging.warning( "Invalid message" )
			raise InvalidMessage

		key = state["key"]

		try:
			cipher = ChaCha20_Poly1305.new( key=key, nonce=nonce )
			plaintext3 = cipher.decrypt_and_verify( ciphertext3, tag3 )
			gi = plaintext3[:32]
			sig = plaintext3[-64:]
		except (ValueError, KeyError):
			logging.warning( "Decryption failed" )
			raise InvalidMessage

		if self.gi != gi:
			logging.warning('Authentication Failed!')
			raise AuthenticationFailed

		# verify signature
		try:
			self.friendly_ed_verif.verify( sig, SHA256.new(key).digest() )
		except:
			logging.warning( "Invalid signature" )
			raise AuthenticationFailed

		# prepare response
		sig = self.ed_sign.sign( SHA256.new(key).digest() )
		plain4 = self.gr.to_bytes() + sig + self.flag

		cipher = ChaCha20_Poly1305.new( key=key )
		ciphertext4, tag4 = cipher.encrypt_and_digest( plain4 )

		msg4 = json.dumps( {'nonce': to_base64( cipher.nonce ),
							'ciphertext': to_base64( ciphertext4 ),
							'tag': to_base64( tag4 )}
							).encode()

		logging.info( f'[snd] msg4: {msg4}.')
		logging.info('Protocol finished successfully.')
		return msg4

	def listenToClient(self, client, address):
		size = 1024
		while True:
			try:
				msg1 = client.recv(size)
				state = {}
				if msg1:
					msg2 = self.response1( msg1, state )
					client.sendall( msg2 )
				else:
					logging.info( "Client disconnected.")
					raise Exception('Client disconnected.')
				msg3 = client.recv(size)
				if msg3:
					msg4 = self.response2( msg3, state )
					client.sendall( msg4 )
				else:
					logging.warning('Client disconnected.')
					raise Exception('Client disconnected.')
			except Exception as inst:
				client.close()
				return False

if __name__ == "__main__":
	ThreadedServer('127.0.0.1',10001).listen()



	
