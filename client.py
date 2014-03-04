import os
import sys
import ssl
import socket
import logging
from Crypto import Random
from Crypto.PublicKey import RSA
from Crypto.Hash import MD5
import constants

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

class Client(object):
	'''ssl client implementation.'''

	def __init__(self, uid, port=10001):
		self.uid = uid
		self.port = port
		
		self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.client = ssl.wrap_socket(self.sock, ca_certs=constants.SERVER_CRT_PATH, cert_reqs=ssl.CERT_REQUIRED)
		self.client.connect(('127.0.0.1', self.port))
		
		self.pubkey, self.privkey = None, None
		self.init_keys()
		
		self.buffer = ''
		self.write(constants.OP_PUBKEY, self.pubkey)
		
		#self.send(1, 'hello world')

	def init_keys(self):
		if os.path.isfile(constants.CLIENT_PUB_PATH % self.uid) and os.path.isfile(constants.CLIENT_PRIV_PATH % self.uid):
			with open(constants.CLIENT_PUB_PATH % self.uid, 'rb') as pubfile, open(constants.CLIENT_PRIV_PATH % self.uid, 'rb') as privfile:
				self.pubkey = pubfile.read()
				self.privkey = privfile.read()
				logger.debug('read existing pub/priv key for uid %s' % self.uid)
		else:
			self.pubkey, self.privkey = self.generate_keys()
			with open(constants.CLIENT_PUB_PATH % self.uid, 'wb') as pubfile, open(constants.CLIENT_PRIV_PATH % self.uid, 'wb') as privfile:
				pubfile.write(self.pubkey)
				privfile.write(self.privkey)
				logger.debug('written pub/priv key for uid %s' % self.uid)

	def run(self):
		try:
			data = self.client.read()
			while data:
				self.buffer += data
				messages = self.buffer.split(constants.CRLF)
				
				opcode = None
				if len(messages) > 1:
					opcode = int(messages[0])
				
				if opcode == constants.OP_MESSAGE and len(messages) >= 6:
					topubkey = messages[1]
					assert topubkey == self.pubkey
					frompubkey = messages[2]
					enc = (messages[3],)
					sig = (long(messages[4]),)
					
					message = self.decrypt_message(enc)
					if self.verify_signature(frompubkey, sig, message):
						logger.info('rcvd %s from %s' % (message, frompubkey))
					
					messages = messages[6:]
				
				self.buffer = constants.CRLF.join(messages)
				data = self.client.read()
		
		except KeyboardInterrupt:
			pass
		
		except Exception as e:
			logger.exception(e)
		
		finally:
			try:
				self.client.close()
			except socket.error:
				pass

	def write(self, *messages):
		for message in messages:
			self.client.write('%s%s' % (message, constants.CRLF))

	def send(self, uid, message):
		with open(constants.CLIENT_PUB_PATH % uid, 'rb') as topubfile, open(constants.CLIENT_PUB_PATH % self.uid, 'rb') as frompubfile:
			topubkey = topubfile.read()
			frompubkey = frompubfile.read()
			enc = self.encrypt_message(message, topubkey)
			sig = self.generate_signature(message)
			self.write(constants.OP_MESSAGE, topubkey, frompubkey, enc[0], sig[0])

	@staticmethod
	def generate_keys():
		random_generator = Random.new().read
		priv = RSA.generate(1024, random_generator)
		pub = priv.publickey()
		return (pub.exportKey(), priv.exportKey())

	def generate_signature(self, message):
		'''sign messaging using our priv key'''
		k = RSA.importKey(self.privkey)
		h = MD5.new(message).digest()
		return k.sign(h, '')

	@staticmethod
	def verify_signature(pubkey, signature, message):
		'''verify signature using signing user public key'''
		k = RSA.importKey(pubkey)
		h = MD5.new(message).digest()
		return k.verify(h, signature)

	@staticmethod
	def encrypt_message(message, pubkey):
		'''encrypt message using receiving user public key'''
		k = RSA.importKey(pubkey)
		return k.encrypt(message, 32)

	def decrypt_message(self, enc):
		'''decrypt message using our priv key'''
		k = RSA.importKey(self.privkey)
		return k.decrypt(enc)

if __name__ == '__main__':
	uid = sys.argv[1]
	c = Client(uid)
	c.run()
