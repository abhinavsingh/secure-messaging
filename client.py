import os
import sys
import ssl
import signal
import socket
import logging

from tornado.ioloop import IOLoop
from tornado.iostream import SSLIOStream
from Crypto import Random
from Crypto.PublicKey import RSA
from Crypto.Hash import MD5

import constants

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

def handle_signal(sig, frame):
	IOLoop.instance().add_callback(IOLoop.instance().stop)

class Client(object):
	'''ssl client implementation.'''

	def __init__(self, uid, port=10001):
		self.uid = uid
		self.port = port
		self.opcode = None
		
		self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.conn = SSLIOStream(self.sock, ssl_options={'ca_certs':constants.SERVER_CRT_PATH, 'cert_reqs':ssl.CERT_REQUIRED})
		self.conn.connect(('127.0.0.1', self.port), self.on_connect)
	
	def on_connect(self):
		self.conn.set_close_callback(self.on_close)
		self.pubkey, self.privkey = None, None
		self.init_keys()
		self.buffer = ''
		self.write(constants.OP_PUBKEY, self.pubkey)
		if self.uid == 2:
			self.send_message(1, 'hello world')
		self.read_line()
	
	def read_line(self):
		self.conn.read_until(constants.CRLF, self.handle_line)

	def on_close(self):
		self.conn = None
		self.sock = None

	def init_keys(self):
		if os.path.isfile(constants.CLIENT_PUB_PATH % self.uid) and os.path.isfile(constants.CLIENT_PRIV_PATH % self.uid):
			with open(constants.CLIENT_PUB_PATH % self.uid, 'rb') as pubfile, open(constants.CLIENT_PRIV_PATH % self.uid, 'rb') as privfile:
				self.pubkey = pubfile.read().strip()
				self.privkey = privfile.read().strip()
				logger.debug('read existing pub/priv key for uid %s' % self.uid)
		else:
			self.pubkey, self.privkey = self.generate_keys()
			with open(constants.CLIENT_PUB_PATH % self.uid, 'wb') as pubfile, open(constants.CLIENT_PRIV_PATH % self.uid, 'wb') as privfile:
				pubfile.write(self.pubkey)
				privfile.write(self.privkey)
				logger.debug('written pub/priv key for uid %s' % self.uid)

	def handle_line(self, data):
		self.buffer += data
		messages = self.buffer.split(constants.CRLF)
		
		if not self.opcode and len(messages) > 1:
			self.opcode = int(messages[0])
		
		if self.opcode == constants.OP_MESSAGE and len(messages) == 5:
			message = messages[1:4]
			self.handle_op_message(*message)
			self.buffer = ''
			self.opcode = None
		
		self.read_line()
	
	def write(self, *messages):
		for message in messages:
			self.conn.write('%s%s' % (message, constants.CRLF))

	def send_message(self, uid, message):
		with open(constants.CLIENT_PUB_PATH % uid, 'rb') as pubfile:
			pubkey = pubfile.read()
			# encrypt message using receiver public key
			enc = self.encrypt_message(message, pubkey)
			# sign encrypted message for digital verification
			sig = self.generate_signature(enc[0])
			message = (constants.OP_MESSAGE, pubkey, enc[0], sig[0],)
			self.write(*message)

	def handle_op_message(self, pubkey, enc, sig):
		enc = (enc,)
		sig = (long(sig),)
		
		# verify signature of incoming encrypted message
		if self.verify_signature(pubkey, sig, enc[0]):
			# decrypt message
			message = self.decrypt_message(enc)
			logger.info('rcvd %s from %s' % (message, pubkey))

	@staticmethod
	def generate_keys():
		random_generator = Random.new().read
		priv = RSA.generate(1024, random_generator)
		pub = priv.publickey()
		return (pub.exportKey().strip(), priv.exportKey().strip())

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
	signal.signal(signal.SIGINT, handle_signal)
	signal.signal(signal.SIGTERM, handle_signal)
	uid = int(sys.argv[1])
	c = Client(uid)
	IOLoop.instance().start()
	IOLoop.instance().close()
