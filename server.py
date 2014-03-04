import ssl
import socket
import logging
import threading

from Crypto.Hash import MD5

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

SERVER_CRT_PATH = 'priv/keys/server/server.crt'
SERVER_KEY_PATH = 'priv/keys/server/server.key'

CRLF = '\r\n'
OP_PUBKEY = 1
OP_MESSAGE = 2

# pubkey md5 to conn mapping
clients = dict()

# buffered messages for offline pubkey
buffers = dict()

class Handler(threading.Thread):
    '''client connection handler.'''

    def __init__(self, conn, addr):
        super(Handler, self).__init__()
        self.conn = conn
        self.addr = addr
        self.client = ssl.wrap_socket(self.conn, server_side=True, certfile=SERVER_CRT_PATH, keyfile=SERVER_KEY_PATH)
        self.buffer = ''
    
    def run(self):
        try:
            data = self.client.read()
            
            while data:
                #logger.info('rcvd %s from client %s' % (data, self.addr))
                self.buffer += data
                messages = self.buffer.split(CRLF)
                
                # extract op
                opcode = None
                if len(messages) > 1:
                    opcode = int(messages[0])
                
                # check if we have sufficient data for current op
                if opcode == OP_PUBKEY and len(messages) >= 3:
                    self.handle_op_pubkey(messages[1])
                    messages = messages[3:]
                elif opcode == OP_MESSAGE and len(messages) >= 6:
                    message = messages[1:5]
                    self.handle_op_message(*message)
                    messages = messages[6:]
                
                self.buffer = CRLF.join(messages)
                data = self.client.read()
        
        except KeyboardInterrupt:
            pass
        
        except Exception, e:
            logger.exception(e)
        
        finally:
            try:
                self.client.shutdown(socket.SHUT_RDWR)
                self.client.close()
            except socket.error:
                pass
    
    def handle_op_pubkey(self, pubkey):
        md5 = MD5.new(pubkey).hexdigest()
        clients[md5] = self.client
        
        if md5 in buffers:
            messages = buffers[md5]
            del buffers[md5]
            for message in messages:
                self.write(self.client, *message)
    
    def handle_op_message(self, topubkey, frompubkey, enc, sig):
        message = (OP_MESSAGE, topubkey, frompubkey, enc, sig,)
        md5 = MD5.new(topubkey).hexdigest()
        
        if md5 in clients:
            client = clients[md5]
            self.write(client, *message)
        else:
            if md5 not in buffers:
                buffers[md5] = list()
            buffers[md5].append(message,)
    
    @staticmethod
    def write(client, *messages):
        for message in messages:
            client.write('%s%s' % (message, CRLF))

class Server(object):
    '''ssl server implementation.'''

    def __init__(self, port=10001):
        self.port = port
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    def run(self):
        self.sock.bind(('127.0.0.1', self.port))
        self.sock.listen(10)
        logging.info('listening on %s' % self.port)

        try:
            while True:
                conn, addr = self.sock.accept()
                handler = Handler(conn, addr)
                handler.daemon = True
                handler.start()
                logger.info('conn %s from %s delegated to handler %s' % (conn, addr, handler))
        except KeyboardInterrupt:
            pass
        except Exception, e:
            logger.exception(e)
        finally:
            logger.info('shutting down server')
            self.sock.close()

if __name__ == '__main__':
    s = Server()
    s.run()
