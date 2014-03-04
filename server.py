import ssl
import socket
import logging
import threading
from Crypto.Hash import MD5
import constants

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

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
        
        self.client = ssl.wrap_socket(self.conn, server_side=True, certfile=constants.SERVER_CRT_PATH, keyfile=constants.SERVER_KEY_PATH)
        
        self.buffer = ''
        self.pubkey = None
        self.md5 = None
    
    def run(self):
        try:
            data = self.client.read()
            
            while data:
                #logger.info('rcvd %s from client %s' % (data, self.addr))
                self.buffer += data
                messages = self.buffer.split(constants.CRLF)
                
                # extract op
                opcode = None
                if len(messages) > 1:
                    opcode = int(messages[0])
                
                # check if we have sufficient data for current op
                if opcode == constants.OP_PUBKEY and len(messages) >= 3:
                    self.handle_op_pubkey(messages[1])
                    messages = messages[3:]
                elif opcode == constants.OP_MESSAGE and len(messages) >= 5:
                    message = messages[1:4]
                    self.handle_op_message(*message)
                    messages = messages[5:]
                
                self.buffer = constants.CRLF.join(messages)
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
        self.pubkey = pubkey
        self.md5 = MD5.new(pubkey).hexdigest()
        clients[self.md5] = self.client
        
        if self.md5 in buffers:
            messages = buffers[self.md5]
            del buffers[self.md5]
            for message in messages:
                self.write(self.client, *message)
    
    def handle_op_message(self, pubkey, enc, sig):
        message = (constants.OP_MESSAGE, self.pubkey, enc, sig,)
        md5 = MD5.new(pubkey).hexdigest()
        
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
            client.write('%s%s' % (message, constants.CRLF))

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
