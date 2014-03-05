import signal
import logging
from tornado.ioloop import IOLoop
from tornado.tcpserver import TCPServer
from Crypto.Hash import MD5

import constants

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# pubkey md5 to conn mapping
clients = dict()

# buffered messages for offline pubkey
buffers = dict()

def handle_signal(sig, frame):
    IOLoop.instance().add_callback(IOLoop.instance().stop)

class Handler(object):
    '''client connection handler.'''

    def __init__(self, conn, addr):
        super(Handler, self).__init__()
        self.conn = conn
        self.addr = addr
        
        self.opcode = None
        self.buffer = ''
        self.pubkey = None
        self.md5 = None
    
    def run(self):
        self.read_line()
    
    def read_line(self):
        self.conn.read_until(constants.CRLF, self.handle_line)
    
    def handle_line(self, data):
        #logger.debug('rcvd %s from client %s' % (data, self.addr))
        
        self.buffer += data
        messages = self.buffer.split(constants.CRLF)
        
        if not self.opcode and len(messages) > 1:
            self.opcode = int(messages[0])
        
        if self.opcode == constants.OP_PUBKEY and len(messages) == 3:
            self.handle_op_pubkey(messages[1])
            self.buffer = ''
            self.opcode = None
        elif self.opcode == constants.OP_MESSAGE and len(messages) == 5:
            message = messages[1:4]
            self.handle_op_message(*message)
            self.buffer = ''
            self.opcode = None
        
        self.read_line()
    
    def handle_op_pubkey(self, pubkey):
        self.pubkey = pubkey
        self.md5 = MD5.new(pubkey).hexdigest()
        clients[self.md5] = self.conn
        
        if self.md5 in buffers:
            messages = buffers[self.md5]
            del buffers[self.md5]
            logger.debug('%s offline messages found for %s' % (len(messages), self.md5))
            for message in messages:
                self.write(self.conn, *message)
    
    def handle_op_message(self, pubkey, enc, sig):
        message = (constants.OP_MESSAGE, self.pubkey, enc, sig,)
        md5 = MD5.new(pubkey).hexdigest()
        
        if md5 in clients:
            conn = clients[md5]
            self.write(conn, *message)
        else:
            if md5 not in buffers:
                buffers[md5] = list()
            buffers[md5].append(message,)
            logger.debug('%s offline, buffered message' % md5)
    
    @staticmethod
    def write(conn, *messages):
        for message in messages:
            conn.write('%s%s' % (message, constants.CRLF))

class Server(TCPServer):
    '''ssl server implementation.'''

    def __init__(self):
        super(Server, self).__init__(ssl_options={'certfile':constants.SERVER_CRT_PATH, 'keyfile':constants.SERVER_KEY_PATH})

    def handle_stream(self, conn, addr):
        handler = Handler(conn, addr)
        handler.run()

if __name__ == '__main__':
    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)
    s = Server()
    s.listen(10001)
    IOLoop.instance().start()
    IOLoop.instance().close()
