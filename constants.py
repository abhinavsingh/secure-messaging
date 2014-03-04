KEYS_PATH = 'priv/keys'
SERVER_CRT_PATH = '%s/server/server.crt' % KEYS_PATH
SERVER_KEY_PATH = '%s/server/server.key' % KEYS_PATH
CLIENT_PUB_PATH = KEYS_PATH + '/clients/%s.pub'
CLIENT_PRIV_PATH = KEYS_PATH + '/clients/%s.priv'

CRLF = '\r\n'

OP_PUBKEY = 1
OP_MESSAGE = 2
