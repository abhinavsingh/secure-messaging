Secure Messaging
================

This is an experiment/demonstration/exercise to create secure server/client communication model using Python.

Goals:
------

- End-to-End encryption (read as, server cannot see who is sending what to whom)
- Message origin verification using digital signatures
- CLI client (ssl)
- Web (https + wss) client

How it works:
-------------

- Clients generate public/private key and send their public key to server upon connection
- Message is addressed from one public key to another public key
- Over the wire packet consists of sender public key, digital signature and encrypted message
- Only destination client can decrypt message and verify digital signature

TODO:
-----

- Methods for public key discovery of social friends and like minded people
- How to send message to all the devices of same user running with different public/private key?
- Acknowledgement and offline message persistence
- Investigate on self expiring messages?
- Message mime type support
- Publish tagged message to users subscribed to specific tags
