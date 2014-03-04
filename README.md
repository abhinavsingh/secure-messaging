Secure Messaging
================

This is an experiment/demonstration/exercise to create secure server/client communication model using Python.

Goals:
------

- End-to-End encryption (read as, server cannot see who is sending what to whom)
- Origin trust using digital signatures
- CLI client (ssl)
- Web (https + wss) client

How it works:
-------------

- Clients generate public/private key and transmit their public key to server upon connection
- Data packets is addressed from one public key to another public key
- Data packet consists of sender public key, digital signature and encrypted message

PS:
---

- How public keys are exchanged among users is currently out of scope
- In future in system discovery methods might get added
