# CryptoMessageBox
Key/Value storage. Encrypts client-side.

* I like Free Hosting.
* I like Privacy.
* Encrypted Key/Value storage to prevent snooping.

This application uses RSA to encrypt the given plain text on the client-side, then stores the ciphertext in a MongoDB collection. Decryptobox (https://github.com/arekmano/DecryptoBox) can then be used to decrypt the ciphertext into plain text once again. This comes in handy when the database is located on an untrusted machine.
