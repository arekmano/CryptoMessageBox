# CryptoMessageBox
A simple Key/Value storage, using MongoDB as the database.

# Primary Use Cases
* Storing data securely in an untrusted MongoDB database.


This application uses RSA encryption algorithm to encrypt the given plain text on the client-side using the public key, then stores the ciphertext in a MongoDB collection. Decryptobox (https://github.com/arekmano/DecryptoBox) can then be used to decrypt the ciphertext into plain text once again, using the private key, on a trusted machine.

# Getting Started

1. Clone the repository:
  <pre> git clone git@github.com:arekmano/CryptoMessageBox.git </pre>
2. Generate an RSA public/private key pair:
  <pre> git clone git@github.com:arekmano/CryptoMessageBox.git </pre>
3. Replace the public key in <pre> dev/js/constants.js</pre> with the generated key.
4. Run npm install:
  <pre> npm install </pre>
5. Run the following gulp task:
  <pre> gulp bundle </pre>
6. The project is now ready to run using <pre> node app.js</pre>

