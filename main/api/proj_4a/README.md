Description: This folder comprises of different encryption APIs and Utilities coded in Python 3.x for the Python SDK for AtSign as a part of 682 course (MS CS - UMass Boston) Project 4a

More about the Encryption API: It makes use of the following encryption and decryption algorithms:
RSA Encryption 2048 (Sign, Verify, Encrypt, Decrypt) & Keypair Generation, Base64 Encode/Decode, AES CTR 256 Encrypt/Decrypt, & Key Generation

Table of Contents:
1)Structure
2)Usage
3)Algorithm
4)Collaborators

Structure:
Abstract Class: Encryption.py
Implementation Classes: Format: xyz_encryption.py
Utility: encryption_util.py

Usage:
1) Use the EncryptionUtil in the main SDK to get the functionality of all the algorithms. 
2) xyz_encryption is for individual implementation of an encryption algorithm, it has to implement the abstract class encryption.py and implement the abstract methods encrypt() and decrypt().

Algorithm:
1) AES key and initialization vector are generated.
2) The base message is AES encrypted in the CTR mode using the keys and the initialization vector.
3) The RSA public and private keys are generated.
4) The AES key is base64 encoded.
5) The encoded AES key is RSA signed using the RSA private key and 'SHA-256'.
6) The encoded AES key is RSA encrypted using the RSA public key.
7) At the client side, the AES key is decrypted using the RSA private key.
8) The decrypted AES key is base64 decoded.
9) The AES key is also verified using the RSA public key and the Signature.
10) The message is finally obstained with AES decrypted using the AES key and initialization vector.


Collaborators:
Muskaan Manocha
Prem Desai
Yesheswani Murthy
