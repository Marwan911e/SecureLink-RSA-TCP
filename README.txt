RSA Secure Communication over TCP
===================================

Files to submit:
  RSAGenKey.java   - Generate sender/receiver key pairs
  RSADecrypt.java  - Server: listen, decrypt, print plaintext
  RSAEncrypt.java  - Client: read name, encrypt, send over socket

Supporting files (compile together):
  RSAKeyUtil.java  - Shared key I/O and cipher settings
  name.txt         - 10-character plaintext for transmission

Build
-----
  javac *.java

Run order
---------
  1. java RSAGenKey
  2. java RSADecrypt              (or: java RSADecrypt --double)
  3. java RSAEncrypt              (or: java RSAEncrypt --double)

Use the same mode flag on sender and receiver (--single is default).

Options
-------
  --double          Double RSA (sender private, then receiver public)
  --single          Single RSA with receiver public key only (default)
  --port 54321      TCP port (both sides)
  --host localhost  Client target host (RSAEncrypt only)

Example (bonus double encryption)
---------------------------------
  Terminal 1: java RSADecrypt --double
  Terminal 2: java RSAEncrypt --double

Double RSA note
---------------
  Step 1 uses PKCS#1 with the sender private key; step 2 uses NoPadding with
  the receiver public key (a full RSA block cannot be PKCS#1-encrypted twice).
  Decryption reverses: NoPadding with receiver private, then PKCS#1 with sender public.

Regenerate keys
---------------
  Delete the keys/ folder, then run java RSAGenKey again.
