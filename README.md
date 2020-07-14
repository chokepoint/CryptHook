CryptHook
============================

CryptHook is a modular implementation for securing existing 
applications with symmetrical block cipher encryption. It works by 
hooking the base system calls for network communication send/sendto 
and recv/recvfrom. Crypthook will work with any existing application 
that relies on these system calls.

Crypto
-----------------------------

CryptHook relies on AES in GCM mode using a 256 bit key. Keys are 
generated from passphrases using PBKDF2. IVs are constructed on the 
fly using random bytes of data, and the same key derivation technique 
to reconstruct the initialization vector on the receiving end in order 
to keep overhead to a minimum. Authentication of each packet is also 
verified.

DISCLAIMER
=============================

The following characteristics must be changed if you are going to use 
this for anything reasonably secure. All configuration can be changed 
in crypthook.c using the following #defines.

	#define KEY_SALT "changeme"
	#define IV_SALT "changeme"
	#define ITERATIONS 1000
	
	#define PASSPHRASE "Hello NSA"
	
KEY_SALT and ITERATIONS are used in the key derivation process to 
change the plain text passphrase into a 256 bit key.

IV_SALT and ITERATIONS are used in the IV derivation process to change 
the 8 bytes of random data into a full IV for use with the algorithm.

PASSPHRASE is simply the default passphrase if none is provided via 
the CH_KEY environment variable. 

Dependencies
-----------------------------

* libcrypto / openssl


Compiling
-----------------------------

	$ make


Example Use
-----------------------------

	Server
	$ LD_PRELOAD=./crypthook.so CH_KEY=donthackmebro ncat -l -p 5000
	
	Client
	$ LD_PRELOAD=./crypthook.so CH_KEY=donthackmebro ncat server 5000
