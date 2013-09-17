CryptHook
============================

CryptHook is a modular implementation for securing existing 
applications with symmetrical block cipher encryption. It works by 
hooking the base system calls for network communication send/sendto 
and recv/recvfrom. Crypthook will work with any existing application 
that relies on these system calls.


Tested Algorithms
----------------------------

* Blowfish
* Advanced Encryption Standard


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


[www.chokepoint.net](http://www.chokepoint.net)
