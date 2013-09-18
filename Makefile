all: crypthook

crypthook:
	gcc crypthook.c -o crypthook.so -Wall -shared -fpic -ldl -lcrypto

clean: 
	rm crypthook.so
