CFLAGS+=	-Wall
LDFLAGS+=	-shared -fpic -ldl -lcrypto

all: crypthook

crypthook:
	$(CC) crypthook.c -o crypthook.so $(CFLAGS) $(LDFLAGS)

clean: 
	rm crypthook.so
