/* 
 * CryptHook
 * Secure TCP/UDP wrapper
 * www.chokepoint.net
 * Tested with both blowfish and AES algorithms
 * Example:
 * $ LD_PRELOAD=crypthook.so CH_KEY=omghax ncat -l -p 5000
 * $ LD_PRELOAD=crypthook.so CH_KEY=omghax ncat localhost 5000
 */
#define _GNU_SOURCE

#include <sys/types.h>
#include <sys/socket.h>
#include <dlfcn.h>
#include <rhash/rhash.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <string.h>

/* Use these to link to actual functions */
static ssize_t (*old_recv)(int sockfd, void *buf, size_t len, int flags);
static ssize_t (*old_send)(int sockfd, void *buf, size_t len, int flags);
static ssize_t (*old_recvfrom)(int sockfd, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen);
static ssize_t (*old_sendto)(int sockfd, void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen);

#define KEY_VAR "CH_KEY"
#define PASSPHRASE "Hello NSA"
#define MAX_LEN 65535

// Zeroes are good enough for SSH, its good enough for this example
// CHANGE THIS to something clever
#define IVEC "\0\0\0\0\0\0\0\0" 

#define BLOCK_CIPHER EVP_aes_256_cbc() 	// EVP_aes_256_cbc() and EVP_bf_cbc() have been tested
#define BLOCK_SIZE 16 					// Blowfish = 8 AES = 16
#define KEY_SIZE 32  					// Blowfish is variable, lets go w/ 256 bits

// Used in PBKDF2 key generation
#define ITERATIONS 1000					
			
/* Check environment variables
 * CH_KEY should be the base pass phrase	
 * if key isn't given, revert back to PASSPHRASE.
 * Remember to change the salt
 */
void gen_key(char *phrase, int len) {
	char *key_var = getenv(KEY_VAR);
	const unsigned char salt[]="changeme"; // salt should be changed. both sides need the same salt.
	
	if (key_var) {
		PKCS5_PBKDF2_HMAC_SHA1(key_var,strlen(key_var),salt,strlen((char*)salt),ITERATIONS,KEY_SIZE,(unsigned char *)phrase);
	} else {
		PKCS5_PBKDF2_HMAC_SHA1(PASSPHRASE,strlen(PASSPHRASE),salt,strlen((char*)salt),ITERATIONS,KEY_SIZE,(unsigned char *)phrase);
	}
}

int encrypt_data(char *in, int len, char *out) {
	unsigned char outbuf[MAX_LEN];
	unsigned char temp[MAX_LEN];
	
	char key[KEY_SIZE];
	int pad=0, tmplen=0, outlen=0;
	
	// Null out temp so that padding is completed with null bytes.
	memset(temp,0x00,MAX_LEN);
	memcpy(temp,in,len);
	
	gen_key(key,KEY_SIZE); // Determine key based on environment 
	
	EVP_CIPHER_CTX ctx;
	EVP_CIPHER_CTX_init (&ctx);
	EVP_EncryptInit_ex (&ctx, BLOCK_CIPHER , NULL, (const unsigned char *)key, (const unsigned char *)IVEC);

	/* How many bytes do we need? */
	pad = BLOCK_SIZE - (len % BLOCK_SIZE);

	if (!EVP_EncryptUpdate (&ctx, outbuf, &outlen, (const unsigned char *)temp, len+pad)) {
		fprintf(stderr, "[!] Error in EVP_EncryptUpdate()\n");
		EVP_CIPHER_CTX_cleanup (&ctx);
		return 0;
	}

	if (!EVP_EncryptFinal_ex (&ctx, outbuf + outlen, &tmplen)) {
		fprintf(stderr, "[!] Error in EVP_EncryptFinal_ex()\n");
		EVP_CIPHER_CTX_cleanup (&ctx);
		return 0;
	}
	
	memcpy(out,outbuf,outlen+tmplen);
	
	EVP_CIPHER_CTX_cleanup (&ctx);
	return outlen+tmplen;
}

int decrypt_data(char *in, int len, char *out) {
	unsigned char outbuf[MAX_LEN];
	
	char key[KEY_SIZE];
	int tmplen=0, outlen=0;
	
	memset(outbuf,0x00,MAX_LEN);
	
	gen_key(key,KEY_SIZE); // Determine key based on environment 
	
	EVP_CIPHER_CTX ctx;
	EVP_CIPHER_CTX_init (&ctx);
	EVP_DecryptInit_ex (&ctx, BLOCK_CIPHER , NULL, (const unsigned char *)key, (const unsigned char *)IVEC);

	if (!EVP_DecryptUpdate (&ctx, outbuf, &outlen, (const unsigned char *)in, len)) {
		fprintf(stderr, "[!] Error in EVP_DecryptUpdate()\n");
		EVP_CIPHER_CTX_cleanup (&ctx);
		return 0;
	}

	if (!EVP_DecryptFinal_ex (&ctx, outbuf + outlen, &tmplen)) {
		fprintf(stderr, "[!] Error in EVP_DecryptFinal_ex()\n");
		EVP_CIPHER_CTX_cleanup (&ctx);
		return 0;
	}
	
	EVP_CIPHER_CTX_cleanup (&ctx);
	
	// this is hacky, but works... clean it up if you like
	char *step=outbuf+len;
	int i = len+1;
	while (*step == 0x00 || *step == 0x10) {
		--step; --i;
	}
	
	memcpy(out,outbuf,i);
	
	return i;
}

/* Hook recv and decrypt the data before returning to the program */
ssize_t recv(int sockfd, void *buf, size_t len, int flags) {
	char outbuf[MAX_LEN];
	char temp[MAX_LEN];
	
	int outlen, ret;

	memset(outbuf,0x00,MAX_LEN);
	memset(temp,0x00,MAX_LEN);
	
	if (!old_recv)
		old_recv = dlsym(RTLD_NEXT,"recv");
		
	if (sockfd == 0) // Y U CALL ME W/ SOCKFD SET TO ZERO!?!?
		return old_recv(sockfd, buf, len, flags);
	
	ret = old_recv(sockfd, (void *)temp, MAX_LEN, flags);
	
	if (ret < 1) { // Nothing to decrypt 
		return ret;
	}

	outlen = decrypt_data((char *)temp,ret,&outbuf[0]);

	memcpy((void*)buf,(void*)outbuf,(size_t)outlen);
	
	return outlen;
}

/* Hook recvfrom and decrypt the data before returning to the program */
ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen) {	
	char outbuf[MAX_LEN];
	char temp[MAX_LEN];
	
	int outlen, ret;

	memset(outbuf,0x00,MAX_LEN);
	memset(temp,0x00,MAX_LEN);
	
	if (!old_recvfrom)
		old_recvfrom = dlsym(RTLD_NEXT,"recvfrom");
		
	if (sockfd == 0) // Y U CALL ME W/ SOCKFD SET TO ZERO!?!?
		return old_recvfrom(sockfd, buf, len, flags, src_addr, addrlen);
	
	ret = old_recvfrom(sockfd, (void *)temp, MAX_LEN, flags, src_addr, addrlen);
	
	if (ret < 1) { // Nothing to decrypt 
		return ret;
	}

	outlen = decrypt_data((char *)temp,ret,&outbuf[0]);

	memcpy((void*)buf,(void*)outbuf,(size_t)outlen);
	
	return outlen;
}

/* Hook send and encrypt data first */
ssize_t send(int sockfd, const void *buf, size_t len, int flags) {
	char outbuf[MAX_LEN];
	int outlen;
	
	memset(outbuf,0x00,MAX_LEN);
	
	if (!old_send)
		old_send = dlsym(RTLD_NEXT,"send");
		
	outlen = encrypt_data((char *)buf, len, &outbuf[0]);
	if (outlen == 0)
		return 0;
		
	// Send the encrypted data
	old_send(sockfd, (void *)outbuf, outlen, flags);

	return len; 
}

/* Hook send and encrypt data first */
ssize_t sendto(int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen) {
	char outbuf[MAX_LEN];
	int outlen;
	
	memset(outbuf,0x00,MAX_LEN);
	
	if (!old_sendto)
		old_sendto = dlsym(RTLD_NEXT,"sendto");
		
	outlen = encrypt_data((char *)buf, len, &outbuf[0]);
	if (outlen == 0)
		return 0;
		
	// Send the encrypted data
	old_sendto(sockfd, (void *)outbuf, outlen, flags, dest_addr, addrlen);

	return len; 
}
