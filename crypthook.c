/* 
 * CryptHook
 * Secure TCP/UDP wrapper
 * www.chokepoint.net
 * Tested with AES algorithm
 * Example:
 * $ LD_PRELOAD=crypthook.so CH_KEY=omghax ncat -l -p 5000
 * $ LD_PRELOAD=crypthook.so CH_KEY=omghax ncat localhost 5000
 * Packet Format:
 * [algo][len][iv][hmac][payload]
 */
#define _GNU_SOURCE

#include <sys/types.h>
#include <sys/socket.h>
#include <dlfcn.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <string.h>

/* Use these to link to actual functions */
static ssize_t (*old_recv)(int sockfd, void *buf, size_t len, int flags);
static ssize_t (*old_send)(int sockfd, void *buf, size_t len, int flags);
static ssize_t (*old_recvfrom)(int sockfd, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen);
static ssize_t (*old_sendto)(int sockfd, void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen);

#define KEY_VAR "CH_KEY"
#define PASSPHRASE "Hello NSA"
#define MAX_LEN 4125
					
#define KEY_SIZE 32  	        // AES 256 in GCM mode.
#define KEY_SALT "changeme"     // Used in key derivation. CHANGE THIS.	
#define IV_SIZE 12				// 12 bytes used for AES 256 in GCM mode

#define PACKET_HEADER 0x17		// Packet Identifier added to each header

// 1 byte packet identifier
// 12 bytes IV
// 16 bytes MAC
#define HEADER_SIZE 31 

// Used in PBKDF2 key generation. CHANGE THIS FROM DEFAULT
#define ITERATIONS 1000					

static char glob_key[KEY_SIZE]="\00";
			
/* Check environment variables
 * CH_KEY should be the base pass phrase	
 * if key isn't given, revert back to PASSPHRASE.
 * Remember to change the salt
 */
static void gen_key(void) {
	char *key_var = getenv(KEY_VAR);

	if (key_var) {
		PKCS5_PBKDF2_HMAC_SHA1(key_var,strlen(key_var),(const unsigned char *)KEY_SALT,strlen(KEY_SALT),ITERATIONS,KEY_SIZE,(unsigned char *)glob_key);
	} else {
		PKCS5_PBKDF2_HMAC_SHA1(PASSPHRASE,strlen(PASSPHRASE),(const unsigned char *)KEY_SALT,strlen(KEY_SALT),ITERATIONS,KEY_SIZE,(unsigned char *)glob_key);
	}
}

static int encrypt_data(char *in, int len, char *out) {
	unsigned char outbuf[MAX_LEN];
	unsigned char temp[MAX_LEN];
	unsigned char iv[IV_SIZE];
	unsigned char tag[16];
	
	unsigned char *step;
	int tmplen=0, outlen=0;

	// copy plain text message into temp
	memset(temp,0x00,MAX_LEN);
	memcpy(temp,in,len);
	
	if (glob_key[0] == 0x00) // Generate key if its the first packet
		gen_key(); 
	RAND_bytes(iv,IV_SIZE); // Generate random IV
	
	EVP_CIPHER_CTX *ctx;
	ctx = EVP_CIPHER_CTX_new();
	EVP_CIPHER_CTX_init (ctx);
	EVP_EncryptInit_ex (ctx, EVP_aes_256_gcm() , NULL, (const unsigned char *)glob_key, (const unsigned char *)iv);

	if (!EVP_EncryptUpdate (ctx, outbuf, &outlen, (const unsigned char *)temp, len)) {
		fprintf(stderr, "[!] Error in EVP_EncryptUpdate()\n");
		EVP_CIPHER_CTX_cleanup (ctx);
		return 0;
	}

	if (!EVP_EncryptFinal_ex (ctx, outbuf + outlen, &tmplen)) {
		fprintf(stderr, "[!] Error in EVP_EncryptFinal_ex()\n");
		EVP_CIPHER_CTX_cleanup (ctx);
		return 0;
	}
	
	EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag);
	
	// Add header information
	out[0]=PACKET_HEADER;
	// Pack full packet length
	out[1]=(0xff00&(len+HEADER_SIZE))>>8;
	out[2]=(0xff&(len+HEADER_SIZE));
	step=(unsigned char *)&out[3];	
	memcpy(step,iv,IV_SIZE);
	step+=IV_SIZE;
	memcpy(step,tag,sizeof(tag));
	step+=sizeof(tag);
	memcpy(step,outbuf,outlen+tmplen);
	
	EVP_CIPHER_CTX_cleanup (ctx);
	return outlen+tmplen+HEADER_SIZE;
}

static int decrypt_data(char *in, int len, char *out) {
	unsigned char outbuf[MAX_LEN];
	unsigned char iv[IV_SIZE];
	unsigned char tag[16];
	char *step;
	
	int tmplen=0, outlen=0;
	
	memset(outbuf,0x00,MAX_LEN);
	
	// header information
	step=in+3; // First three bytes are header info / length only
	memcpy(iv,step,IV_SIZE); // Extract the IV
	step+=IV_SIZE;
	memcpy(tag,step,16); // Extract the MAC
	step+=16;

	if (glob_key[0] == 0x00)   // Generate key if its the first packet
		gen_key(); 
	
	EVP_CIPHER_CTX *ctx;
	ctx = EVP_CIPHER_CTX_new();
	EVP_CIPHER_CTX_init (ctx);
	EVP_DecryptInit_ex (ctx, EVP_aes_256_gcm() , NULL, (const unsigned char *)glob_key, (const unsigned char *)iv);
	
	EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_SIZE, NULL);
	
	if (!EVP_DecryptUpdate (ctx, outbuf, &outlen, (const unsigned char *)step, len)) {
		fprintf(stderr, "[!] Error in EVP_DecryptUpdate()\n");
		EVP_CIPHER_CTX_cleanup (ctx);
		return 0;
	}

	EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, sizeof(tag), tag);

	if (!EVP_DecryptFinal_ex (ctx, outbuf + outlen, &tmplen)) {
		fprintf(stderr, "[!] Error in EVP_DecryptFinal_ex(). Possible foul play involved.\n");
		EVP_CIPHER_CTX_cleanup (ctx);
		return 0;
	}
	
	EVP_CIPHER_CTX_cleanup (ctx);
	
	memcpy(out,outbuf,outlen+tmplen);
	
	return len;
}

/* Hook recv and decrypt the data before returning to the program */
ssize_t recv(int sockfd, void *buf, size_t len, int flags) {
	char outbuf[MAX_LEN];
	unsigned char temp[MAX_LEN];
	
	int outlen, ret, packet_len;
	
	memset(outbuf,0x00,MAX_LEN);
	memset(temp,0x00,MAX_LEN);
	
	if (!old_recv)
		old_recv = dlsym(RTLD_NEXT,"recv");
		
	if (sockfd == 0) // Y U CALL ME W/ SOCKFD SET TO ZERO!?!?
		return old_recv(sockfd, buf, len, flags);
	
	//ret = old_recv(sockfd, (void *)temp, MAX_LEN, flags);
	ret = old_recv(sockfd, (void *)temp, 3, MSG_PEEK);
	
	if (ret < 1) { // Nothing to decrypt 
		return ret;
	}

	if (temp[0] != PACKET_HEADER) {
		fprintf(stderr,"[!] Client not using CryptHook\n");
		return 0;
	}
	// Unpack the full message length
	packet_len = (temp[1]<<8)+temp[2];

	ret = old_recv(sockfd, (void *)temp, packet_len, flags);

	outlen = decrypt_data((char *)temp,ret-HEADER_SIZE,&outbuf[0]);

	memcpy((void*)buf,(void*)outbuf,(size_t)outlen);
	
	return outlen;
}

/* Hook recvfrom and decrypt the data before returning to the program */
ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen) {	
	char outbuf[MAX_LEN];
	unsigned char temp[MAX_LEN];
	
	int outlen, ret, packet_len;
	
	memset(outbuf,0x00,MAX_LEN);
	memset(temp,0x00,MAX_LEN);
	
	if (!old_recvfrom)
		old_recvfrom = dlsym(RTLD_NEXT,"recvfrom");
		
	if (sockfd == 0) // Y U CALL ME W/ SOCKFD SET TO ZERO!?!?
		return old_recvfrom(sockfd, buf, len, flags, src_addr, addrlen);
	
	// Grab first three bytes to see if its our protocol and the length
	ret = old_recvfrom(sockfd, (void *)temp, 3, MSG_PEEK, src_addr, addrlen);

	if (ret < 1) { // Nothing to decrypt 
		return ret;
	}

	if (temp[0] != PACKET_HEADER) {
		fprintf(stderr,"[!] Client not using same crypto algorithm\n");
		return 0;
	}
	// Unpack the full message length
	packet_len = (temp[1]<<8)+temp[2];
	
	ret = old_recvfrom(sockfd, (void *)temp, packet_len, flags, src_addr, addrlen);
	outlen = decrypt_data((char *)temp,ret-HEADER_SIZE,&outbuf[0]);

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
