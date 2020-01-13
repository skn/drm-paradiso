#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/err.h>

#define KEYSIZE 2048
#define SIGLEN (KEYSIZE / 8)

/* reads file name and writes data_size bytes to buf */
void readFile(char *name, int *len, unsigned char **buf){
    FILE *fp;
    int read, errsv;
    uint16_t size;

    /* open file in binary read mode */
    fp = fopen(name, "rb");
    if(fp == NULL){
        errsv = errno;
        printf("Error opening file %s\nError: %s\n", name, strerror(errsv));
        exit(0);
    }

    /* read the size and convert to host order */
    read = fread((char *)&size, sizeof(uint16_t), 1, fp);
    if(read != 1){
        errsv = errno;
        printf("Error reading data size from file %s\nError: %s\n", name, strerror(errsv));
    }
    *len = ntohs(size);

    /* allocate the memory */
    *buf = malloc(*len);
    if(*buf == NULL){
        printf("out of memory\n");
        exit(0);
    }

    /* read the data from the file */
    read = fread(*buf, sizeof(unsigned char), *len, fp);
    
    if(read != *len){
        errsv = errno;
        printf("Error reading file %s\nError: %s\n", name, strerror(errsv));
    }

    fclose(fp);
}

void makeFile(char *name, char *buf, int len){
    FILE *fp;
    int written, errsv;
    uint16_t size;

    /* truncate and create file in binary mode */
    fp = fopen(name, "wb");
    if(fp == NULL){
        errsv = errno;
        printf("Error opening file %s\nError: %s\n", name, strerror(errsv));
        exit(0);
    }

    /* write the size in network order to the file */
    size = htons(len);
    written = fwrite((char *)&size, sizeof(uint16_t), 1, fp);

    if(written != 1){
        errsv = errno;
        printf("Error writing size to file %s\nError: %s\n", name, strerror(errsv));
        fclose(fp);
        return;
    }

    /* write the data to the file */
    written = fwrite(buf, sizeof(unsigned char), len, fp);

    if(written != len){
        errsv = errno;
        printf("Error writing file %s\nError: %s\n", name, strerror(errsv));
    }
    
    fclose(fp);
}

/* this methode uses the higher level methods of SSL to sign */
void do_sign(unsigned char *data, int datalen, unsigned char **sigres, int *siglen, RSA *private_key){
    EVP_PKEY* evp_private_key;
    EVP_MD_CTX md_ctx;

    evp_private_key = EVP_PKEY_new();
    if ( EVP_PKEY_assign_RSA(evp_private_key, private_key) == 0) {
        printf("generate EVP private key failed\n");
        exit(0);
    }

    if( EVP_SignInit(&md_ctx, EVP_sha1()) == 0){
        printf("evp init sign failed\n");
        exit(0);
    }

    if( EVP_SignUpdate(&md_ctx, data, datalen) == 0){
        printf("evp sign update failed\n");
        exit(0);
    }

    *sigres = malloc(EVP_PKEY_size(evp_private_key));
    if( EVP_SignFinal(&md_ctx, *sigres, siglen, evp_private_key) == 0){
        printf("evp sign final failed\n");
        exit(0);
    }
}

void sign_key(char *private_file, char *public_file, char *sig_file){
    RSA *rsa_private_key;
    unsigned char *public_key, *private_key, *signature, *tmp;
    int sig_len, rsa_error, public_keylen, private_keylen;

    /* read the keys */
    readFile(private_file, &private_keylen, &private_key);
    readFile(public_file, &public_keylen, &public_key);

    printf("Private key length: %d\n", private_keylen);
    printf("Public key length: %d\n", public_keylen);

    /* regenerate the RSA private key */
    tmp = private_key;
    rsa_private_key = d2i_RSAPrivateKey(NULL, (const unsigned char**) &tmp, private_keylen);
    if(rsa_private_key == NULL){
        printf("generate private key failed\n");
        ERR_load_crypto_strings();
        while((rsa_error = ERR_get_error())!=0){
            printf(ERR_reason_error_string(rsa_error));
            ERR_error_string(rsa_error, signature);
            printf("%s\n", signature);
        }
        exit(0);
    }

    /* now sign the raw public_key data with the private key */
    do_sign(public_key, public_keylen, &signature, &sig_len, rsa_private_key);

    printf("Signature length: %d\n", sig_len);
    /* check signature length */
    if(sig_len != SIGLEN){
        printf("incorrect signature length\n");
        exit(0);
    }

    /* save the signature to disk */
    makeFile(sig_file, signature, SIGLEN);
}

/* this utility signs a public key with a given private key */
int main(int argc, char *argv[]){
    int signme_len, signwith_len;
    char *private_file, *public_file, *sig_file;
    char *private_post = ".private.key";
    char *public_post = ".public.key";
    char *sig_post = ".sig";

    if(argc != 3){
        printf("Usage: %s <sign-me-name> <sign-with-name>\n", argv[0]);
        exit(0);
    }

    signwith_len = strlen(argv[2]);
    signme_len = strlen(argv[1]);

    private_file = malloc(signwith_len+strlen(private_post)+1);
    if(private_file == NULL){
        printf("out of memory\n");
        exit(0);
    }

    public_file = malloc(signme_len+strlen(public_post)+1);
    if(public_file == NULL){
        printf("out of memory\n");
        exit(0);
    }

    sig_file = malloc(signme_len+signwith_len+strlen(sig_post)+2);
    if(sig_file == NULL){
        printf("out of memory\n");
        exit(0);
    }

    strncpy(private_file, argv[2], signwith_len);
    strcpy(private_file+signwith_len, private_post);

    strncpy(public_file, argv[1], signme_len);
    strcpy(public_file+signme_len, public_post);
    strncpy(sig_file, argv[1], signme_len);
    strncpy(sig_file+signme_len, ".", 1);
    strncpy(sig_file+signme_len+1, argv[2], signwith_len);
    strcpy(sig_file+signme_len+1+signwith_len, sig_post);
    sign_key(private_file, public_file, sig_file);
    return 0;
}
