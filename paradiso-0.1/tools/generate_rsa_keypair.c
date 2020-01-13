#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <openssl/rsa.h>
#include <openssl/objects.h>
#include <openssl/err.h>

#define KEYSIZE 2048

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

void generate_keys(char *private_file, char *public_file){
    RSA *keypair;
    unsigned char *public_key, *private_key, *tmp;
    int public_keylen, private_keylen;

    /* generate the key pair */
    keypair = RSA_generate_key(KEYSIZE, RSA_F4, NULL, NULL);
    if(keypair == NULL){
        printf("key generation failed\n");
        exit(0);
    }

    /* get the key lengths */
    private_keylen = i2d_RSAPrivateKey(keypair, NULL);
    public_keylen = i2d_RSAPublicKey(keypair, NULL);

    printf("Private key length: %d\n", private_keylen);
    printf("Public key length: %d\n", public_keylen);

    /* reserve memory */
    public_key = malloc(public_keylen);
    private_key = malloc(private_keylen);

    /* convert keys to character array */
    tmp = private_key;
    if(i2d_RSAPrivateKey(keypair, &tmp) == 0){
        printf("get private key failed\n");
        exit(0);
    }
    tmp = public_key;
    if(i2d_RSAPublicKey(keypair, &tmp) == 0){
        printf("get public key failed\n");
        exit(0);
    }

    /* save to file */
    makeFile(private_file, private_key, private_keylen);
    makeFile(public_file, public_key, public_keylen);
}

/* this utility produces a public and private key file */
int main(int argc, char *argv[]){
    int len;
    char *private_file, *public_file;
    char *private_post = ".private.key";
    char *public_post = ".public.key";

    if(argc != 2){
        printf("Usage: %s <name>\n", argv[0]);
        exit(0);
    }

    len = strlen(argv[1]);
    private_file = malloc(len+strlen(private_post)+1);
    if(private_file == NULL){
        printf("out of memory\n");
        exit(0);
    }

    public_file = malloc(len+strlen(public_post)+1);
    if(public_file == NULL){
        printf("out of memory\n");
        exit(0);
    }

    strncpy(private_file, argv[1], len);
    strcpy(private_file+len, private_post);

    strncpy(public_file, argv[1], len);
    strcpy(public_file+len, public_post);

    generate_keys(private_file, public_file);

    return 0;
}
