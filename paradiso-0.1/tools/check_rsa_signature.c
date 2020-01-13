#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/err.h>
#include <openssl/engine.h>

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

/* this methode uses the higher level methods of SSL to sign */
void do_check(unsigned char *data, int datalen, unsigned char *sigres, int siglen, RSA *public_key){
    EVP_PKEY* evp_public_key;
    EVP_MD_CTX md_ctx;

int rsa_error;
char *signature = malloc(2048);

    evp_public_key = EVP_PKEY_new();
    if ( EVP_PKEY_assign_RSA(evp_public_key, public_key) == 0) {
        printf("generate EVP public key failed\n");
        exit(0);
    }

    if( EVP_VerifyInit(&md_ctx, EVP_sha1()) == 0){
        printf("evp verify sign failed\n");
        exit(0);
    }

    if( EVP_VerifyUpdate(&md_ctx, data, datalen) == 0){
        printf("evp verify update failed\n");
        exit(0);
    }

    if( EVP_VerifyFinal(&md_ctx, sigres, siglen, evp_public_key) == 0){
        printf("evp verify final failed\n");
        ERR_load_crypto_strings();
        while((rsa_error = ERR_get_error())!=0){
            printf(ERR_reason_error_string(rsa_error));
            ERR_error_string(rsa_error, signature);
            printf("%s\n", signature);
        }
        exit(0);
    }
}

void check_signature(char *public_file, char *signed_file, char *sig_file){
    RSA *rsa_public_key;
    unsigned char *public_key, *data, *signature, *tmp;
    int sig_len, rsa_error, public_keylen, data_len;

    /* read the public key, data and signature */
    readFile(public_file, &public_keylen, &public_key);
    readFile(sig_file, &sig_len, &signature);
    readFile(signed_file, &data_len, &data);

    printf("Public key length: %d\n", public_keylen);
    printf("Signature length: %d\n", sig_len);
    printf("Data length: %d\n", data_len);

    /* check signature length */
    if(sig_len != SIGLEN){
        printf("incorrect signature length\n");
        exit(0);
    }

    /* regenerate the RSA public key */
    tmp = public_key;
    rsa_public_key = d2i_RSAPublicKey(NULL, (const unsigned char**) &tmp, public_keylen);
    if(rsa_public_key == NULL){
        printf("generate public key failed\n");
        exit(0);
    }

printf("regenerated\n");

    /* now check the signature with the public key */
    do_check(data, data_len, signature, sig_len, rsa_public_key);

printf("checked\n");

    ERR_load_crypto_strings();
    while((rsa_error = ERR_get_error())!=0){
        printf(ERR_reason_error_string(rsa_error));
        ERR_error_string(rsa_error, signature);
        printf("%s\n", signature);
    }


}

/* this utility checks a signature with a given public key */
int main(int argc, char *argv[]){
    int signed_len, signedwith_len;
    char *public_file, *signed_file, *sig_file;
    char *public_post = ".public.key";
    char *sig_post = ".sig";

    if(argc != 3){
        printf("Usage: %s <signed-name> <signed-with-name>\n", argv[0]);
        exit(0);
    }

    signedwith_len = strlen(argv[2]);
    signed_len = strlen(argv[1]);

    public_file = malloc(signedwith_len+strlen(public_post)+1);
    if(public_file == NULL){
        printf("out of memory\n");
        exit(0);
    }

    sig_file = malloc(signed_len+signedwith_len+strlen(sig_post)+2);
    if(sig_file == NULL){
        printf("out of memory\n");
        exit(0);
    }

    signed_file = malloc(signed_len+strlen(public_post)+1);
    if(signed_file == NULL){
        printf("out of memory\n");
        exit(0);
    }

    strncpy(public_file, argv[2], signedwith_len);
    strcpy(public_file+signedwith_len, public_post);

    strncpy(signed_file, argv[1], signed_len);
    strcpy(signed_file+signed_len, public_post);

    strncpy(sig_file, argv[1], signed_len);
    strncpy(sig_file+signed_len, ".", 1);
    strncpy(sig_file+signed_len+1, argv[2], signedwith_len);
    strcpy(sig_file+signed_len+1+signedwith_len, sig_post);

    check_signature(public_file, signed_file, sig_file);

    return 1;
}
