#ifndef _DATA_H_
#define _DATA_H_ 1

#include "interface.h"

/* this file contains the structs for the data server and data client
   the structs are in chronological order, the first sent struct is
   declared first */

#define NONCE_LENGTH    16 /* the length of the nonce in bytes */

/* a nonce consists of characters */
typedef int8_t nonce;

#define SIZE_READ_BUFFER 131072 /* number of bytes in the default read buffer, 128Kbytes */

/* this struct is used to keep state of a large file being transferred from socket to disk, or disk to socket */
struct _large_file{
    FILE *fp;                               /* pointer to the file stored on disk */
    int socket;                             /* the file is written/read to/from this socket */
    u_int32_t total_size;                   /* total size of the file being read */
    u_int32_t total_read;                   /* total size already read from socket/disk */
    u_int32_t buffer_size;                  /* size of the data currently stored in buffer */
    char buffer[SIZE_READ_BUFFER];          /* buffer where the last */
} __attribute__((__packed__));
typedef struct _large_file large_file;

/* this message indicates that an error occured, it is protected to ensure the source
   note: the nonces can be empty depending on the security manager state */
struct _protected_error{
    nonce nonce_rp[NONCE_LENGTH];            /* nonce chosen by the reseller/provider */
    nonce nonce_c[NONCE_LENGTH];             /* nonce chosen by the consumer */
    int8_t error_code;                       /* the code of the occured error */
    public_key source;                       /* person from who the message is originating */
    char signature[RSA_SHA1_SIGLEN];         /* signed by the originator */
} __attribute__((__packed__));
typedef struct _protected_error protected_error;


/* get */
/* this message is sent to initiate a connection from a consumer to a reseller/provider */
struct _new_connection{
    public_key source;                       /* public key of the consumer */
    nonce nonce_c[NONCE_LENGTH];             /* nonce chosen by the consumer */
} __attribute__((__packed__));
typedef struct _new_connection new_connection;

/* the mutual_auth message is always sent from the reseller/provider to the consumer */
struct _mutualauth{
    nonce nonce_r[NONCE_LENGTH];             /* nonce chosen by the reseller */
    nonce nonce_c[NONCE_LENGTH];             /* nonce chosen by the consumer */
    public_key target;                       /* public key of the person where this message is intended for */
    char signature[RSA_SHA1_SIGLEN];         /* signed by the reseller/provider {nonce_r, nonce_c, target} */
} __attribute__((__packed__));
typedef struct _mutualauth mutualauth;

/* the payment is sent from the consumer to the reseller/provider */
struct _payment{
    nonce nonce_c[NONCE_LENGTH];             /* nonce chosen by the consumer */
    nonce nonce_r[NONCE_LENGTH];             /* nonce chosen by the reseller */
    char sha_hash[SHA_DIGEST_LENGTH];        /* SHA-1 hash of the content */
    rights content_rights;                   /* rights of the content that was obtained/requested, including payment amount */
    public_key target;                       /* public key of the person entitled to own this payment */
    char signature[RSA_SHA1_SIGLEN];         /* signed by the consumer */
} __attribute__((__packed__));
typedef struct _payment payment;

/* the secured content message is always sent from the reseller/provider to the consumer */
struct _secured_content{
    u_int32_t content_length;                /* the length of the encrypted content */
    unsigned char key[RSA_ENCRYPTED_BLOCK_LENGTH];  /* AES key encrypted with public RSA key of consumer */
    unsigned char iv[AES_KEY_LENGTH];        /* initialization vector of the AES encryption */
    rights content_rights;                   /* rights of the content */
    nonce nonce_c[NONCE_LENGTH];             /* nonce chosen by the consumer */
    char signature[RSA_SHA1_SIGLEN];         /* {content_rights, nonce_c} signed by the reseller/provider */
} __attribute__((__packed__));
typedef struct _secured_content secured_content;

/* the next few structs are needed for protcols other than get */

/* restore */
/* the restored payment message is sent from the consumer to the provider */
struct _restored_payment{
    nonce nonce_c[NONCE_LENGTH];             /* nonce chosen by the consumer */
    nonce nonce_p[NONCE_LENGTH];             /* nonce chosen by the provider */
    payment restore;                         /* the payment message being restored */
    public_key target;                       /* public key of the provider */
    char signature[RSA_SHA1_SIGLEN];         /* signed by the consumer */
} __attribute__((__packed__));
typedef struct _restored_payment restored_payment;

/* cash */
/* a list of payments intended for the cash protocol */
struct _payment_list{
    u_int16_t len;                           /* the length of the list */
    payment** payments;                      /* pointer to the list */
} __attribute__((__packed__));
typedef struct _payment_list payment_list;

#endif /* _DATA_H_ */
