#ifndef _INTERFACE_H_
#define _INTERFACE_H_ 1

/* if you get compiler errors from this header file then you probably
   forget to include the openssl header files */

/* this file contains structs etc. for communication with the nuovo interface
   note: please do not confuse this with any data_client communication, these structs
   are only to send additional information from the interface to the interface server */

/* some cryptographic values */
#define AES_KEY_LENGTH  32                  /* the kind of EAS (rijndael) key we use, 256 bits */
#define RSA_LENGTH 2048                     /* the length of the RSA key */
#define RSA_ENCRYPTED_BLOCK_LENGTH 256      /* the length of a block of RSA encrypted data */
#define RSA_SHA1_SIGLEN 256                 /* length of a signature depends on RSA key length */
#define RSA_PKEY_RAW_LENGTH 270             /* length of RSA public key on disk depends on key length */

/* the maximum length of a hostname */
#define MAXLEN_HOSTNAME 128

/* maximum length of the self-chosen device name */
#define MAXLEN_DEVICENAME     128

/* maximum length of the several parts of content information */
#define MAXLEN_CONTENT_INFO 128

/* define the request types used by the interface server */
#define IS_REQUEST_GET      1       /* request content at a given party */
#define IS_REQUEST_SESSIONS 2       /* request a list of session which can be restored */
#define IS_REQUEST_RESTORE  3       /* request a certain session to be restored */
#define IS_REQUEST_LIST     4       /* request a list of available content at a given reseller */
#define IS_REQUEST_UPDATE   5       /* request a DRL */
#define IS_REQUEST_CASH     6       /* cash all payments at a given bank !NOT AVAILABLE! */
#define IS_REQUEST_SCAN     7       /* scan the network for other nuovo servers */
#define IS_REQUEST_ADD      8       /* add content to the device, only at provider side */
#define IS_REQUEST_REVOKE   9       /* add the given device to the DRL, only at provider side */
#define IS_REQUEST_PLAY     10      /* plays the content with the given content hash */
#define IS_REQUEST_PKEY     11      /* get the public key of the local device */

/* note: still not sure if these are really needed.... aren't the internal error codes
   good enough? */

/* these status indicators are used to reply */
#define IS_REPLY_OK          0      /* request was finished succesfully
                                       note: more data could follow this indicator */
#define IS_REPLY_ERR_AUTH    1      /* authentication failed */
#define IS_REPLY_ERR_SAVEC   2      /* saving the content failed */
#define IS_REPLY_ERR_LIST    3      /* could not read list */
#define IS_REPLY_ERR_NOPAY   4      /* there are no payments available to cash */

/* the types used by the public key struct */
#define NUOVO_SERVER_TYPE_RESELLER 0
#define NUOVO_SERVER_TYPE_PROVIDER 1

/* these are the several possible content types */
#define CONTENT_TYPE_AUDIO 0
#define CONTENT_TYPE_VIDEO 1
#define CONTENT_TYPE_IMAGE 2
#define CONTENT_TYPE_TEXT 3
#define CONTENT_TYPE_SOFT 4

/* a public key and signature of a nuovo server
   the RSA public key is signed by the manufacturer,
   and the manufacturer pkey by the licensing organization...
   the pkey of the licensing organization is embedded in the TPM */
struct _public_key{
    char device_name[MAXLEN_DEVICENAME];                   /* the name of the device chosen by owner */
    u_int8_t type;                                         /* the type can be RESELLER or PROVIDER */
    unsigned char device_pkey[RSA_PKEY_RAW_LENGTH];        /* the actual public key of the device */
    unsigned char signature[RSA_SHA1_SIGLEN];              /* signature of public key created by manufacturer */
    unsigned char manufacturer_pkey[RSA_PKEY_RAW_LENGTH];  /* public key of the manufacturer */
    unsigned char manufacturer_signature[RSA_SHA1_SIGLEN]; /* signature of manufacturer pkey created by license org. */
} __attribute__((__packed__));
typedef struct _public_key public_key;

/*  the rights container
    note: should be represented with XACml or XrML */
struct _rights{
    uint16_t resell_count;                      /* resell count */
    uint16_t resell_depth;                      /* the maximum depth reselling is allowed */
    uint16_t resell_total;                      /* the number of times the content has been resold */
    uint32_t price;                             /* price of the content in cents, max price: € 42.949.672,95 */
} __attribute__((__packed__));
typedef struct _rights rights;

/* this struct is used to store information about content including
   the hash to uniqely identify it */
struct _content_info{
    unsigned char hash[SHA_DIGEST_LENGTH];     /* SHA-1 hash of the content */
    uint8_t type;                              /* type of the content */
    unsigned char title[MAXLEN_CONTENT_INFO];  /* content title */
    unsigned char author[MAXLEN_CONTENT_INFO]; /* author/artist of the content */
    rights content_rights;                     /* the content rights */
    uint32_t content_size;                     /* original size of the content in bytes */
} __attribute__((__packed__));
typedef struct _content_info content_info;

/* nuovo server struct containing connect information */
struct _nuovo_server{
    public_key pkey;                            /* public key of the server */
    uint16_t port;                              /* the port used by the data server */
    unsigned char hostname[MAXLEN_HOSTNAME];    /* normally an ip address */
} __attribute__((__packed__));
typedef struct _nuovo_server nuovo_server;


typedef u_int8_t state;                         /* definition of the state type used by security manager sessions */

/* open session struct contains session which is still open */
struct _open_session{
    u_int16_t index;                            /* fileindex location of the session if stored to disk */
    content_info info;                          /* detailed information about the content */
    public_key target;                          /* the target device */
} __attribute__((__packed__));
typedef struct _open_session open_session;

/* ***************
   the following structs are sent to the interface server
   ***************
*/

/* this struct is used to sent a request get command to the interface server */
struct _interface_request_get{
    content_info info;               /* details about the requested content */
    nuovo_server request_at;         /* the server where the content should be requested */
} __attribute__((__packed__));
typedef struct _interface_request_get interface_request_get;

/* only the command indicator should be sent to trigger request sessions */

/* this struct is used for the request restore command */
struct _interface_request_restore{
    u_int16_t index;                 /* the fileindex of the session to be restored */
    nuovo_server restore_at;         /* provider where the content should be restored */
} __attribute__((__packed__));
typedef struct _interface_request_restore interface_request_restore;

/* the nuovo_server struct is used for the request list command */

/* the struct nuovo_server is also used for the request update command */

/* cash command isn't available in the prototype */

/* only the command indicator should be sent to trigger request scan */

/* content info struct should be sent for play request */

/* this struct is used to sent a add content request to the interface server
   note: struct became useless short during implementation of large file support*/
struct _raw_content{
    content_info info;               /* information about this content */
} __attribute__((__packed__));
typedef struct _raw_content raw_content;

/* ***************
   the following structs are replied by the interface server
   ***************
*/

/* this struct is used for the request sessions command, AS REPLY!
   note: do not confuse with the list command for content listing! */
struct _interface_reply_session_list{
    u_int16_t len;                   /* the length of the list */
    open_session **list;             /* pointer to pointer of sessions */
} __attribute__((__packed__));
typedef struct _interface_reply_session_list interface_reply_session_list;

/* this struct is replied by the request scan command */
struct _interface_reply_scan_list{
    u_int16_t len;                   /* length of the list */
    nuovo_server **list;             /* the available servers */
} __attribute__((__packed__));
typedef struct _interface_reply_scan_list interface_reply_scan_list;

/* the following structs are all for the list request, most of these
   structs are also used by the data server/client and data manager */

struct _content_info_list{
    u_int16_t len;                    /* the length of the list */
    content_info** list;              /* pointer to the list of information of available content */
} __attribute__((__packed__));
typedef struct _content_info_list content_info_list;

/* the revocation list is used for the update command */
struct _revocation_list{
    u_int16_t len;                    /* the length of the list */
    char** revoked_keys;              /* pointer to the list of revoked public keys (raw) */
    char signature[RSA_SHA1_SIGLEN];  /* signature of a trusted provider */
    public_key provider;              /* the public key of the provider */
} __attribute__((__packed__));
typedef struct _revocation_list revocation_list;

#endif /* _INTERFACE_H_ */
