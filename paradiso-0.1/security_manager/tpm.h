#ifndef _TPM_H_
#define _TPM_H_ 1

/* this file tries to address all functionalities provided by a TPM
   in seperate methods. At this moment openssl is used to process the
   TPM requests but these calls can in the future easily be replaced
   with TPM calls.
   note: this is no TPM emulator whatsoever, and it does not comply
   to architectures designed by the Trusted Computing Group */

/*
    embedded in TPM:
        randomizer
        SHA-1
        RSA
        AES
        secured storage
*/

#include <openssl/rsa.h>
#include <openssl/aes.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/engine.h>
#include <openssl/rand.h>
#include <openssl/objects.h>
#include <openssl/err.h>
#include <string.h>
#include <math.h>

#include "../generic/generic.h"
#include "../data.h"
#include "../interface.h"
#include "../data_manager/data_manager.h"

/* the secured storage is 512KB long */
#define SECURE_MEMORY_LENGTH 524288

/* the secure scratch memory is 192KB long */
#define SECURE_SCRATCH_MEMORY_LENGTH 196608

/* hashes of CLF are stored in the secured memory. We keep track of
   free space in the secured memory with a bitmap. The size of the bitmap
   depends on the size of hashes and the size of the memory */

/* one hash takes up SHA_DIGEST_LENGTH bytes, and 8 hashes needs one byte in the bitmap */
#define HASH_BYTESIZE ((SHA_DIGEST_LENGTH * 8) + 1)

/* now we can estimate the number of bytes we need for the bitmap */
#define HASH_BITMAP_SIZE (SECURE_MEMORY_LENGTH / HASH_RELSIZE)

/* so now we estimate the total of hashes we can store */
#define HASH_TOTAL (8 * HASH_BITMAP_SIZE)

/* this macro can be used to manipulate the bitmap, we first calculate the byte number,
   and then we manipulate this byte accordingly. we start counting at zero! */
#define BITMAP_SET(bitmap, index) bitmap[(index / 8)] |= (1 << (index % 8))
#define BITMAP_UNSET(bitmap, index) bitmap[(index / 8)] &= ~(1 << (index % 8))
#define BITMAP_TOGGLE(bitmap, index) bitmap[(index / 8)] ^= (1 << (index % 8))

/* declare global generic error variables */
DEFERROR(E_SM_TPM_READ_PRIVATE_KEY,                 "Could not read private key file.", -3100);
DEFERROR(E_SM_TPM_GEN_RSAPRIVATEKEY,                "Could not regenerate raw private key.", -3101);
DEFERROR(E_SM_TPM_READ_PUBLIC_KEY,                  "Could not read public key file.", -3102);
DEFERROR(E_SM_TPM_PUBLIC_KEYLEN_MISMATCH,           "Public keylength differs from expected key length.", -3103);
DEFERROR(E_SM_TPM_MEM_COPY,                         "Could not perform copy memory operation.", -3104);
DEFERROR(E_SM_TPM_GEN_RSAPUBLICKEY,                 "Could not regenerate raw public key.", -3105);
DEFERROR(E_SM_TPM_SET_DEVICENAME,                   "Could not set device name.", -3106);
DEFERROR(E_SM_TPM_READ_SECURED_STORAGE,             "Could not read secure storage file.", -3107);
DEFERROR(E_SM_TPM_READ_MANUFACTURER_SIG,            "Could not read manufacturer signature.", -3108);
DEFERROR(E_SM_TPM_READ_MANUFACTURER_SIG_MISMATCH,   "Manufacturer signature length differs from expected length.", -3109);
DEFERROR(E_SM_TPM_READ_LICENSEORG_SIG,              "Could not read license organization signature.", -3110);
DEFERROR(E_SM_TPM_READ_LICENSEORG_SIG_MISMATCH,     "License org. signature length differs from expected length.", -3111);
DEFERROR(E_SM_TPM_EVP_DIGEST_INIT,                  "Could not initialize EVP digest.", -3112);
DEFERROR(E_SM_TPM_EVP_DIGEST_UPDATE,                "Could not update EVP digest.", -3113);
DEFERROR(E_SM_TPM_EVP_DIGEST_FINAL,                 "Could not finalize EVP digest.", -3114);
DEFERROR(E_SM_TPM_EVP_ASSIGN_RSA,                   "Could not assign RSA key to EVP digest.", -3115);
DEFERROR(E_SM_TPM_EVP_VERIFY_INIT,                  "Could not initialize EVP verification.", -3116);
DEFERROR(E_SM_TPM_EVP_VERIFY_UPDATE,                "Could not update EVP verification.", -3117);
DEFERROR(E_SM_TPM_RAND_BYTES,                       "Could not generate random bytes.", -3118);
DEFERROR(E_SM_TPM_EVP_SIGN_INIT,                    "Could not initialize EVP signing.", -3119);
DEFERROR(E_SM_TPM_EVP_SIGN_UPDATE,                  "Could not update EVP signing.", -3120);
DEFERROR(E_SM_TPM_EVP_SIGN_FINAL,                   "Could not finalize EVP signing.", -3121);
DEFERROR(E_SM_TPM_SIGLEN_MISMATCH,                  "Signature length differs from expected signature length.", -3122);
DEFERROR(E_SM_TPM_RSA_ENCRYPT_OVERFLOW,             "Given result string too small for RSA encryption result.", -3123);
DEFERROR(E_SM_TPM_RSA_ENCRYPT,                      "Could not perform RSA public key encryption.", -3124);
DEFERROR(E_SM_TPM_RSA_DECRYPT_OVERFLOW,             "Given result string too small for RSA decryption result.", -3125);
DEFERROR(E_SM_TPM_RSA_DECRYPT,                      "Could not perform RSA private key decryption.", -3126);
DEFERROR(E_SM_TPM_EVP_ENCRYPT_INIT,                 "Could not initialize EVP encryption.", -3127);
DEFERROR(E_SM_TPM_EVP_ENCRYPT_UPDATE,               "Could not update EVP encryption.", -3128);
DEFERROR(E_SM_TPM_EVP_ENCRYPT_FINAL,                "Could not finalize EVP encryption.", -3129);
DEFERROR(E_SM_TPM_EVP_DECRYPT_INIT,                 "Could not initialize EVP decryption.", -3130);
DEFERROR(E_SM_TPM_EVP_DECRYPT_UPDATE,               "Could not update EVP decryption.", -3131);
DEFERROR(E_SM_TPM_EVP_DECRYPT_FINAL,                "Could not finalize EVP decryption.", -3132);
DEFERROR(E_SM_TPM_SECMEM_WRITE,                     "Could not write-through secured storage.", -3133);
DEFERROR(E_SM_TPM_RSA_ENCRYPT_DATALEN,              "Supplied data to RSA encrypt is too large.", -3134);
DEFERROR(E_SM_TPM_RSA_DECRYPT_DATALEN,              "Supplied data to RSA decrypt is too large.", -3135);
DEFERROR(E_SM_TPM_PRIVATEKEY_CORRUPT,               "Private key from TPM is corrupt.", -3136);
DEFERROR(E_SM_TPM_RSA_DECRYPT_EXPECTEDLENGTH,       "Expected length of decrypted RSA data is incorrect.", -3137);
DEFERROR(E_SM_TPM_AES_BLOCKSIZE_MISMATCH,           "Expected block size of AES encrypted block does not correspond with real size.", -3138);
DEFERROR(E_SM_TPM_RSA_SIGNATURE_INCORRECT,          "Signature fed to TPM appears to be incorrect.", -3139);
DEFERROR(E_SM_TPM_SHA1_SEC_MISMATCH,                "SHA-1 hash in secured memory does not correspond with data.", -3140);
DEFERROR(E_SM_TPM_BUFFERSIZE_TOOSMALL,              "The buffer size for large files may not be smaller then the cipher block size.", -3141);
DEFERROR(E_SM_TPM_BUFFERSIZE_TOOLARGE,              "The buffer size is too large to cooperate with the TPM secured scratch memory.", -3142);
DEFERROR(E_SM_TPM_BUFFERSIZE_COLISSION,             "An unexpected buffer size collision occured.", -3143);
int tpm_init(char *device_name);
int tpm_cleanup();
int tpm_sha1_check(char *data, uint16_t datalen, uint16_t index);
int tpm_set_secure_hash_slot(char *data, uint16_t datalen, uint16_t index);

int tpm_rsa_signature_check(char *data, uint16_t datalen, unsigned char *signature, RSA *pkey);
int tpm_rsa_signature_check_raw(char *data, uint16_t datalen, unsigned char *signature, unsigned char *pkey);
int tpm_rsa_signature_check_licenseorg(char *data, uint16_t datalen, unsigned char *signature);
int tpm_rsa_signature_check_manufacturer(char *data, uint16_t datalen, unsigned char *signature);
int tpm_rsa_signature_create(char *data, uint16_t datalen, unsigned char *signature);
int tpm_rsa_encrypt(unsigned char *data, uint16_t datalen, RSA *pkey, unsigned char *result, int reslen);
int tpm_rsa_decrypt(char *encrypted_block, unsigned char *decrypted_block, int blocklen, int reslen);

int tpm_sha_hash_start();
int tpm_sha_hash_step(char *data, u_int32_t datalen);
int tpm_sha_hash_stop(char *sha_hash);
int tpm_sha_hash_cancel();

int tpm_content_encode_start(uint32_t buffer_size, secured_content *content, unsigned char *pkey);
int tpm_content_encode_step(char *data, uint32_t datalen, char **result, uint32_t *resultlen);
int tpm_content_encode_stop(char **result, uint32_t *resultlen);
int tpm_content_encode_cancel();
        
int tpm_content_decode_start(secured_content *old_content, uint32_t buffer_size);
int tpm_content_decode_step(char *data, uint32_t datalen, char **result, uint32_t *resultlen);
int tpm_content_decode_stop(char **result, uint32_t *resultlen);
int tpm_content_decode_cancel();

int tpm_content_recode_start(secured_content *old_content, secured_content *new_content, uint32_t buffer_size, unsigned char *pkey);
int tpm_content_recode_step(large_file *lfp);
int tpm_content_recode_stop(large_file *lfp);
int tpm_content_recode_cancel();

int tpm_content_check_key(char *sha_hash, secured_content *content);
int tpm_randomize(char *target, uint16_t size);
int tpm_get_pkey(public_key *pkey);


#endif /* _TPM_H_ */
