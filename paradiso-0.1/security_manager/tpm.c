#include "tpm.h"

/* indicates if the tpm has been initialized */
int tpm_state = 0;

/* raw public key */
public_key tpm_pkey;

/* non-raw public keys */
RSA *device_public_key;
RSA *manufacturer_public_key;

unsigned char *temp_sig;

/* ** all data mentioned below is conceptually stored in the TPM... so don't worry! ** */

char secured_storage[SECURE_MEMORY_LENGTH];          /* memory for secured storage */
char scratch_memory[SECURE_SCRATCH_MEMORY_LENGTH];   /* scratch memory for storing secure data */
RSA *tpm_private_key;                                /* memory where the private key resides */
char licenseorg_raw_public_key[RSA_PKEY_RAW_LENGTH]; /* raw public key of licensing organizatoin */
RSA *licenseorg_public_key;                          /* memory where the public key of the licensing org. resides */

/* these are used to keep state of encryption/decryption */
EVP_MD_CTX sha_ctx;
EVP_CIPHER_CTX aes_encrypt_ctx;
EVP_CIPHER_CTX aes_decrypt_ctx;
char *result_buffer;

/* ** end of TPM memory ** */

/* this method converts a raw rsa public key to normal RSA format */
PRIVATE int tpm_rsa_convert_public(unsigned char *rsa_raw_pkey, RSA **rsa_pkey){
    unsigned char *tmp;

    tmp = rsa_raw_pkey;
    *rsa_pkey = d2i_RSAPublicKey(NULL, (const unsigned char**) &tmp, RSA_PKEY_RAW_LENGTH);
    if(rsa_pkey == NULL){
        return quit(&E_SM_TPM_GEN_RSAPUBLICKEY);
    }

    /* return success */
    return 1;
}

/* this method reads a rsa private key from disk and stores it in pkey */
PRIVATE int tpm_read_private_key(char *pkey_file, RSA **pkey){
    unsigned char *rsa_key_buffer;
    int rsa_key_length, status;
    unsigned char *tmp;

    /* read the private key from disk */
    status = dm_read_custom_file(pkey_file, SAVE_DIR_TPM, &rsa_key_length, (unsigned char **)&rsa_key_buffer);
    if(status < 0){
        return quit(&E_SM_TPM_READ_PRIVATE_KEY);
    }

    /* regenerate the raw RSA private key */
    tmp = rsa_key_buffer;
    *pkey = d2i_RSAPrivateKey(NULL, (const unsigned char**) &tmp, rsa_key_length);
    if(pkey == NULL){
        return quit(&E_SM_TPM_GEN_RSAPRIVATEKEY);
    }

    /* free the temporary buffer */
    deallocate(rsa_key_buffer);

    /* return success */
    return 1;
}

/* this method reads a rsa public key from disk and stores the raw version
   in buffer and the converted version in pkey */
PRIVATE int tpm_read_public_key(char *pkey_file, char *buffer, RSA **pkey){
    unsigned char *rsa_key_buffer;
    int rsa_key_length, status;

    /* read the device public key from disk */
    status = dm_read_custom_file(pkey_file, SAVE_DIR_KEYS, &rsa_key_length, (unsigned char **)&rsa_key_buffer);
    if(status < 0){
        return quit(&E_SM_TPM_READ_PUBLIC_KEY);
    }

    /* check the length of the key */
    if(RSA_PKEY_RAW_LENGTH != rsa_key_length){
        return quit(&E_SM_TPM_PUBLIC_KEYLEN_MISMATCH);
    }
    
    /* copy the raw version to the buffer */
    if(memcpy(buffer, rsa_key_buffer, RSA_PKEY_RAW_LENGTH) == NULL){
        return quit(&E_SM_TPM_MEM_COPY);
    }

    /* regenerate the raw RSA public key */
    if(tpm_rsa_convert_public(buffer, pkey) < 0){
        return LAST_ERROR;
    }

    /* free the temporary buffer */
    deallocate(rsa_key_buffer);
    
    /* return success */
    return 1;
}

/* this method initializes the TPM, this method should be called once,
   but can be called multiple times, and is used to emulate the tpm
   from disk, a large part can probably be cleared when a real TPM is used  */
PUBLIC int tpm_init(char *device_name){
    int rsa_sig_length, status;

    /* check if the TPM was initialized already */
    if(tpm_state != 0){
        return 1;
    }

    /* set the state */
    tpm_state = 1;

    /* set the type of the public key */
    #ifndef _PROVIDER_
    tpm_pkey.type = NUOVO_SERVER_TYPE_RESELLER;
    #else
    tpm_pkey.type = NUOVO_SERVER_TYPE_PROVIDER;
    #endif /* _PROVIDER_ */

    /* set the device name in the pkey */
    if(strncpy(tpm_pkey.device_name, device_name, MAXLEN_DEVICENAME) == NULL){
        return quit(&E_SM_TPM_SET_DEVICENAME);
    }
    tpm_pkey.device_name[MAXLEN_DEVICENAME - 1] = '\0';
    
    /* read the device private key */
    status = tpm_read_private_key(TPM_PRIVATE_KEY_FILE, &tpm_private_key);
    if(status < 0){
        return status;
    }

    /* check if the private key is oke */
    if(RSA_check_key(tpm_private_key) != 1){
        return quit(&E_SM_TPM_PRIVATEKEY_CORRUPT);
    }

    /* read the device public key */
    status = tpm_read_public_key(DEVICE_PUBLIC_KEY_FILE, tpm_pkey.device_pkey, &device_public_key);
    if(status < 0){
        return status;
    }

    /* read the signature made by the manufacturer */
    status = dm_read_custom_file(DEVICE_PKEY_SIG_FILE, SAVE_DIR_KEYS, &rsa_sig_length, &temp_sig);
    if(status < 0){
        return quit(&E_SM_TPM_READ_MANUFACTURER_SIG);
    }
    if(rsa_sig_length != RSA_SHA1_SIGLEN){
        return quit(&E_SM_TPM_READ_MANUFACTURER_SIG_MISMATCH);
    }

    /* copy the read signature */
    if(memcpy(tpm_pkey.signature, temp_sig, RSA_SHA1_SIGLEN) == NULL){
        return quit(&E_SM_TPM_MEM_COPY);
    }

    /* read the manufacturer public key */
    status = tpm_read_public_key(MANUFACTURER_PUBLIC_KEY_FILE, tpm_pkey.manufacturer_pkey, &manufacturer_public_key);
    if(status < 0){
        return status;
    }

    /* check the manufacturer signature
       note: this only guarantees that the public key and signature correspond */
    status = tpm_rsa_signature_check_manufacturer(tpm_pkey.device_pkey, RSA_PKEY_RAW_LENGTH, tpm_pkey.signature);
    if(status < 0){
        return status;
    }

    /* read the signature made by the licensing org. */
    status = dm_read_custom_file(MANUFACTURER_PKEY_SIG_FILE, SAVE_DIR_KEYS, &rsa_sig_length, &temp_sig);

    if(status < 0){
        return quit(&E_SM_TPM_READ_LICENSEORG_SIG);
    }
    if(rsa_sig_length != RSA_SHA1_SIGLEN){
        return quit(&E_SM_TPM_READ_LICENSEORG_SIG_MISMATCH);
    }

    /* copy the read signature */
    if(memcpy(tpm_pkey.manufacturer_signature, temp_sig, RSA_SHA1_SIGLEN) == NULL){
        return quit(&E_SM_TPM_MEM_COPY);
    }

    /* read the licensing org. public key */
    status = tpm_read_public_key(LICENSEORG_PUBLIC_KEY_FILE, licenseorg_raw_public_key, &licenseorg_public_key);
    if(status < 0){
        return status;
    }

    /* check the licensing org. signature
       note: this only guarantees that the public key and signature correspond */
    status = tpm_rsa_signature_check_licenseorg(tpm_pkey.manufacturer_pkey, RSA_PKEY_RAW_LENGTH, tpm_pkey.manufacturer_signature);
    if(status < 0){
        return status;
    }

    /* return success */
    return 1;
}

PUBLIC int tpm_cleanup(char *device_name){
    deallocate(temp_sig);
    deallocate(tpm_pkey.manufacturer_signature);

    return 1;
}

/* this method checks if some supplied data still is consistent. It computes
   the SHA-1 hash of the data and compares it with the hash stored at location
   'index' of the secured memory */
PUBLIC int tpm_sha1_check(char *data, uint16_t datalen, uint16_t index){
    int status, offset;
    char sha_hash[SHA_DIGEST_LENGTH];
    EVP_MD_CTX ctx;

    /* initialize the digest contet */
    EVP_MD_CTX_init(&ctx);

    /* setup sha1 */
    status = EVP_DigestInit_ex(&ctx, EVP_sha1(), NULL);
    if(status != 1){
        EVP_MD_CTX_cleanup(&ctx);
        return quit(&E_SM_TPM_EVP_DIGEST_INIT);
    }

    /* hash the data with sha1 */
    status = EVP_DigestUpdate(&ctx, data, datalen);
    if(status != 1){
        EVP_MD_CTX_cleanup(&ctx);
        return quit(&E_SM_TPM_EVP_DIGEST_UPDATE);
    }

    /* finalize the hashing and write the result to our buffer */
    status = EVP_DigestFinal_ex(&ctx, sha_hash, NULL);
    if(status != 1){
        EVP_MD_CTX_cleanup(&ctx);
        return quit(&E_SM_TPM_EVP_DIGEST_FINAL);
    }

    /* clean the digest contet */
    EVP_MD_CTX_cleanup(&ctx);

    /* read all secured storage from disk */
    status = dm_read_file(TPM_SECURED_STORAGE_FILE, SAVE_DIR_TPM, SECURE_MEMORY_LENGTH, secured_storage);
    if(status < 0){
        return quit(&E_SM_TPM_READ_SECURED_STORAGE);
    }

    /* calculate the secured storage offset */
    offset = SHA_DIGEST_LENGTH * index;
    
//printf("tpm_sha1_check> SLOT %i: %03i %03i %03i %03i %03i %03i %03i %03i %03i %03i\n", index, sha_hash[0], sha_hash[1], sha_hash[2], sha_hash[3], sha_hash[4], sha_hash[5], sha_hash[6], sha_hash[7], sha_hash[8], sha_hash[9]);
//printf("tpm_sha1_check> SECM %i: %03i %03i %03i %03i %03i %03i %03i %03i %03i %03i\n", index, (secured_storage+offset)[0], (secured_storage+offset)[1], (secured_storage+offset)[2], (secured_storage+offset)[3], (secured_storage+offset)[4], (secured_storage+offset)[5], (secured_storage+offset)[6], (secured_storage+offset)[7], (secured_storage+offset)[8], (secured_storage+offset)[9]);

    /* now verify the hash */
    if(memcmp((const void *)sha_hash, (const void*)(secured_storage+offset), SHA_DIGEST_LENGTH) !=0){
        return quit(&E_SM_TPM_SHA1_SEC_MISMATCH);
    }
    
    /* validated with success */
    return 1;
}

/* hashes the given data and stores it at hash-slot index */
int tpm_set_secure_hash_slot(char *data, uint16_t datalen, uint16_t index){
    int status, offset, len;
    char sha_hash[SHA_DIGEST_LENGTH];
    EVP_MD_CTX ctx;

    /* initialize the digest contet */
    EVP_MD_CTX_init(&ctx);

    /* setup sha1 */
    status = EVP_DigestInit_ex(&ctx, EVP_sha1(), NULL);
    if(status != 1){
        EVP_MD_CTX_cleanup(&ctx);
        return quit(&E_SM_TPM_EVP_DIGEST_INIT);
    }

    /* hash the data with sha1 */
    status = EVP_DigestUpdate(&ctx, data, datalen);
    if(status != 1){
        EVP_MD_CTX_cleanup(&ctx);
        return quit(&E_SM_TPM_EVP_DIGEST_UPDATE);
    }

    /* finalize the hashing and write the result to our buffer */
    status = EVP_DigestFinal_ex(&ctx, sha_hash, &len);
    if(status != 1){
        EVP_MD_CTX_cleanup(&ctx);
        return quit(&E_SM_TPM_EVP_DIGEST_FINAL);
    }

    /* clean the digest contet */
    EVP_MD_CTX_cleanup(&ctx);

    /* read all secured storage from disk */
    status = dm_read_file(TPM_SECURED_STORAGE_FILE, SAVE_DIR_TPM, SECURE_MEMORY_LENGTH, secured_storage);
    if(status < 0){
        return quit(&E_SM_TPM_READ_SECURED_STORAGE);
    }

    /* calculate the secured storage offset */
    offset = SHA_DIGEST_LENGTH * index;

//printf("tpm_set_secure_hash_slot> SLOT %i: %03i %03i %03i %03i %03i %03i %03i %03i %03i %03i\n", index, sha_hash[0], sha_hash[1], sha_hash[2], sha_hash[3], sha_hash[4], sha_hash[5], sha_hash[6], sha_hash[7], sha_hash[8], sha_hash[9]);

    /* store the hash to secured memory */
    if(memcpy(secured_storage + offset, sha_hash, SHA_DIGEST_LENGTH) == NULL){
        return quit(&E_SM_TPM_MEM_COPY);
    }

    /* write the secured storage changes to disk */
    status = dm_create_file(TPM_SECURED_STORAGE_FILE, SAVE_DIR_TPM, SECURE_MEMORY_LENGTH, secured_storage);
//    status = dm_write_file(TPM_SECURED_STORAGE_FILE, SAVE_DIR_TPM, SHA_DIGEST_LENGTH, offset, secured_storage + offset);
    if(status < 0){
        return quit(&E_SM_TPM_SECMEM_WRITE);
    }

    /* validated with success */
    return 1;
}

/* this method checks if the supplied data and signature correspond to each other based
   on the provided public key. It uses the higher level methods of OPENSSL */
PUBLIC int tpm_rsa_signature_check(char *data, uint16_t datalen, unsigned char *signature, RSA *pkey){
    EVP_PKEY* evp_public_key;
    EVP_MD_CTX ctx;

    /* create the EVP public key from our RSA public key */
    evp_public_key = EVP_PKEY_new();
    if(EVP_PKEY_assign_RSA(evp_public_key, pkey) == 0){
        return quit(&E_SM_TPM_EVP_ASSIGN_RSA);
    }

    /* initialize the digest contet */
    EVP_MD_CTX_init(&ctx);
    
    /* initialize the verification process */
    if(EVP_VerifyInit_ex(&ctx, EVP_sha1(), NULL) == 0){
        EVP_MD_CTX_cleanup(&ctx);
        return quit(&E_SM_TPM_EVP_VERIFY_INIT);
    }

    /* add data tot the verification process */
    if(EVP_VerifyUpdate(&ctx, data, datalen) == 0){
        EVP_MD_CTX_cleanup(&ctx);
        return quit(&E_SM_TPM_EVP_VERIFY_UPDATE);
    }

    /* finalize the verification process */
    if(EVP_VerifyFinal(&ctx, signature, RSA_SHA1_SIGLEN, evp_public_key) == 0){
        /* signature incorrect */
        EVP_MD_CTX_cleanup(&ctx);
        return quit(&E_SM_TPM_RSA_SIGNATURE_INCORRECT);
    }

    /* clean-up the digest contet */
    EVP_MD_CTX_cleanup(&ctx);

    /* success */
    return 1;
}

/* this method checks if the supplied data and signature correspond to each other based
   on the raw public key pkey */
PUBLIC int tpm_rsa_signature_check_raw(char *data, uint16_t datalen, unsigned char *signature, unsigned char *pkey){
    RSA *rsa_pkey;

    /* regenerate the raw RSA public key */
    if(tpm_rsa_convert_public(pkey, &rsa_pkey) < 0){
        return LAST_ERROR;
    }

    /* now start the normal signature validation method */
    return tpm_rsa_signature_check(data, datalen, signature, rsa_pkey);
}

/* this method checks if the supplied data and signature correspond to each other based
   on the public key of the license organization */
PUBLIC int tpm_rsa_signature_check_licenseorg(char *data, uint16_t datalen, unsigned char *signature){
    return tpm_rsa_signature_check(data, datalen, signature, licenseorg_public_key);
}

/* this method checks if the supplied data and signature correspond to each other based
   on the public key of the manufacturer */
PUBLIC int tpm_rsa_signature_check_manufacturer(char *data, uint16_t datalen, unsigned char *signature){
    return tpm_rsa_signature_check(data, datalen, signature, manufacturer_public_key);
}

/* this method creates a signature of the data with the private key of the device and
   stores it in signature */
PUBLIC int tpm_rsa_signature_create(char *data, uint16_t datalen, unsigned char *signature){
    EVP_PKEY* evp_private_key;
    EVP_MD_CTX ctx;
    int siglen;

    /* create the EVP private key from the RSA private key */
    evp_private_key = EVP_PKEY_new();
    if(EVP_PKEY_assign_RSA(evp_private_key, tpm_private_key) == 0) {
        return quit(&E_SM_TPM_EVP_ASSIGN_RSA);
    }

    /* initialize the digest contet */
    EVP_MD_CTX_init(&ctx); 

    /* initialize the SHA-1 signing */
    if(EVP_SignInit_ex(&ctx, EVP_sha1(), NULL) == 0){
        EVP_MD_CTX_cleanup(&ctx);
        return quit(&E_SM_TPM_EVP_SIGN_INIT);
    }

    /* add data to the signature */
    if(EVP_SignUpdate(&ctx, data, datalen) == 0){
        EVP_MD_CTX_cleanup(&ctx);
        return quit(&E_SM_TPM_EVP_SIGN_UPDATE);
    }

    /* create and store the signature */
    if( EVP_SignFinal(&ctx, signature, &siglen, evp_private_key) == 0){
        EVP_MD_CTX_cleanup(&ctx);
        return quit(&E_SM_TPM_EVP_SIGN_FINAL);
    }
    if(RSA_SHA1_SIGLEN != siglen){
        EVP_MD_CTX_cleanup(&ctx);
        return quit(&E_SM_TPM_SIGLEN_MISMATCH);
    }  

    /* clean-up the digest contet */
    EVP_MD_CTX_cleanup(&ctx);
    
    /* signature created with success */
    return 1;
}

/* this method encrypts data with the given rsa public key and stores the
   result in result */
int tpm_rsa_encrypt(unsigned char *data, uint16_t datalen, RSA *pkey, unsigned char *result, int reslen){
    int status, maxlen;

    /* determine the maximum length of the result */
    maxlen = RSA_size(pkey);
    
    /* check for buffer-overflow */
    if(maxlen > reslen){
        return quit(&E_SM_TPM_RSA_ENCRYPT_OVERFLOW);
    }

    /* check if the supplied data isn't too large */
    if(datalen >= (maxlen - 41)){
        return quit(&E_SM_TPM_RSA_ENCRYPT_DATALEN);
    }
    
    /* rsa encrypt the content */
    status = RSA_public_encrypt(datalen, data, result, pkey, RSA_PKCS1_OAEP_PADDING);
    if(status != maxlen){
        return quit(&E_SM_TPM_RSA_ENCRYPT);
    }

    /* success */
    return 1;
}

/* this method decrypts the rsa encrypted block with our private rsa key and stores the
   result in decrypted block. The result is expected to be of reslen but beware that the
   complete decrypted block is stored and is commonly larger than the result itself */
int tpm_rsa_decrypt(char *encrypted_block, unsigned char *decrypted_block, int blocklen, int reslen){
    int status, maxlen;

    /* determine the maximum length of the result */
    maxlen = RSA_size(tpm_private_key);
    
    /* check if there is enough space for the result */
    if(maxlen > blocklen){
        return quit(&E_SM_TPM_RSA_DECRYPT_OVERFLOW);
    }

    /* check if the supplied reslen can't be correct */
    if(reslen >= (maxlen - 41)){
        return quit(&E_SM_TPM_RSA_DECRYPT_DATALEN);
    }
    
    /* rsa decrypt the content, status becomes the total number of result bytes */
    status = RSA_private_decrypt(maxlen, encrypted_block, decrypted_block, tpm_private_key, RSA_PKCS1_OAEP_PADDING);
    if(status < 0){
        return quit(&E_SM_TPM_RSA_DECRYPT);
    }

    /* check if the expected length is correct, otherwise stop */
    if(reslen != status){
        return quit(&E_SM_TPM_RSA_DECRYPT_EXPECTEDLENGTH);
    }

    /* success */
    return 1;
}

int tpm_sha_hash_start(){
    int status;
    
    /* initialize sha hashing */
    EVP_MD_CTX_init(&sha_ctx);
    status = EVP_DigestInit_ex(&sha_ctx, EVP_sha1(), NULL);
    if(status != 1){
        EVP_MD_CTX_cleanup(&sha_ctx);
        return quit(&E_SM_TPM_EVP_DIGEST_INIT);
    }
    return 1;
}

int tpm_sha_hash_step(char *data, u_int32_t datalen){
    int status;
    
    /* add all data to the sha-hash calculation */
    status = EVP_DigestUpdate(&sha_ctx, data, datalen);
    if(status != 1){
        EVP_MD_CTX_cleanup(&sha_ctx);
        return quit(&E_SM_TPM_EVP_DIGEST_UPDATE);
    }
    return 1;
}

int tpm_sha_hash_stop(char *sha_hash){
    int status;
    
    /* close the sha-hash */
    status = EVP_DigestFinal_ex(&sha_ctx, sha_hash, NULL);
    if(status != 1){
        EVP_MD_CTX_cleanup(&sha_ctx);
        return quit(&E_SM_TPM_EVP_DIGEST_FINAL);
    }
    return 1;
}

int tpm_sha_hash_cancel(){
    EVP_MD_CTX_cleanup(&sha_ctx);
    return 1;
}

int tpm_content_encode_start(uint32_t buffer_size, secured_content *content, unsigned char *pkey){
//    uint32_t aes_datalen, blocklen;
    RSA *rsa_pkey;
    char *aes_key;
    int status;

    /* set the pointers so we use the secured scratch memory
       note: we add buffer size + key size because the other part of the scratch memory is used by content decode */
    aes_key = scratch_memory + buffer_size + AES_KEY_LENGTH;

    /* generate a new aes content-key and store it in scratch memory */
    if(tpm_randomize(aes_key, AES_KEY_LENGTH) < 0){
        return LAST_ERROR;
    }

    /* prepare the public key to encrypt the AES key */
    if(pkey == NULL){
        rsa_pkey = device_public_key;
    } else {
        /* regenerate the raw RSA public key */
        if(tpm_rsa_convert_public(pkey, &rsa_pkey) < 0){
            return LAST_ERROR;
        }
    }

    /* encrypt the new aes content-key and store it in the content */
    if(tpm_rsa_encrypt(aes_key, AES_KEY_LENGTH, rsa_pkey, content->key, RSA_ENCRYPTED_BLOCK_LENGTH) < 0){
        return LAST_ERROR;
    }
    
    /* generate a initialization vector and store it in the content */
    if(tpm_randomize(content->iv, AES_KEY_LENGTH) < 0){
        return LAST_ERROR;
    }
    
    /* initialize AES encryption */
    EVP_CIPHER_CTX_init(&aes_encrypt_ctx);
    status = EVP_EncryptInit_ex(&aes_encrypt_ctx, EVP_aes_256_cbc(), NULL, aes_key, content->iv);
    if(status != 1){
        EVP_CIPHER_CTX_cleanup(&aes_encrypt_ctx);
        return quit(&E_SM_TPM_EVP_ENCRYPT_INIT);
    }
    
    /* check for size failures */
    if(buffer_size < EVP_CIPHER_CTX_block_size(&aes_encrypt_ctx)){
        EVP_CIPHER_CTX_cleanup(&aes_encrypt_ctx);
        return quit(&E_SM_TPM_BUFFERSIZE_TOOSMALL);
    }
    if(SECURE_SCRATCH_MEMORY_LENGTH < buffer_size + (2 * AES_KEY_LENGTH)){
        EVP_CIPHER_CTX_cleanup(&aes_encrypt_ctx);
        return quit(&E_SM_TPM_BUFFERSIZE_TOOLARGE);
    }
    
    /* calculate correct amount of memory per encrypted block */
/*    blocklen = EVP_CIPHER_CTX_block_size(&aes_encrypt_ctx);
    aes_datalen = (int)floor(buffer_size / blocklen);
    if(datalen % blocklen > 0){
         aes_datalen += 1;
    }
    aes_datalen *= blocklen;*/
    
    /* allocate the memory */
    result_buffer = allocate(buffer_size);
    if(result_buffer == NULL){
        return LAST_ERROR;
    }
    
    /* ready to perform steps now */
    return 1;
    
}

int tpm_content_encode_step(char *data, uint32_t datalen, char **result, uint32_t *resultlen){
    int inlen;
    int status;
    
    /* encrypt all data and save it to the new content */
    status = EVP_EncryptUpdate(&aes_encrypt_ctx, result_buffer, &inlen, data, datalen);
    if(status != 1){
        deallocate(result_buffer);
        EVP_CIPHER_CTX_cleanup(&aes_encrypt_ctx);
        return quit(&E_SM_TPM_EVP_ENCRYPT_UPDATE);
    }
    
    *resultlen = inlen;
    *result = result_buffer;

    /* step is ready */
    return 1;
}

int tpm_content_encode_stop(char **result, uint32_t *resultlen){
    int inlen;
    int status;
    
    /* close AES encryption */
    status = EVP_EncryptFinal_ex(&aes_encrypt_ctx, result_buffer, &inlen);
    if(status != 1){
        EVP_CIPHER_CTX_cleanup(&aes_encrypt_ctx);
        return quit(&E_SM_TPM_EVP_ENCRYPT_FINAL);
    }

    /* cleanup contets */
    EVP_CIPHER_CTX_cleanup(&aes_encrypt_ctx);
    
    *resultlen = inlen;
    *result = result_buffer;
    
    /* encoding ended successfully */
    return 1;
}

int tpm_content_encode_cancel(){
    EVP_CIPHER_CTX_cleanup(&aes_encrypt_ctx);
    
    /* free memory */
    deallocate(result_buffer);
    
    return 1;
}

int tpm_content_decode_start(secured_content *old_content, uint32_t buffer_size){
    char *aes_key;
    int status;
    
    /* set the pointers so we use the secured scratch memory
       note: we add the buffer size so we can use the scratch memory directly for decode results */
    aes_key = scratch_memory + buffer_size;
    
    /* decrypt the current content-key and store it in scratch memory */
    if(tpm_rsa_decrypt(old_content->key, aes_key, RSA_ENCRYPTED_BLOCK_LENGTH, AES_KEY_LENGTH) < 0){
        return LAST_ERROR;
    }
    
    /* initialize AES decryption */
    EVP_CIPHER_CTX_init(&aes_decrypt_ctx);
    status = EVP_DecryptInit_ex(&aes_decrypt_ctx, EVP_aes_256_cbc(), NULL, aes_key, old_content->iv);
    if(status != 1){
        EVP_CIPHER_CTX_cleanup(&aes_decrypt_ctx);
        return quit(&E_SM_TPM_EVP_DECRYPT_INIT);
    }
    
    /* check for buffer size failure */
    if(buffer_size < EVP_CIPHER_CTX_block_size(&aes_decrypt_ctx)){
        EVP_CIPHER_CTX_cleanup(&aes_decrypt_ctx);
        return quit(&E_SM_TPM_BUFFERSIZE_TOOSMALL);
    }
    if(SECURE_SCRATCH_MEMORY_LENGTH < buffer_size + (2 * AES_KEY_LENGTH)){
        EVP_CIPHER_CTX_cleanup(&aes_decrypt_ctx);
        return quit(&E_SM_TPM_BUFFERSIZE_TOOLARGE);
    }
    
    /* ready to perform steps now */
    return 1;
}

int tpm_content_decode_step(char *data, uint32_t datalen, char **result, uint32_t *resultlen){
    int outlen;
    int status;
    
    status = EVP_DecryptUpdate(&aes_decrypt_ctx, scratch_memory, &outlen, data, datalen);
    if(status != 1){
        EVP_CIPHER_CTX_cleanup(&aes_decrypt_ctx);
        return quit(&E_SM_TPM_EVP_DECRYPT_UPDATE);
    }
    *resultlen = outlen;
    *result = scratch_memory;
    
    /* step ready */
    return 1;
}

int tpm_content_decode_stop(char **result, uint32_t *resultlen){
    int outlen;
    int status;
    
    /* close AES decryption */
    status = EVP_DecryptFinal_ex(&aes_decrypt_ctx, scratch_memory, &outlen);
    if(status != 1){
        EVP_CIPHER_CTX_cleanup(&aes_decrypt_ctx);
        return quit(&E_SM_TPM_EVP_DECRYPT_FINAL);
    }
    *resultlen = outlen;
    *result = scratch_memory;

    /* cleanup contets */
    EVP_CIPHER_CTX_cleanup(&aes_decrypt_ctx);

    /* success */
    return 1;
}

int tpm_content_decode_cancel(){
    EVP_CIPHER_CTX_cleanup(&aes_decrypt_ctx);
    return 1;
}

/* this method re-encodes the content and stores the new (rsa-encrypted) key */
int tpm_content_recode_start(secured_content *old_content, secured_content *new_content, uint32_t buffer_size, unsigned char *pkey){
    if(tpm_content_decode_start(old_content, buffer_size) < 0){
        return LAST_ERROR;
    }
    if(tpm_content_encode_start(buffer_size, new_content, pkey) < 0){
        tpm_content_decode_cancel();
        return LAST_ERROR;
    }
    
    /* ready to perform steps */
    return 1;
}

int tpm_content_recode_step(large_file *lfp){
    char *decode_result;
    u_int32_t decode_resultlen;
    
    char *encode_result;
    u_int32_t encode_resultlen;

    if(tpm_content_decode_step((char *)lfp->buffer, lfp->buffer_size, &decode_result, &decode_resultlen) < 0){
        tpm_content_encode_cancel();
        return LAST_ERROR;
    }
    
    if(tpm_content_encode_step(decode_result, decode_resultlen, &encode_result, &encode_resultlen) < 0){
        tpm_content_decode_cancel();
        return LAST_ERROR;
    }
    
    /* check if the buffer is large enough */
    if(SIZE_READ_BUFFER < encode_resultlen){
        return quit(&E_SM_TPM_BUFFERSIZE_TOOSMALL);
    }
    
    /* copy the data to the result holder */
    if(memcpy(lfp->buffer, encode_result, encode_resultlen) == NULL){
        return quit(&E_SM_TPM_MEM_COPY);
    }
    lfp->buffer_size = encode_resultlen;
    
    /* step is completed */
    return 1;
}

int tpm_content_recode_stop(large_file *lfp){
    char *decode_result;
    u_int32_t decode_resultlen;
    
    char *encode_result;
    u_int32_t encode_resultlen;

    u_int32_t temp_len;
    
    /* first stop decoding and encode the remaining block */
    if(tpm_content_decode_stop(&decode_result, &decode_resultlen) < 0){
        tpm_content_encode_cancel();
        return LAST_ERROR;
    }
    if(tpm_content_encode_step(decode_result, decode_resultlen, &encode_result, &encode_resultlen) < 0){
        return LAST_ERROR;
    }

    /* copy the block to the result holder */
    if(memcpy(lfp->buffer, encode_result, encode_resultlen) == NULL){
        return quit(&E_SM_TPM_MEM_COPY);
    }

    /* now stop encoding */
    if(tpm_content_encode_stop(&encode_result, &temp_len) < 0){
        return LAST_ERROR;
    }

    /* check if the buffer is large enough */
    if(SIZE_READ_BUFFER < (encode_resultlen + temp_len)){
        return quit(&E_SM_TPM_BUFFERSIZE_COLISSION);
    }

    /* copy the remaining encode block of data */
    if(memcpy((((char *)(lfp->buffer)) + (int)encode_resultlen), encode_result, temp_len) == NULL){
        return quit(&E_SM_TPM_MEM_COPY);
    }
    lfp->buffer_size = encode_resultlen + temp_len;
    
    deallocate(encode_result);

    /* done */
    return 1;
}

int tpm_content_recode_cancel(){
    tpm_content_encode_cancel();
    tpm_content_decode_cancel();
    
    /* done */
    return 1;
}

/* writes size bytes of random data to target */
PUBLIC int tpm_randomize(char *target, uint16_t size){
    int status;

    /* put size pseudo-random bytes into buf */
    status = RAND_bytes(target, size);
    if(status != 1){
        return quit(&E_SM_TPM_RAND_BYTES);
    }

    /* return success */
    return 1;
}

/* copies the public key to buffer pkey */
PUBLIC int tpm_get_pkey(public_key *pkey){
    if(memcpy(pkey, &tpm_pkey, sizeof(public_key)) == NULL){
        return quit(&E_SM_TPM_MEM_COPY);
    }
    return 1;
}
