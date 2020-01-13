#ifndef _SECURITY_MANAGER_H_
#define _SECURITY_MANAGER_H_ 1

#include "tpm.h"
#include "../generic/semaphores.h"


/*
    What algorithms do we use?

    Asymmetic algorithm   RSA Engine
    Symmetric algorithm   AES Engine, 256 bits (Rijndael)
    Hash algorithm        SHA-1 Engine
                        + HMAC for message authentication in TPM

    note: TPM does not support any symmetric algorithm

*/

/* we do not use the openssl EVP interface because
   now we only need to compile and load the
   engine's we really use */

DEFERROR(E_SM_CHECK_PKEY_DEVICE,        "Signed device public key is revoked.",                 -3000);
DEFERROR(E_SM_CHECK_PKEY_MANUFACTURER,  "Signed manufacturer public key is revoked.",           -3001);
DEFERROR(E_SM_MEM_COPY,                 "Memory copy in security manager failed.",              -3002);
DEFERROR(E_SM_GET_DRL,                  "Get DRL from data manager failed.",                    -3003);
DEFERROR(E_SM_CHECK_DRL,                "Security manager was fed with untrusted DRL.",         -3004);
DEFERROR(E_SM_REVOKED_DEVICE,           "Public key of device was listed on DRL.",              -3005);
DEFERROR(E_SM_COUNT_INCREMENTAL_FILES,  "Error occured while counting incremental files.",      -3006);
DEFERROR(E_SM_FILE_INCONSISTENCY,       "The Nuovo filemanagement got corrupted.",              -3007);
DEFERROR(E_SM_STATE_EXCEPTION,          "Invoked method is inconsistent with current state.",   -3008);
DEFERROR(E_SM_CREATE_NONCE,             "Could not create new random nonce.",                   -3009);
DEFERROR(E_SM_SIGN_MUTAU,               "Mutual authentication couldn't be signed.",            -3010);
DEFERROR(E_SM_CHECK_MUTAU_NONCES,       "Mutual authentication denied: inconsistent nonces.",   -3011);
DEFERROR(E_SM_CHECK_MUTAU_PKEY,         "Mutual authentication public key mismatch.",           -3012);
DEFERROR(E_SM_CHECK_MUTAU_SIGNATURE,    "Mutual authentication signature incorrect.",           -3013);
DEFERROR(E_SM_SIGN_PAYM,                "Payment message couldn't be signed.",                  -3014);
DEFERROR(E_DM_SEM_LOCK_EXCEPTION,       "Could not manipulate semaphore.",                      -3015);
DEFERROR(E_SM_WRITE_SESSION,            "Failed to write session to disk.",                     -3016);
DEFERROR(E_SM_CHECK_PAYM_NONCE_C,       "Customer nonce of payment message is wrong.",          -3017);
DEFERROR(E_SM_CHECK_PAYM_NONCE_P,       "Reseller/provider nonce of payment message is wrong.", -3018);
DEFERROR(E_SM_CHECK_PAYM_PKEY,          "Payment message public key mismatch.",                 -3019);
DEFERROR(E_SM_CHECK_PAYM_SIGNATURE,     "Payment message signature incorrect.",                 -3020);
DEFERROR(E_SM_NO_CORRESPONDING_CLF,     "Payment received for non-existent CLF or content.",    -3021);
DEFERROR(E_SM_READ_CLF,                 "Could not read CLF from disk.",                        -3022);
DEFERROR(E_SM_RIGHTS_RESELLCOUNT,       "Requested content resell count is depleted.",          -3023);
DEFERROR(E_SM_RIGHTS_RESELLDEPTH,       "Requested content resell depth is too low.",           -3024);
DEFERROR(E_SM_RIGHTS_RESELLTOTAL,       "Requested resell total should be the same.",           -3025);
DEFERROR(E_SM_RIGHTS_PRICE,             "Payment message price is too low.",                    -3026);
DEFERROR(E_SM_RIGHTS_RESELLDEPTH_EXCEEDED, "Requested content resell depth is wrong.",          -3027);
DEFERROR(E_SM_RIGHTS_RESELLCOUNT_EXCEEDED, "Requested resell count is too large.",              -3028);
DEFERROR(E_SM_RIGHTS_RESELLCOUNT_USELESS,  "Requested resell count should be 0 when depth is 0.", -3029);
DEFERROR(E_SM_WRITE_PAYMENT,            "Failed to write payment to disk.",                     -3030);
DEFERROR(E_SM_RENEW_CLF_HASH,           "Could not renew hash slot in TPM.",                    -3031);
DEFERROR(E_SM_WRITE_CLF,                "Could not write CLF to disk.",                         -3032);
DEFERROR(E_SM_DM_UPDATE_DRL,            "Could not update the DRL on disk.",                    -3033);
DEFERROR(E_SM_RECODE_CONTENT,           "TPM failed to recode the requested content.",          -3034);
DEFERROR(E_SM_SIGN_SECUREDCONTENT,      "Could not sign new secured content message.",          -3035);
DEFERROR(E_SM_SIGN_RESPAYM,             "Could not sign the restore payment message.",          -3036);
DEFERROR(E_SM_CHECK_SECUREDCONTENT_RIGHTS,    "Received content right differ from requested rights.", -3037);
DEFERROR(E_SM_CHECK_SECUREDCONTENT_NONCE,     "Received content nonce mismatch.",                     -3038);
DEFERROR(E_SM_CHECK_SECUREDCONTENT_SIGNATURE, "Received content signature is wrong.",                 -3039);
DEFERROR(E_SM_CHECK_CONTENT_KEY,        "Received content has broken encryption or key mismatch.",    -3040);
DEFERROR(E_SM_UPDATE_SESSION,           "Could not update the session on disk.",                 -3041);
DEFERROR(E_SM_WRITE_CONTENT,            "Could not write content to disk.",                      -3042);
DEFERROR(E_SM_REMOVE_SESSION,           "Could not remove old session from disk.",               -3043);
DEFERROR(E_SM_READ_CONTENT,             "Could not read content from disk.",                     -3044);
DEFERROR(E_SM_CHECK_RESPAYM_NONCE_C,    "Customer nonce of restore payment message is wrong.",   -3045);
DEFERROR(E_SM_CHECK_RESPAYM_NONCE_P,    "Reseller/provider nonce of restore payment message is wrong.", -3046);
DEFERROR(E_SM_CHECK_RESPAYM_PKEY,       "Restore payment message public key mismatch.",          -3047);
DEFERROR(E_SM_CHECK_RESPAYM_SIGNATURE,  "Restore payment message signature incorrect.",          -3048);
DEFERROR(E_SM_SIGN_DRL,                 "Could not sign changed DRL.",                           -3049);
DEFERROR(E_SM_TPM_CONTENT_ENCODE,       "TPM failed to encode content.",                         -3050);
DEFERROR(E_SM_FIXED_FILE_INCONSISTENCY, "Fixed an nuovo filesystem inconsistency.",              -3051);
DEFERROR(E_SM_UPDATE_INFOLIST,          "Could not update content info list on disk.",           -3052);
DEFERROR(E_SM_EMPTY_DRL,                "New DRL rejected because it was empty.",                -3053);
DEFERROR(E_SM_CHECK_CONN_PKEY,          "Connection public key does not correspond with session.", -3054);
DEFERROR(E_SM_WRITE_RESPAYMENT,         "Could not write restored payment message.",             -3055);
DEFERROR(E_SM_TPM_DECODE,               "TPM Failed to decode content.",                         -3056);
DEFERROR(E_SM_CLF_UNTRUSTED,            "Authenticity of corresponding CLF could not be verified", -3057);
DEFERROR(E_SM_READ_PAYMENT,             "Could not read payment from disk.",                      -3058);
DEFERROR(E_SM_READ_SESSION,             "Could not read session from disk.",                      -3059);
DEFERROR(E_SM_TPM_SHA_HASH,             "TPM failed to create a hash.",                           -3060);
DEFERROR(E_SM_BUFFER_TOOSMALL,          "Target buffer too small.",                               -3061);
DEFERROR(E_SM_CHECK_DUPLICATE_CONTENT,  "Content already present on this device.",                -3062);

/* declare datatypes */

/* using a enum type would have been better, but we cannot fix
    the byte length of it for sure, so making it harder to guarantee
    any inter-architecture compatibility */
#define STATE_NEW_SESSION               0
#define STATE_FIRST_NONCE               1
#define STATE_SECOND_NONCE              2
#define STATE_INCOMING_AUTHENTICATED    3
#define STATE_OUTGOING_AUTHENTICATED    4
#define STATE_RESTORED_PAYMENT          5
#define STATE_RESTORED_AUTHENTICATED    6
#define STATE_PAYMENT_SENT              7
#define STATE_PAYMENT_ACCEPTED          8
#define STATE_FINISHED                  9

#define STATE_NEW_INTERNAL              10

/* the security state session */
struct _session{
    u_int16_t index;                         /* fileindex location of the session if stored to disk */
    content_info info;                       /* detailed information about the content */
    public_key target;                       /* public key of the person connected to */
    public_key second_target;                /* public key of the second person for the restore protocol */
    state current_state;                     /* current state of the session */
    nonce nonce_c_first[NONCE_LENGTH];       /* first nonce chosen by customer */
    nonce nonce_c_second[NONCE_LENGTH];      /* second nonce chosen by customer */
    nonce nonce_rp[NONCE_LENGTH];            /* nonce chosen by reseller or provider */
    payment paym;                            /* payment message for this session */
    int8_t key[RSA_ENCRYPTED_BLOCK_LENGTH];  /* RSA encrypted key of content possibly stored to disk */
} __attribute__((__packed__));
typedef struct _session session;

/* the content license is stored on disk as file and secured by a hash stored in the secured memory */
struct _content_license{
    content_info info;                       /* information about the content including hash, original size and rights */
/*    char sha_hash[SHA_DIGEST_LENGTH];     */   /* SHA-1 hash of the content */
    int8_t key[RSA_ENCRYPTED_BLOCK_LENGTH];  /* AES key to read secured content encrypted with own public key */
    int8_t iv[AES_KEY_LENGTH];               /* initialization vector of the AES encryption */
/*    rights content_rights;               */    /* rights of the content */
    u_int16_t index;                         /* fileindex location for content and clf */
    u_int32_t encrypted_size;                /* the size of the encrypted content, probably a multiple of AES_KEY_LENGTH */
} __attribute__((__packed__));
typedef struct _content_license content_license;

/* declare public methods */
int sm_init(char *device_name);
int sm_cleanup();
int sm_close();

int sm_start_session(session *sess, public_key *target);
int sm_get_nonce(session *sess, new_connection *conn);
int sm_get_second_nonce(session *sess, public_key *second_target, new_connection *conn);

int sm_get_mutualauth(session *sess, new_connection *conn, mutualauth *mutau);
int sm_check_mutualauth(session *sess, mutualauth *check);

int sm_get_payment(session *sess, content_info *get_content, payment *paym);
int sm_check_payment(session *sess, payment *check);
int sm_get_restored_payment(session *sess, restored_payment *respaym);

int sm_start_get_secured_content(session *sess, secured_content *content, large_file *lfp);
int sm_stop_get_secured_content(session *sess, secured_content *content, large_file *lfp);
int sm_get_partof_secured_content(session *sess, secured_content *content, large_file *lfp);
int sm_finalize_get_secured_content(session *sess, secured_content *content, large_file *lfp);

int sm_start_save_secured_content(session *sess, content_info *get_content, secured_content *content, large_file *lfp);
int sm_stop_save_secured_content(session *sess, content_info *get_content, secured_content *content, large_file *lfp);
int sm_save_partof_secured_content(session *sess, content_info *get_content, secured_content *content, large_file *lfp);
int sm_finalize_save_secured_content(session *sess, content_info *get_content, secured_content *content, large_file *lfp);

int sm_get_payment_list(session *sess, payment_list *payml);
int sm_update_payment_list(session *sess, payment_list update);
int sm_update_drl(session *sess, revocation_list *update);
int sm_get_public_key(session *sess, public_key *pkey);

int sm_get_protected_error(session *sess, protected_error *failed);

int sm_start_internal(session *sess);

int sm_start_get_raw_content(session *sess, char *hash, raw_content *content, large_file *lfp);
int sm_stop_get_raw_content(session *sess, raw_content *content, large_file *lfp);
int sm_get_partof_raw_content(session *sess, raw_content *content, large_file *lfp);
int sm_finalize_get_raw_content(session *sess, raw_content *content, large_file *lfp);

#ifdef _PROVIDER_

int sm_check_restored_payment(session *sess, restored_payment *respaym);
int sm_validate_payment(session *sess);

int sm_get_drl(session *sess, revocation_list *drl);
int sm_revoke_device(session *sess, public_key *revoke);

int sm_start_add_raw_content(session *sess, raw_content *content, secured_content *scontent, large_file *lfp);
int sm_stop_add_raw_content(session *sess, raw_content *content, large_file *lfp);
int sm_add_partof_raw_content(session *sess, raw_content *content, secured_content *scontent, large_file *lfp);
int sm_finalize_add_raw_content(session *sess, raw_content *content, secured_content *scontent, large_file *lfp);
    
#endif


#endif /* _SECURITY_MANAGER_H_ */
