#include "security_manager.h"

/* A session must be written to disk just before the payment is
   returned to the customer.
   All inconsistent sessions (a sessions which is for example
   incomplete which can be caused by turning off the device when the
   session is being written to disk) on disk can therefore be deleted without
   problem because their payment can't be sent to the reseller. The
   session is deleted as soon the reseller sent us the content and
   we saved the content to disk without problems. */


/*
    secure storage 512kb
        licensing organization public key
        personal private key
    secure scratchpad
*/

/* semaphore so we can declare some parts of the content-write/update code parts critical */
int sem_fileindex;

/* we keep track of the payment list (write-through) */
/* ??? */

/* this method compares 2 content right structs */
PRIVATE int sm_compare_content_rights(rights *first_content_rights, rights *second_content_rights){
    return memcmp((const void *)first_content_rights, (const void *)second_content_rights, sizeof(rights)) == 0;
}

/* this method compares 2 public keys but ignores the self-chosen device name */
PRIVATE int sm_compare_public_keys(public_key *first_pkey, public_key *second_pkey){
    return memcmp((const void *)first_pkey + MAXLEN_DEVICENAME, (const void *)second_pkey + MAXLEN_DEVICENAME, sizeof(public_key) - MAXLEN_DEVICENAME) == 0;
}

/* this method compares 2 nonces */
PRIVATE int sm_compare_nonces(nonce *first_nonce, nonce *second_nonce){
    return memcmp((const void *)first_nonce, (const void *)second_nonce, NONCE_LENGTH) == 0;
}

/* this method searches a DRL for a specific raw RSA public key */
PRIVATE int sm_search_drl(revocation_list *drl, char *pkey){
    int cnt;

    for(cnt = 0; cnt < drl->len; cnt++){
        if(memcmp(pkey, drl->revoked_keys[cnt], RSA_PKEY_RAW_LENGTH) == 0){
            /* we found a match */
            return -1;
        }
    }

    /* no match was found */
    return 1;
}

/* this method checks all signatures in a public key */
PRIVATE int sm_check_public_key_signatures(public_key *pkey){
    int status;

    /* check if the signature from the manufacturer is oke */
    status = tpm_rsa_signature_check_raw(pkey->device_pkey, RSA_PKEY_RAW_LENGTH, pkey->signature, pkey->manufacturer_pkey);
    if(status < 0){
        return quit(&E_SM_CHECK_PKEY_DEVICE);
    }

    /* check if the signature from the license org. is oke */
    status = tpm_rsa_signature_check_licenseorg(pkey->manufacturer_pkey, RSA_PKEY_RAW_LENGTH, pkey->manufacturer_signature);
    if(status < 0){
        return quit(&E_SM_CHECK_PKEY_MANUFACTURER);
    }
    
    return 1;
}

/* this method returns a sequentially stored list of all revoked devices raw public keys */
PRIVATE int sm_get_sequential_drl(revocation_list *drl, char **result){
    int cnt;

    /* allocate memory to store the list sequentially
       note: yes this isn't a real neat approach but adding a list-signing
             method in the TPM makes the TPM to complex */
    *result = allocate(drl->len * RSA_PKEY_RAW_LENGTH);
    if(*result == NULL){
        return LAST_ERROR;
    }

    /* copy each entry from the list into it */
    for(cnt = 0; cnt < drl->len; cnt++){
        if(memcpy(*result + (cnt * RSA_PKEY_RAW_LENGTH), drl->revoked_keys[cnt], RSA_PKEY_RAW_LENGTH) == NULL){
            deallocate(*result);
            return quit(&E_SM_MEM_COPY);
        }
    }

    /* success */
    return 1;
}

/* this method checks if the provided DRL can be trusted */
PRIVATE int sm_check_drl(revocation_list *drl){
    char *sigbuf;
    int status;
    
    /* return true if the DRL is empty
       note: this isn't really secure... but the DRL support is still
       experimental so this should be removed later on! */
    if(drl->len == 0){
        return 1;
    }

    /* first check if the provided public key can be trusted */
    status = sm_check_public_key_signatures(&(drl->provider));
    if(status < 0){
        return status;
    }

    /* now create a sequential version of the drl */
    if(sm_get_sequential_drl(drl, &sigbuf) < 0){
        return LAST_ERROR;
    }

    /* check the signature */
    status = tpm_rsa_signature_check_raw(sigbuf, (drl->len * RSA_PKEY_RAW_LENGTH), drl->signature, (drl->provider).device_pkey);

    /* free the memory */
    deallocate(sigbuf);

    /* return the status */
    return status;
}

PRIVATE int sm_check_public_key(public_key *pkey){
    int status;
    revocation_list drl;

    /* check if the signatures are oke */
    status = sm_check_public_key_signatures(pkey);
    if(status < 0){
        return status;
    }

    /* get the DRL from the data manager */
    status = dm_get_drl(&drl);
    if(status < 0){
        return quit(&E_SM_GET_DRL);
    }
    
    /* check if we can trust this DRL, we need to do this becuase the DRL is saved on insecure storage */
    status = sm_check_drl(&drl);
    if(status < 0){
        return quit(&E_SM_CHECK_DRL);
    }

    /* check if the public key isn't listed on the DRL */
    status = sm_search_drl(&drl, pkey->device_pkey);
    if(status < 0){
        return quit(&E_SM_REVOKED_DEVICE);
    }

/* free the revocation list */

    /* public key accepted */
    return 1;
}

/* this method creates a content license file */
PRIVATE int sm_generate_content_license_file(content_info *info, char *aes_key, char *iv, u_int32_t encrypted_size, content_license *clf){
    /* copy the content info to it */
    if(memcpy(&(clf->info), info, sizeof(content_info)) == NULL){
        return quit(&E_SM_MEM_COPY);
    }

    /* copy the RSA encrypted key to it */
    if(memcpy(clf->key, aes_key, RSA_ENCRYPTED_BLOCK_LENGTH) == NULL){
        return quit(&E_SM_MEM_COPY);
    }

    /* copy the initialization vector to it */
    if(memcpy(clf->iv, iv, AES_KEY_LENGTH) == NULL){
        return quit(&E_SM_MEM_COPY);
    }
    
    clf->encrypted_size = encrypted_size;

    /* ready */
    return 1;
}

/* this method checks if the clf and content directories are consistent.
   note: make sure this method is called within a critical region! */
PRIVATE int sm_check_clf_content_consistency(u_int16_t *clf_index){
    u_int16_t content_index;
    int status, diff;

    status = dm_count_incremental_files(SAVE_DIR_CLF, clf_index);
    if(status < 0){
        return quit(&E_SM_COUNT_INCREMENTAL_FILES);
    }
    status = dm_count_incremental_files(SAVE_DIR_CONTENT, &content_index);
    if(status < 0){
        return quit(&E_SM_COUNT_INCREMENTAL_FILES);
    }

    /* check for inconsistency */
    if(content_index != *clf_index){
        diff = (*clf_index) - content_index;
        if(diff == 1){
            /* there is one CLF more than there is content so we try to
               remove the last CLF
               note: clf_index-1 because we start counting at 0 */
            status = dm_remove_incremental_file(SAVE_DIR_CLF, (*clf_index) - 1);
            if(status < 0){
                return quit(&E_SM_FILE_INCONSISTENCY);
            }
            quit(&E_SM_FIXED_FILE_INCONSISTENCY);
            /* update the index */
            *clf_index -= 1;
        } else {
            return quit(&E_SM_FILE_INCONSISTENCY);
        }
    }

    /* success, no inconsistency */
    return 1;
}

/* this method checks if all the stored payment messages correspond with 
   the content license files. It is part of the atomicity sequence when
   to guarantee an local clf update is performed consistent
   note: make sure this method is called within a critical region! */
PRIVATE int sm_check_clf_payment_consistency(){
    u_int16_t clf_index, payment_index;
    int cnt, status;
    payment paym;
    content_license clf;
    
    status = dm_count_incremental_files(SAVE_DIR_PAYM, &payment_index);
    if(status < 0){
        return quit(&E_SM_COUNT_INCREMENTAL_FILES);
    }
    
    /* we iterate over all the payment messages and search for each
       corresponding clf. */
    for(cnt = 0; cnt < payment_index; cnt++){
        status = dm_read_incremental_file(SAVE_DIR_PAYM, cnt, sizeof(payment), (char *)&paym);
        if(status < 0){
            return quit(&E_SM_READ_PAYMENT);
        }
        status = dm_search_incremental_file(SAVE_DIR_CLF, paym.sha_hash, SHA_DIGEST_LENGTH, &clf_index);
        if(status > 0){ /* we continue if the CLF exists */
            status = dm_read_incremental_file(SAVE_DIR_CLF, clf_index, sizeof(content_license), (char *)&clf);
            if(status < 0){
                return quit(&E_SM_READ_CLF);
            }
            /* if the resell total is the same then we know for sure that there is something wrong */
            if(clf.info.content_rights.resell_total == paym.content_rights.resell_total){
                /* now we verify the hash in secured memory to see what happened */
                if(tpm_sha1_check((char *)&clf, sizeof(content_license), clf.index) < 0){
                    /* the hash does not match so check if updating the clf rights fixes this problem */
                    clf.info.content_rights.resell_count -= paym.content_rights.resell_count + 1;
                    clf.info.content_rights.resell_total += 1;
                    if(tpm_sha1_check((char *)&clf, sizeof(content_license), clf.index) < 0){
                        /* the hash is still inconsistent so someone must have tampered with his device */
                        return quit(&E_SM_FILE_INCONSISTENCY);
                    } else {
                        /* the hash is correct now, so save the changed CLF to disk */
                        status = dm_write_incremental_file(SAVE_DIR_CLF, clf.index, sizeof(content_license), (char *)&clf);
                        if(status < 0){
                            return quit(&E_SM_WRITE_CLF);
                        }
                    }
                } else {
                    /* the hash matches but the payment messages are inconsistent. So we need to
                       update both the CLF and the secured hash according to the payment message */
                    clf.info.content_rights.resell_count -= paym.content_rights.resell_count + 1;
                    clf.info.content_rights.resell_total += 1;
                    status = tpm_set_secure_hash_slot((char *)&clf, sizeof(content_license), clf.index);
                    if(status < 0){
                        return quit(&E_SM_RENEW_CLF_HASH);
                    }
                    status = dm_write_incremental_file(SAVE_DIR_CLF, clf.index, sizeof(content_license), (char *)&clf);
                    if(status < 0){
                        return quit(&E_SM_WRITE_CLF);
                    }
                }
            }
        }
    }
    
    /* consistency is checked and repaired if needed */
    return 1;
}

/* this method checks if all the restorable sessions stored to disk are
   in fact restorable, because if the content is already present on the device
   then the last step of the atomicity sequence could have failed
   note: make sure this method is called within a critical region! */
PRIVATE int sm_check_clf_session_consistency(){
    u_int16_t clf_index, session_index;
    int cnt, status;
    session sess;
    content_license clf;
    
    status = dm_count_incremental_files(SAVE_DIR_SESSIONS, &session_index);
    if(status < 0){
        return quit(&E_SM_COUNT_INCREMENTAL_FILES);
    }
    
    /* we iterate over all the sessions and search for each
       corresponding clf. */
    for(cnt = 0; cnt < session_index; cnt++){
        status = dm_read_incremental_file(SAVE_DIR_SESSIONS, cnt, sizeof(session), (char *)&sess);
        if(status < 0){
            return quit(&E_SM_READ_SESSION);
        }
        status = dm_search_incremental_file(SAVE_DIR_CLF, sess.paym.sha_hash, SHA_DIGEST_LENGTH, &clf_index);
        if(status > 0){ /* we continue if the CLF exists */
            status = dm_read_incremental_file(SAVE_DIR_CLF, clf_index, sizeof(content_license), (char *)&clf);
            if(status < 0){
                return quit(&E_SM_READ_CLF);
            }
            /* now we check if the CLF has a matching content key, in that case the session 
               is not restorable and should be removed */
            if(memcmp((const void *)sess.key, (const void *)clf.key, RSA_ENCRYPTED_BLOCK_LENGTH) == 0){
                status = dm_remove_incremental_file(SAVE_DIR_SESSIONS, session_index);
                if(status < 0){
                    return quit(&E_SM_FILE_INCONSISTENCY);
                }
                /* in this case we restart the for-loop, a file from the directory
                   we were iterating is removed */
                cnt = -1;
                session_index -= 1;
            }
        }
    }
    
    /* consistency is checked and repaired if needed */
    return 1;
}

/* initialize the security manager before the sub-processes are spawned */
int sm_init(char *device_name){
    u_int16_t clf_index;
    
    /* initialize the TPM */
    if(tpm_init(device_name) < 0){
        return LAST_ERROR;
    }
    
    /* initilialize the semaphore */
    if(init_semaphore(&sem_fileindex) < 0){
        return LAST_ERROR;
    }
    
    /* consistency checks make use of file indexes, so enter critical region */
    if(enter(sem_fileindex) < 0){
        return quit(&E_DM_SEM_LOCK_EXCEPTION);
    }
    
    /* check the clf/content consistency */
    if(sm_check_clf_content_consistency(&clf_index) < 0){
        return LAST_ERROR;
    }
    
    /* check the clf/payment consistency */
    if(sm_check_clf_payment_consistency() < 0){
        return LAST_ERROR;
    }
    
    /* check the clf/session consistency */
    if(sm_check_clf_session_consistency() < 0){
        return LAST_ERROR;
    }
    
    /* close the critical region */
    if(leave(sem_fileindex) < 0){
        return quit(&E_DM_SEM_LOCK_EXCEPTION);
    }
    
    /* return success */
    return 1;
}

int sm_cleanup(){
    tpm_cleanup();
    return 1;
}

/* shutdown the security manager */
int sm_close(){
    /* destroy the semaphore */
    if(destroy_semaphore(sem_fileindex) < 0){
        return LAST_ERROR;
    }
    
    /* return success */
    return 1;
}


/* start security manager session and check the public key */
int sm_start_session(session *sess, public_key *target){
    int status;

    status = sm_check_public_key(target);
    if(status < 0){
        return status;
    }

    /* copy target public key to the session */
    if(memcpy(&(sess->target), target, sizeof(public_key)) == NULL){
        return quit(&E_SM_MEM_COPY);
    }

    /* also copy the target pkey to the second target so we can use that one
       safely methods which are invoked during normal get requests and during
       restore requests when a second target is involved */
    if(memcpy(&(sess->second_target), target, sizeof(public_key)) == NULL){
        return quit(&E_SM_MEM_COPY);
    }

    /* initialize session state */
    sess->current_state = STATE_NEW_SESSION;

    /* succeeded */
    return 1;
}

/* this method is called for a new outgoing connection */
int sm_get_nonce(session *sess, new_connection *conn){
    int status;

    /* allowed states: new_session */
    if(sess->current_state != STATE_NEW_SESSION){
        return quit(&E_SM_STATE_EXCEPTION);
    }

    /* generate the new nonce */
    status = tpm_randomize(sess->nonce_c_first, NONCE_LENGTH);
    if(status < 0){
        return quit(&E_SM_CREATE_NONCE);
    }

    /* also store the nonce as second nonce in the session
       note: this simplifies the check_mutual_auth method a lot because
       he can always use the second nonce as the last sent nonce */
    if(memcpy(&(sess->nonce_c_second), &(sess->nonce_c_first), NONCE_LENGTH) == NULL){
        return quit(&E_SM_MEM_COPY);
    }

    /* copy the nonce to the new connection */
    if(memcpy(&(conn->nonce_c), &(sess->nonce_c_first), NONCE_LENGTH) == NULL){
        return quit(&E_SM_MEM_COPY);
    }

    /* get the (raw) public key from the tpm */
    tpm_get_pkey(&(conn->source));

    /* set the new state */
    sess->current_state = STATE_FIRST_NONCE;

    /* the new connection has been initialized now, so return */
    return 1;
}

/* this method is called to restore an old session at a second target */
int sm_get_second_nonce(session *sess, public_key *second_target, new_connection *conn){
    int status;

    /* allowed states: first_nonce, second_nonce, payment_sent */
    if((sess->current_state != STATE_FIRST_NONCE) && (sess->current_state != STATE_SECOND_NONCE) && (sess->current_state != STATE_PAYMENT_SENT)){
        return quit(&E_SM_STATE_EXCEPTION);
    }

    /* validate the second target */
    status = sm_check_public_key(second_target);
    if(status < 0){
        return status;
    }

    /* copy the second target to the session */
    if(memcpy(&(sess->second_target), second_target, sizeof(public_key)) == NULL){
        return quit(&E_SM_MEM_COPY);
    }

    /* generate the second nonce */
    status = tpm_randomize(sess->nonce_c_second, NONCE_LENGTH);
    if(status < 0){
        return quit(&E_SM_CREATE_NONCE);
    }

    /* copy the nonce to the new connection */
    if(memcpy(&(conn->nonce_c), &(sess->nonce_c_second), NONCE_LENGTH) == NULL){
        return quit(&E_SM_MEM_COPY);
    }

    /* copy the (raw) public key from the tpm to the new connection */
    status = tpm_get_pkey(&(conn->source));
    if(status < 0){
        return quit(&E_SM_MEM_COPY);
    }

    /* set the new state */
    sess->current_state = STATE_SECOND_NONCE;

    /* the connection has been initialized now, so return */
    return 1;
}

/* this method verifies a new connection and replies the mutual authentication message */
int sm_get_mutualauth(session *sess, new_connection *conn, mutualauth *mutau){
    int status;

    /* allowed states: new session */
    if(sess->current_state != STATE_NEW_SESSION){
        return quit(&E_SM_STATE_EXCEPTION);
    }
    
    /* check if the connection corresponds with the started session */
    if(!sm_compare_public_keys(&(sess->target), &(conn->source))){
        return quit(&E_SM_CHECK_CONN_PKEY);
    }

    /* generate our nonce and store it in the session */
    status = tpm_randomize(sess->nonce_rp, NONCE_LENGTH);
    if(status < 0){
        return quit(&E_SM_CREATE_NONCE);
    }

    /* copy the new nonce to the mutaul authentication */
    if(memcpy(&(mutau->nonce_r), &(sess->nonce_rp), NONCE_LENGTH) == NULL){
        return quit(&E_SM_MEM_COPY);
    }

    /* copy the received nonce to our session */
    if(memcpy(&(sess->nonce_c_first), &(conn->nonce_c), NONCE_LENGTH) == NULL){
        return quit(&E_SM_MEM_COPY);
    }

    /* copy the received nonce to the mutual authentication */
    if(memcpy(&(mutau->nonce_c), &(sess->nonce_c_first), NONCE_LENGTH) == NULL){
        return quit(&E_SM_MEM_COPY);
    }

    /* copy target public key to the mutual authentication */
    if(memcpy(&(mutau->target), &(sess->target), sizeof(public_key)) == NULL){
        return quit(&E_SM_MEM_COPY);
    }
    
    /* sign the mutual authentication
       note: we subtract the size of the signature to avoid overlap */
    status = tpm_rsa_signature_create((char *)mutau, (uint16_t)sizeof(mutualauth)-RSA_SHA1_SIGLEN, mutau->signature);
    if(status < 0){
        return quit(&E_SM_SIGN_MUTAU);
    }

    /* set the new state */
    sess->current_state = STATE_INCOMING_AUTHENTICATED;

    /* the mutual authentication is ready, so return */
    return 1;
}

/* this method checks an incoming mutual authentication message */
int sm_check_mutualauth(session *sess, mutualauth *check){
    int status;
    public_key pkey;

    /* allowed states: first nonce, second nonce */
    if((sess->current_state != STATE_FIRST_NONCE) && (sess->current_state != STATE_SECOND_NONCE) ){
        return quit(&E_SM_STATE_EXCEPTION);
    }

    /* check if the received and sent nonces are the same
       note: the second nonce is always the last sent one, see also: sm_get_nonce */
    if(!sm_compare_nonces(check->nonce_c, sess->nonce_c_second)){
        return quit(&E_SM_CHECK_MUTAU_NONCES);
    }

    /* get our public key */
    status = tpm_get_pkey(&pkey);
    if(status < 0){
        return quit(&E_SM_MEM_COPY);
    }

    /* validate if the replied public key is ours */
    if(!sm_compare_public_keys(&(check->target), &pkey)){
        return quit(&E_SM_CHECK_MUTAU_PKEY);
    }

    /* check the signature */
    status = tpm_rsa_signature_check_raw((char *)check, (uint16_t)sizeof(mutualauth)-RSA_SHA1_SIGLEN, check->signature, sess->second_target.device_pkey);
    if(status < 0){
        return quit(&E_SM_CHECK_MUTAU_SIGNATURE);
    }

    /* save the received nonce */
    if(memcpy(sess->nonce_rp, check->nonce_r, NONCE_LENGTH) == NULL){
        return quit(&E_SM_MEM_COPY);
    }
    
    /* set the correct state */
    sess->current_state = (sess->current_state == STATE_FIRST_NONCE) ? STATE_OUTGOING_AUTHENTICATED : STATE_RESTORED_AUTHENTICATED;

    /* mutual authentication was accepted */
    return 1;
}

/* this method creates a payment message */
int sm_get_payment(session *sess, content_info *get_content, payment *paym){
    int status;

    /* allowed state: outgoing authenticated */
    if(sess->current_state != STATE_OUTGOING_AUTHENTICATED){
        return quit(&E_SM_STATE_EXCEPTION);
    }

    /* copy our nonce to the payment message */
    if(memcpy(&(paym->nonce_c), &(sess->nonce_c_first), NONCE_LENGTH) == NULL){
        return quit(&E_SM_MEM_COPY);
    }

    /* copy the received nonce to the payment message */
    if(memcpy(&(paym->nonce_r), &(sess->nonce_rp), NONCE_LENGTH) == NULL){
        return quit(&E_SM_MEM_COPY);
    }

    /* copy the content sha1 hash to the payment message */
    if(memcpy(&(paym->sha_hash), get_content->hash, SHA_DIGEST_LENGTH) == NULL){
        return quit(&E_SM_MEM_COPY);
    }

    /* copy the rights to the payment message */
    if(memcpy(&(paym->content_rights), &(get_content->content_rights), sizeof(rights)) == NULL){
        return quit(&E_SM_MEM_COPY);
    }

    /* copy the public key of the reseller to the payment message */
    if(memcpy(&(paym->target), &(sess->target), sizeof(public_key)) == NULL){
        return quit(&E_SM_MEM_COPY);
    }

    /* create a signature with our private key */
    status = tpm_rsa_signature_create((char *)paym, sizeof(payment)-RSA_SHA1_SIGLEN, paym->signature);
    if(status < 0){
        return quit(&E_SM_SIGN_PAYM);
    }

    /* save the payment message to our session */
    if(memcpy(&(sess->paym), paym, sizeof(payment)) == NULL){
        return quit(&E_SM_MEM_COPY);
    }

    /* wait for the fileindex manipulation to be safe */
    if(enter(sem_fileindex) < 0){
        return quit(&E_DM_SEM_LOCK_EXCEPTION);
    }

    /* save the content info in the session (possibly needed during restore) */
    if(memcpy(&(sess->info), get_content, sizeof(content_info)) == NULL){
        return quit(&E_SM_MEM_COPY);
    }

    /* change state before we save the session to disk */
    sess->current_state = STATE_PAYMENT_SENT;

    /* get an index so we can save the session to disk */
    status = dm_count_incremental_files(SAVE_DIR_SESSIONS, &(sess->index));
    if(status < 0){
        sess->current_state = STATE_OUTGOING_AUTHENTICATED;
        leave(sem_fileindex);
        return quit(&E_SM_COUNT_INCREMENTAL_FILES);
    }

    /* store the session */
    status = dm_write_incremental_file(SAVE_DIR_SESSIONS, sess->index, sizeof(session), (char *)sess);
    if(status < 0){
        sess->current_state = STATE_OUTGOING_AUTHENTICATED;
        leave(sem_fileindex);
        return quit(&E_SM_WRITE_SESSION);
    }

    /* we are ready with our fileindex manipulations */
    if(leave(sem_fileindex) < 0){
        sess->current_state = STATE_OUTGOING_AUTHENTICATED;
        return quit(&E_DM_SEM_LOCK_EXCEPTION);
    }

    /* the payment is ready, so return */
    return 1;
}


int sm_get_restored_payment(session *sess, restored_payment *respaym){
    int status;

    /* allowed state: restored authenticated */
    if(sess->current_state != STATE_RESTORED_AUTHENTICATED){
        return quit(&E_SM_STATE_EXCEPTION);
    }

    /* copy our second nonce to the payment message */
    if(memcpy(&(respaym->nonce_c), &(sess->nonce_c_second), NONCE_LENGTH) == NULL){
        return quit(&E_SM_MEM_COPY);
    }

    /* copy the received nonce to the payment message */
    if(memcpy(&(respaym->nonce_p), &(sess->nonce_rp), NONCE_LENGTH) == NULL){
        return quit(&E_SM_MEM_COPY);
    }

    /* load the old payment from session */
    if(memcpy(&(respaym->restore), &(sess->paym), sizeof(payment)) == NULL){
        return quit(&E_SM_MEM_COPY);
    }

    /* copy the public key of the provider to the payment message */
    if(memcpy(&(respaym->target), &(sess->second_target), sizeof(public_key)) == NULL){
        return quit(&E_SM_MEM_COPY);
    }

    /* create a signature with our private key */
    status = tpm_rsa_signature_create((char *)respaym, sizeof(restored_payment)-RSA_SHA1_SIGLEN, respaym->signature);
    if(status < 0){
        return quit(&E_SM_SIGN_RESPAYM);
    }

    /* change state */
    sess->current_state = STATE_PAYMENT_SENT;

    /* the payment is ready, so return */
    return 1;
}

int sm_check_payment(session *sess, payment *check){
    int status;
    u_int16_t index;
    public_key pkey;
    content_license clf;

    /* allowed state: incoming authenticated */
    if(sess->current_state != STATE_INCOMING_AUTHENTICATED){
        return quit(&E_SM_STATE_EXCEPTION);
    }

    /* check if the consumer nonce corresponds to the earlier received one */
    if(!sm_compare_nonces(check->nonce_c, sess->nonce_c_first)){
        return quit(&E_SM_CHECK_PAYM_NONCE_C);
    }

    /* check if our nonce corresponds with the send one */
    if(!sm_compare_nonces(check->nonce_r, sess->nonce_rp)){
        return quit(&E_SM_CHECK_PAYM_NONCE_P);
    }

    /* get our public key */
    status = tpm_get_pkey(&pkey);
    if(status < 0){
        return quit(&E_SM_MEM_COPY);
    }

    /* check that our public key corresponds */
    if(!sm_compare_public_keys(&(check->target), &pkey)){
        return quit(&E_SM_CHECK_PAYM_PKEY);
    }

    /* verify the signature */
    status = tpm_rsa_signature_check_raw((char *)check, (uint16_t)sizeof(payment)-RSA_SHA1_SIGLEN, check->signature, sess->target.device_pkey);
    if(status < 0){
        return quit(&E_SM_CHECK_PAYM_SIGNATURE);
    }

    /* search for the corresponding CLF */
    status = dm_search_incremental_file(SAVE_DIR_CLF, check->sha_hash, SHA_DIGEST_LENGTH, &index);
    if(status < 0){
        return quit(&E_SM_NO_CORRESPONDING_CLF);
    }

    /* read the content license file */
    if(dm_read_incremental_file(SAVE_DIR_CLF, index, sizeof(content_license), (char *)&clf) < 0){
        return quit(&E_SM_READ_CLF);
    }
    
    /* verify that the CLF can be trusted */
    if(tpm_sha1_check((char *)&clf, sizeof(content_license), clf.index) < 0){
        return quit(&E_SM_CLF_UNTRUSTED);
    }

    /* check if the rights can be accepted */
    if(clf.info.content_rights.resell_count < 1){
        /* the maximum number of resells has been reached */
        return quit(&E_SM_RIGHTS_RESELLCOUNT);
    }
    if(clf.info.content_rights.resell_depth < 1){
        /* reselling is not allowed beyond this depth */
        return quit(&E_SM_RIGHTS_RESELLDEPTH);
    }
    if(clf.info.content_rights.resell_total != check->content_rights.resell_total){
        /* the resell total indicates the number of times the content has been sold,
           independant of the resell count */
        return quit(&E_SM_RIGHTS_RESELLTOTAL);
    }
    if(clf.info.content_rights.price > check->content_rights.price){
        /* we will not sell the content for less then we paid for ourselves */
        return quit(&E_SM_RIGHTS_PRICE);
    }
    if( (clf.info.content_rights.resell_depth - 1) != check->content_rights.resell_depth ){
        /* (1) the customer may only request a resell_depth - 1 */
        return quit(&E_SM_RIGHTS_RESELLDEPTH_EXCEEDED);
    }
    if( (clf.info.content_rights.resell_count - check->content_rights.resell_count) < 0 ){
        /* we don't have enough resell-rights left to sell the content this many times */
        return quit(&E_SM_RIGHTS_RESELLCOUNT_EXCEEDED);
    }
    if( check->content_rights.resell_depth < 1 && check->content_rights.resell_count > 0 ){
        /* if the customer cannot resell then there is no need to buy resell-counts */
        return quit(&E_SM_RIGHTS_RESELLCOUNT_USELESS);
    }

    /* write the rights to our session */
    if(memcpy(&(sess->paym), check, sizeof(payment)) == NULL){
        return quit(&E_SM_MEM_COPY);
    }
    
/* ! here we need to guarantee some atomicity with rollback functionality
   consult the paper for the details! */

    /* wait for the fileindex manipulation to be safe */
    if(enter(sem_fileindex) < 0){
        return quit(&E_DM_SEM_LOCK_EXCEPTION);
    }

    /* (1) set the index to store the payment message
       note: we cannot use the clf index because one single content can
       be sold multiple times */
    status = dm_count_incremental_files(SAVE_DIR_PAYM, &index);
    if(status < 0){
        leave(sem_fileindex);
        return quit(&E_SM_COUNT_INCREMENTAL_FILES);
    }

    /* (1) store the payment message */
    status = dm_write_incremental_file(SAVE_DIR_PAYM, index, sizeof(payment), (char *)check);
    if(status < 0){
        leave(sem_fileindex);
        return quit(&E_SM_WRITE_PAYMENT);
    }

    /* (2) update the rights in our clf
       note: +1 because buying the content costs 1 resell count */
    clf.info.content_rights.resell_count -= check->content_rights.resell_count + 1;
    clf.info.content_rights.resell_total += 1;

    /* (2) calculate and store new clf hash */
    status = tpm_set_secure_hash_slot((char *)&clf, sizeof(content_license), clf.index);
    if(status < 0){
        leave(sem_fileindex);
        return quit(&E_SM_RENEW_CLF_HASH);
    }
    
    /* (3) update the clf on disk */
    status = dm_write_incremental_file(SAVE_DIR_CLF, clf.index, sizeof(content_license), (char *)&clf);
    if(status < 0){
        leave(sem_fileindex);
        return quit(&E_SM_WRITE_CLF);
    }

    /* we are ready with our fileindex manipulations */
    if(leave(sem_fileindex) < 0){
        return quit(&E_DM_SEM_LOCK_EXCEPTION);
    }

    /* change state */
    sess->current_state = STATE_PAYMENT_ACCEPTED;

    /* the payment is accepted, so return */
    return 1;
}

int sm_get_payment_list(session *sess, payment_list *payml){
    if(sess->current_state != STATE_NEW_SESSION){
        return quit(&E_SM_STATE_EXCEPTION);
    }
/* not implemented */
return -1;
}

int sm_update_payment_list(session *sess, payment_list update){
    if(sess->current_state != STATE_NEW_SESSION){
        return quit(&E_SM_STATE_EXCEPTION);
    }
/* not implemented */
return -1;
}

/* this method verifies a new DRL and stores it if it is accepted */
int sm_update_drl(session *sess, revocation_list *update){
    int status;

    /* allowed states: new session */
    if(sess->current_state != STATE_NEW_SESSION){
        return quit(&E_SM_STATE_EXCEPTION);
    }

    /* check for empty DRL, which we do not accept */
    if(update->len == 0){
        return quit(&E_SM_EMPTY_DRL);
    }
    
    /* verify that the DRL can be trusted */
    status = sm_check_drl(update);
    if(status < 0){
        return quit(&E_SM_CHECK_DRL);
    }


/* ! some kind of version-check should be added here ! */


    /* the DRL is accepted so let the data manager write the DRL to disk */
    status = dm_write_drl(update);
    if(status < 0){
        return quit(&E_SM_DM_UPDATE_DRL);
    }

    /* set the state to finished */
    sess->current_state = STATE_FINISHED;
    
    /* return succesfully */
    return 1;
}

int sm_get_public_key(session *sess, public_key *pkey){
    /* allowed states: new session, internal session */
    if(sess->current_state != STATE_NEW_SESSION && sess->current_state != STATE_NEW_INTERNAL){
        return quit(&E_SM_STATE_EXCEPTION);
    }

    /* get the public key from the tpm */
    tpm_get_pkey(pkey);

    /* set the state to finished */
    sess->current_state = STATE_FINISHED;
    
    /* return succesfully */
    return 1;
}

PRIVATE int sm_get_old_secured_content(char *sha_hash, u_int16_t *file_index, secured_content *content){
    int status;
    content_license clf;

    /* search for the corresponding CLF */
    status = dm_search_incremental_file(SAVE_DIR_CLF, sha_hash, SHA_DIGEST_LENGTH, file_index);
    if(status < 0){
        return quit(&E_SM_NO_CORRESPONDING_CLF);
    }

    /* read the content license file */
    if(dm_read_incremental_file(SAVE_DIR_CLF, *file_index, sizeof(clf), (char *)(&clf)) < 0){
        return quit(&E_SM_READ_CLF);
    }

    /* set the size of the old content read from CLF */
    content->content_length = clf.encrypted_size;
    
    /* reserve memory to store the encrypted content from disk to */
/*    content->encrypted_content = allocate(content->content_length);
    if(content->encrypted_content == NULL){
        return LAST_ERROR;
    }*/
    
    /* read the old content from disk */
/*    if(dm_read_incremental_file(SAVE_DIR_CONTENT, *file_index, content->content_length, content->encrypted_content) < 0){
        deallocate(content->encrypted_content);
        return quit(&E_SM_READ_CONTENT);
    }*/

    /* copy the RSA encrypted key to the old content */
    if(memcpy(content->key, clf.key, RSA_ENCRYPTED_BLOCK_LENGTH) == NULL){
        return quit(&E_SM_MEM_COPY);
    }

    /* copy the initialization vector to the old content */
    if(memcpy(content->iv, clf.iv, AES_KEY_LENGTH) == NULL){
        return quit(&E_SM_MEM_COPY);
    }

    /* copy the content rights to the old content */
    if(memcpy(&content->content_rights, &clf.info.content_rights, sizeof(rights)) == NULL){
        return quit(&E_SM_MEM_COPY);
    }
    
    return 1;
}

int sm_start_get_secured_content(session *sess, secured_content *content, large_file *lfp){
    int status;
    u_int16_t file_index;
    secured_content old_content;
    
    /* allowed state: payment accepted */
    if(sess->current_state != STATE_PAYMENT_ACCEPTED){
        return quit(&E_SM_STATE_EXCEPTION);
    }

    /* get the old secured content from disk */
    status = sm_get_old_secured_content((sess->paym).sha_hash, &file_index, &old_content);
    if(status < 0){
        return LAST_ERROR;
    }
    
    /* copy the rights agreed upon during payment */
    if(memcpy(&(content->content_rights), &((sess->paym).content_rights), sizeof(rights)) == NULL){
        return quit(&E_SM_MEM_COPY);
    }

    /* copy the received nonce to the content */
    if(memcpy(&(content->nonce_c), &(sess->nonce_c_first), NONCE_LENGTH) == NULL){
        return quit(&E_SM_MEM_COPY);
    }
    
    /* new size = old size */
    content->content_length = old_content.content_length;
    
    /* sign the secured content message */
    status = tpm_rsa_signature_create((char *)&(content->content_rights), sizeof(rights) + sizeof(nonce), content->signature);
    if(status < 0){
        return quit(&E_SM_SIGN_SECUREDCONTENT);
    }
    
    /* create a large file pointer for it */
    status = dm_start_reading_large_incremental_file(SAVE_DIR_CONTENT, file_index, old_content.content_length, lfp);
    if(status < 0){
        return quit(&E_SM_READ_CONTENT);
    }
    
    /* start the recode process at the tpm */
    status = tpm_content_recode_start(&old_content, content, SIZE_READ_BUFFER, sess->target.device_pkey);
    if(status < 0){
        return quit(&E_SM_RECODE_CONTENT);
    }
    
    return 1;
}

int sm_stop_get_secured_content(session *sess, secured_content *content, large_file *lfp){
    /* allowed state: payment accepted */
    if(sess->current_state != STATE_PAYMENT_ACCEPTED){
        return quit(&E_SM_STATE_EXCEPTION);
    }
    
    tpm_content_recode_cancel();
    dm_close_large_file(lfp);
        
    /* set the state to finished */
    sess->current_state = STATE_FINISHED;
    
    return 1;
}

int sm_get_partof_secured_content(session *sess, secured_content *content, large_file *lfp){
    int status;
    
    /* allowed state: payment accepted */
    if(sess->current_state != STATE_PAYMENT_ACCEPTED){
        return quit(&E_SM_STATE_EXCEPTION);
    }

    status = dm_read_partof_large_file(lfp);
    if(status < 0){
        tpm_content_recode_cancel();
        return quit(&E_SM_READ_CONTENT);
    }

    status = tpm_content_recode_step(lfp);
    if(status < 0){
        dm_close_large_file(lfp);
        return quit(&E_SM_RECODE_CONTENT);
    }
    
    return 1;
}

int sm_finalize_get_secured_content(session *sess, secured_content *content, large_file *lfp){
    int status;

    /* allowed state: payment accepted */
    if(sess->current_state != STATE_PAYMENT_ACCEPTED){
        return quit(&E_SM_STATE_EXCEPTION);
    }

    /* close the file */
    dm_close_large_file(lfp);

    /* finalize the tpm recode */
    status = tpm_content_recode_stop(lfp);
    if(status < 0){
        return quit(&E_SM_RECODE_CONTENT);
    }

    /* set the state to finished */
    sess->current_state = STATE_FINISHED;

    /* return success */
    return 1;
}

int sm_start_save_secured_content(session *sess, content_info *get_content, secured_content *scontent, large_file *lfp){
    /* allowed state: payment sent */
    if(sess->current_state != STATE_PAYMENT_SENT){
        return quit(&E_SM_STATE_EXCEPTION);
    }

    /* set the tpm to start decoding (in order to check and create a hash) */
    if(tpm_content_decode_start(scontent, SIZE_READ_BUFFER) < 0){
        return quit(&E_SM_TPM_CONTENT_ENCODE);
    }

    /* set the tpm to start hashing */
    if(tpm_sha_hash_start() < 0){
        tpm_content_decode_cancel();
        return quit(&E_SM_TPM_SHA_HASH);
    }

    /* save the --encrypted-- data to a temporary file */
    if(dm_start_writing_large_file(SAVE_DIR_TEMP, TEMP_CONTENT_FILE, lfp) < 0){
        tpm_content_decode_cancel();
        tpm_sha_hash_cancel();
        return quit(&E_SM_WRITE_CONTENT);
    }
    
    return 1;
}

int sm_stop_save_secured_content(session *sess, content_info *get_content, secured_content *content, large_file *lfp){
    /* allowed state: payment sent */
    if(sess->current_state != STATE_PAYMENT_SENT){
        return quit(&E_SM_STATE_EXCEPTION);
    }
    
    /* set the tpm to cancel the decoding */
    tpm_content_decode_cancel();
    tpm_sha_hash_cancel();
    
    /* close and remove the file at the data manager */
    dm_close_large_file(lfp);
    dm_remove_file(SAVE_DIR_TEMP, TEMP_CONTENT_FILE);
    
    /* set the state to finished */
    sess->current_state = STATE_FINISHED;
    
    return 1;
}

int sm_save_partof_secured_content(session *sess, content_info *get_content, secured_content *content, large_file *lfp){
    char *result;
    int resultlen;
    
    /* allowed state: payment sent */
    if(sess->current_state != STATE_PAYMENT_SENT){
        return quit(&E_SM_STATE_EXCEPTION);
    }
    
    /* decode the given step of data */
    if(tpm_content_decode_step(lfp->buffer, lfp->buffer_size, &result, &resultlen) < 0){
        tpm_sha_hash_cancel();
        dm_close_large_file(lfp);
        dm_remove_file(SAVE_DIR_TEMP, TEMP_CONTENT_FILE);
        return quit(&E_SM_TPM_CONTENT_ENCODE);
    }

    /* add decoded data to hash */
    if(tpm_sha_hash_step(result, resultlen) < 0){
        tpm_content_decode_cancel();
        dm_close_large_file(lfp);
        dm_remove_file(SAVE_DIR_TEMP, TEMP_CONTENT_FILE);
        return quit(&E_SM_TPM_SHA_HASH);
    }

    /* write the --encrypted-- data to the large file */
    if(dm_write_partof_large_file(lfp) < 0){
        tpm_content_decode_cancel();
        tpm_sha_hash_cancel();
        dm_close_large_file(lfp);
        dm_remove_file(SAVE_DIR_TEMP, TEMP_CONTENT_FILE);
        return quit(&E_SM_WRITE_CONTENT);
    }
    
    /* done */
    return 1;
}

int sm_finalize_save_secured_content(session *sess, content_info *get_content, secured_content *content, large_file *lfp){
    int status;
    char *result;
    char sha_hash[SHA_DIGEST_LENGTH];
    u_int16_t fileindex;
    int resultlen;
    content_license clf;

    /* allowed state: payment sent */
    if(sess->current_state != STATE_PAYMENT_SENT){
        return quit(&E_SM_STATE_EXCEPTION);
    }

    /* perform the last decode step */
    if(tpm_content_decode_stop(&result, &resultlen) < 0){
        dm_close_large_file(lfp);
        dm_remove_file(SAVE_DIR_TEMP, TEMP_CONTENT_FILE);
        return quit(&E_SM_TPM_CONTENT_ENCODE);
    }
    
    /* add the last decrypted data to the hash */
    if(tpm_sha_hash_step(result, resultlen) < 0){
        dm_close_large_file(lfp);
        dm_remove_file(SAVE_DIR_TEMP, TEMP_CONTENT_FILE);
        return quit(&E_SM_TPM_SHA_HASH);
    }
    
    /* get the hash */
    if(tpm_sha_hash_stop(sha_hash) < 0){
        dm_close_large_file(lfp);
        dm_remove_file(SAVE_DIR_TEMP, TEMP_CONTENT_FILE);
        return quit(&E_SM_TPM_SHA_HASH);
    }
    
    /* close the large file */
    dm_close_large_file(lfp);

    /* check if the content rights correspond with the requested rights */
    if(!sm_compare_content_rights(&(content->content_rights), &((sess->paym).content_rights))){
        return quit(&E_SM_CHECK_SECUREDCONTENT_RIGHTS);
    }

    /* check if the received and sent nonces are the same */
    if(!sm_compare_nonces(content->nonce_c, sess->nonce_c_second)){
        return quit(&E_SM_CHECK_SECUREDCONTENT_NONCE);
    }

    /* check the signature */
    status = tpm_rsa_signature_check_raw((char *)&(content->content_rights), sizeof(rights) + sizeof(nonce), content->signature, sess->second_target.device_pkey);
    if(status < 0){
        return quit(&E_SM_CHECK_SECUREDCONTENT_SIGNATURE);
    }

    /* verify the content hash */
    if(memcmp((const void *)(sess->paym).sha_hash, (const void *)sha_hash, SHA_DIGEST_LENGTH) != 0){
        return quit(&E_SM_CHECK_CONTENT_KEY);
    }

    /* copy the rights to the content info so it can be used for the clf */
    if(memcpy(&(get_content->content_rights), &((sess->paym).content_rights), sizeof(rights)) == NULL){
        return quit(&E_SM_MEM_COPY);
    }
    
    /* also copy the hash */
    if(memcpy(get_content->hash, (sess->paym).sha_hash, SHA_DIGEST_LENGTH) == NULL){
        return quit(&E_SM_MEM_COPY);
    }

    /* generate a content license file */
    status = sm_generate_content_license_file(get_content, content->key, content->iv, content->content_length, &clf);
    if(status < 0){
        return LAST_ERROR;
    }

    /* save the content info in the session (possibly needed during restore) */
    if(memcpy(&(sess->info), get_content, sizeof(content_info)) == NULL){
        return quit(&E_SM_MEM_COPY);
    }

    /* store the RSA encrypted key in the session */
    if(memcpy(sess->key, content->key, AES_KEY_LENGTH) == NULL){
        return quit(&E_SM_MEM_COPY);
    }

/* ! here we need to guarantee some atomicity with rollback functionality
   consult the paper for the details! */


/* note: the atomicity becomes much much simpler when the key of the new content is
   sent along with the mutualauth message instead of one step later */

    /* wait for the fileindex manipulation to be safe */
    if(enter(sem_fileindex) < 0){
        return quit(&E_DM_SEM_LOCK_EXCEPTION);
    }

    /* (1) first check if both content and clf directories are consistent and get file index */
    if(sm_check_clf_content_consistency(&fileindex) < 0){
        leave(sem_fileindex);
        return LAST_ERROR;
    }
    clf.index = fileindex;

    /* (2) save the changed session to disk */
    status = dm_write_incremental_file(SAVE_DIR_SESSIONS, sess->index, sizeof(session), (char *)sess);
    if(status < 0){
        leave(sem_fileindex);
        return quit(&E_SM_UPDATE_SESSION);
    }

    /* (3) generate and store a hash of the license file */
    status = tpm_set_secure_hash_slot((char *)&clf, sizeof(content_license), clf.index);
    if(status < 0){
        leave(sem_fileindex);
        return quit(&E_SM_RENEW_CLF_HASH);
    }

    /* (4) store the CLF to disk */
    status = dm_write_incremental_file(SAVE_DIR_CLF, clf.index, sizeof(content_license), (char *)&clf);
    if(status < 0){
        leave(sem_fileindex);
        return quit(&E_SM_WRITE_CLF);
    }


/* fail only if we are not restoring and fail is turned on */
if(((sess->paym).target.device_name)[0] == 'F'){
if(sm_compare_nonces(sess->nonce_c_first, sess->nonce_c_second)){
    leave(sem_fileindex);
    printf("************\nsm_save_secured_content> FAKING FAILED COMMUNICATION\n************\n");
    return -1;
}
}

    /* (5) save the content to disk (by moving the temporary file) */
    status = dm_move_to_incremental(SAVE_DIR_TEMP, TEMP_CONTENT_FILE, SAVE_DIR_CONTENT, clf.index);
    if(status < 0){
        /* remove the written clf to maintain consistency */
        dm_remove_incremental_file(SAVE_DIR_CLF, clf.index);
        leave(sem_fileindex);
        return quit(&E_SM_WRITE_CONTENT);
    }

    /* (6) remove the session from disk */
    status = dm_remove_incremental_file(SAVE_DIR_SESSIONS, sess->index);
    if(status < 0){
        /* in this case, when we weren't able to remove the session stored on disk,
           we should also remove the content and clf etc. because if the session
           remains on disk the customer can restore the communication at the provider
           enabling it to obtain the content+rights twice by paying once */
        dm_remove_incremental_file(SAVE_DIR_CLF, clf.index);
        dm_remove_incremental_file(SAVE_DIR_CONTENT, clf.index);
        leave(sem_fileindex);
        return quit(&E_SM_REMOVE_SESSION);
    }

    /* we are ready with our fileindex manipulations */
    if(leave(sem_fileindex) < 0){
        return quit(&E_DM_SEM_LOCK_EXCEPTION);
    }

    /* set the state to finished */
    sess->current_state = STATE_FINISHED;
    
    /* return succesfully */
    return 1;
}

/* this method creates a protected error message so the
   receiver can tell from who it originated*/
int sm_get_protected_error(session *sess, protected_error *failed){
    int status;
    public_key pkey;

    /* this method can be called anytime, the state doesn't matter */

    /* note: there is no need to add any signature at this moment because it
       isn't possible to retry when the signature is incorrect */

//    if(sess != NULL){
        /* copy the reseller/provider nonce */
        /*if(memcpy(failed->nonce_rp, sess->nonce_rp, NONCE_LENGTH) == NULL){
            return quit(&E_SM_MEM_COPY);
        }*/

        /* copy the consumer nonce
           note: the second nonce is always the last sent nonce */
        /*if(memcpy(sess->nonce_c, check->nonce_c_second, NONCE_LENGTH) == NULL){
            return quit(&E_SM_MEM_COPY);
        }*/
//    }

    /* set the error message */
    failed->error_code = LAST_ERROR;

    /* get our public key */
    status = tpm_get_pkey(&pkey);
    if(status < 0){
        return quit(&E_SM_MEM_COPY);
    }

    /* copy our public key */
    if(memcpy(&(failed->source), &pkey, sizeof(public_key)) == NULL){
        return quit(&E_SM_MEM_COPY);
    }

    /* create the signature */
    /*status = tpm_rsa_signature_create((char *)failed, (uint16_t)sizeof(protected_error)-RSA_SHA1_SIGLEN, failed->signature);
    if(status < 0){
        return quit(&E_SM_SIGN_MUTAU);
    }*/
    
    /* protected error created with succes */
    return 1;
}

/* this method initializes a session for internal use only */
int sm_start_internal(session *sess){

    /* initialize session state */
    sess->current_state = STATE_NEW_INTERNAL;

    /* succeeded */
    return 1;
}

/* *** FOLLOWING METHODS SHOULD BE REMOVED IN THE FUTURE *** */

int sm_start_get_raw_content(session *sess, char *hash, raw_content *content, large_file *lfp){
    int status;
    secured_content scontent;
    uint16_t file_index;
    
    /* get information about the old content */
    status = sm_get_old_secured_content(hash, &file_index, &scontent);
    if(status < 0){
        return LAST_ERROR;
    }

    /* set to tpm to start decoding content */
    if(tpm_content_decode_start(&scontent, SIZE_READ_BUFFER) < 0){
        return quit(&E_SM_TPM_DECODE);
    }
    
    /* create a large file pointer for it */
    status = dm_start_reading_large_incremental_file(SAVE_DIR_CONTENT, file_index, scontent.content_length, lfp);
    if(status < 0){
        return quit(&E_SM_READ_CONTENT);
    }

    return 1;
}

int sm_stop_get_raw_content(session *sess, raw_content *content, large_file *lfp){

    tpm_content_decode_cancel();
    dm_close_large_file(lfp);
        
    return 1;
}

int sm_get_partof_raw_content(session *sess, raw_content *content, large_file *lfp){
    char *result;
    int resultlen;
    int status;
    
    /* read encrypted data from the file */
    status = dm_read_partof_large_file(lfp);
    if(status < 0){
        tpm_content_decode_cancel();
        return quit(&E_SM_READ_CONTENT);
    }
    
    /* decode this part of data */
    status = tpm_content_decode_step(lfp->buffer, lfp->buffer_size, &result, &resultlen);
    if(status < 0){
        return quit(&E_SM_TPM_DECODE);
    }
    
    /* check if the buffer is large enough */
    if(SIZE_READ_BUFFER < resultlen){
        return quit(&E_SM_BUFFER_TOOSMALL);
    }
    
    /* copy the decrypted data to the large file buffer */
    if(memcpy(lfp->buffer, result, resultlen) == NULL){
        quit(&E_SM_MEM_COPY);
    }
    lfp->buffer_size = resultlen;
    
    return 1;
}

int sm_finalize_get_raw_content(session *sess, raw_content *content, large_file *lfp){
    int status;
    
    char *decode_result;
    int decode_resultlen;
    
    /* close the file */
    dm_close_large_file(lfp);
    
    /* finalize the tpm content decode */
    status = tpm_content_decode_stop(&decode_result, &decode_resultlen);
    if(status < 0){
        return quit(&E_SM_TPM_DECODE);
    }

    if(memcpy(lfp->buffer, decode_result, decode_resultlen) == NULL){
        return quit(&E_SM_TPM_MEM_COPY);
    }
    lfp->buffer_size = decode_resultlen;

    return 1;   
}

/* include if needed the provider methods */
#ifdef _PROVIDER_
#include "security_manager_provider.c"
#endif
