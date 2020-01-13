/* this method checks if a restored payment message is good
   note: in the current implementation we do not change the rights
   of the clf at provider side which simplifies the restore protocol
   a lot */
int sm_check_restored_payment(session *sess, restored_payment *respaym){
    int status;
    u_int16_t index;
    public_key pkey;

    /* allowed state: incoming authenticated */
    if(sess->current_state != STATE_INCOMING_AUTHENTICATED){
        return quit(&E_SM_STATE_EXCEPTION);
    }
    
    /* check if the consumer nonce corresponds to the earlier received one */
    if(!sm_compare_nonces(respaym->nonce_c, sess->nonce_c_first)){
        return quit(&E_SM_CHECK_RESPAYM_NONCE_C);
    }

    /* check if our nonce corresponds with the send one */
    if(!sm_compare_nonces(respaym->nonce_p, sess->nonce_rp)){
        return quit(&E_SM_CHECK_RESPAYM_NONCE_P);
    }

    /* get our public key */
    status = tpm_get_pkey(&pkey);
    if(status < 0){
        return quit(&E_SM_MEM_COPY);
    }

    /* check that our public key corresponds */
    if(!sm_compare_public_keys(&(respaym->target), &pkey)){
        return quit(&E_SM_CHECK_RESPAYM_PKEY);
    }

    /* verify the signature */
    status = tpm_rsa_signature_check_raw((char *)respaym, (uint16_t)sizeof(restored_payment)-RSA_SHA1_SIGLEN, respaym->signature, sess->target.device_pkey);
    if(status < 0){
        return quit(&E_SM_CHECK_RESPAYM_SIGNATURE);
    }

    /* copy the original payment message to the session */
    if(memcpy(&(sess->paym), &(respaym->restore), sizeof(payment)) == NULL){
        return quit(&E_SM_MEM_COPY);
    }

    /* wait for the fileindex manipulation to be safe */
    if(enter(sem_fileindex) < 0){
        return quit(&E_DM_SEM_LOCK_EXCEPTION);
    }

    /* get a fileindex for the restored payment message */
    status = dm_count_incremental_files(SAVE_DIR_RESPAYM, &index);
    if(status < 0){
        leave(sem_fileindex);
        return quit(&E_SM_COUNT_INCREMENTAL_FILES);
    }

    /* save the restored payment message to disk */
    status = dm_write_incremental_file(SAVE_DIR_RESPAYM, index, sizeof(restored_payment), (char *)respaym);
    if(status < 0){
        leave(sem_fileindex);
        return quit(&E_SM_WRITE_RESPAYMENT);
    }

    /* we are ready with our fileindex manipulations */
    if(leave(sem_fileindex) < 0){
        return quit(&E_DM_SEM_LOCK_EXCEPTION);
    }

    /* change state */
    sess->current_state = STATE_RESTORED_PAYMENT;

    /* the payment is accepted, so return */
    return 1;
}

/* this method validates a payment received from the bank */
int sm_validate_payment(session *sess){
    /* allowed state: restored payment */
    if(sess->current_state != STATE_RESTORED_PAYMENT){
        return quit(&E_SM_STATE_EXCEPTION);
    }

    /* ! NOT IMPLEMENTED ! */

    /* change state */
    sess->current_state = STATE_PAYMENT_ACCEPTED;

    /* the payment is accepted, so return */
    return 1;
}

/* this method reads the DRL from disk and returns it */
int sm_get_drl(session *sess, revocation_list *drl){
    int status;

    /* allowed states: internal use only */
    if(sess->current_state != STATE_NEW_INTERNAL){
        return quit(&E_SM_STATE_EXCEPTION);
    }
    
    /* get the DRL from the data manager */
    status = dm_get_drl(drl);
    if(status < 0){
        return quit(&E_SM_GET_DRL);
    }

    /* check if we can trust this DRL */
    status = sm_check_drl(drl);
    if(status < 0){
        return quit(&E_SM_CHECK_DRL);
    }

    /* set the state to finished */
    sess->current_state = STATE_FINISHED;

    /* return succesfully */
    return 1;
}

/* this method adds a device to the revocation list */
int sm_revoke_device(session *sess, public_key *device){
    int status, cnt;
    char *sigbuf;
    revocation_list old_drl;
    revocation_list new_drl;

    /* allowed states: internal use only */
    if(sess->current_state != STATE_NEW_INTERNAL){
        return quit(&E_SM_STATE_EXCEPTION);
    }

    /* copy our public key from the tpm to the new drl */
    status = tpm_get_pkey(&(new_drl.provider));
    if(status < 0){
        return quit(&E_SM_MEM_COPY);
    }

    /* get the old DRL from the data manager */
    status = dm_get_drl(&old_drl);
    if(status < 0){
        return quit(&E_SM_GET_DRL);
    }

    /* check if we can trust the old DRL */
    status = sm_check_drl(&old_drl);
    if(status < 0){
        /* in case the current DRL is broken, reset it */
        new_drl.len = 1;

        /* allocate memory for the key pointer */
        new_drl.revoked_keys = (char **)allocate(new_drl.len);
        if(new_drl.revoked_keys == NULL){
            deallocate_pp(old_drl.revoked_keys, old_drl.len);
            return LAST_ERROR;
        }
    } else {
        /* in case the current DRL is oke, add the device */
        new_drl.len = old_drl.len + 1;

        /* allocate memory for the pointers */
        new_drl.revoked_keys = (char **)allocate(new_drl.len);
        if(new_drl.revoked_keys == NULL){
            deallocate_pp(old_drl.revoked_keys, old_drl.len);
            return LAST_ERROR;
        }

        /* interate over all old keys */
        for(cnt = 0; cnt < old_drl.len; cnt++){
            /* copy the memory pointer */
            new_drl.revoked_keys[cnt] = old_drl.revoked_keys[cnt];
        }
    }

    /* allocate memory for the new key */
    new_drl.revoked_keys[new_drl.len - 1] = allocate(RSA_PKEY_RAW_LENGTH);
    if(new_drl.revoked_keys[new_drl.len - 1] == NULL){
        deallocate_pp(old_drl.revoked_keys, old_drl.len);
        deallocate((char *)new_drl.revoked_keys);
        return LAST_ERROR;
    }
    
    /* copy the new key */
    if(memcpy(new_drl.revoked_keys[new_drl.len - 1], device->device_pkey, RSA_PKEY_RAW_LENGTH) == NULL){
        deallocate_pp(old_drl.revoked_keys, old_drl.len);
        deallocate(new_drl.revoked_keys[new_drl.len - 1]);
        deallocate((char *)new_drl.revoked_keys);
        return quit(&E_SM_MEM_COPY);
    }

    /* create a sequential version of the drl */
    sm_get_sequential_drl(&new_drl, &sigbuf);
    if(LAST_ERROR < 0){
        deallocate_pp(old_drl.revoked_keys, old_drl.len);
        deallocate(new_drl.revoked_keys[new_drl.len - 1]);
        deallocate((char *)new_drl.revoked_keys);
        return LAST_ERROR;
    }

    /* sign the drl */
    status = tpm_rsa_signature_create(sigbuf, (new_drl.len * RSA_PKEY_RAW_LENGTH), new_drl.signature);
    if(status < 0){
        deallocate_pp(old_drl.revoked_keys, old_drl.len);
        deallocate(new_drl.revoked_keys[new_drl.len - 1]);
        deallocate((char *)new_drl.revoked_keys);
        deallocate(sigbuf);
        return quit(&E_SM_SIGN_DRL);
    }
    
    /* write the new drl to disk */
    status = dm_write_drl(&new_drl);
    if(status < 0){
        deallocate_pp(old_drl.revoked_keys, old_drl.len);
        deallocate(new_drl.revoked_keys[new_drl.len - 1]);
        deallocate((char *)new_drl.revoked_keys);
        deallocate(sigbuf);
        return quit(&E_SM_DM_UPDATE_DRL);
    }

    /* deallocate all memory */
    deallocate_pp(old_drl.revoked_keys, old_drl.len);
    deallocate(new_drl.revoked_keys[new_drl.len - 1]);
    deallocate((char *)new_drl.revoked_keys);
    deallocate(sigbuf);

    /* success */
    return 1;
}


/* this method adds some raw content to the system */
int sm_start_add_raw_content(session *sess, raw_content *content, secured_content *scontent, large_file *lfp){

    /* allowed states: internal use only */
    if(sess->current_state != STATE_NEW_INTERNAL){
        return quit(&E_SM_STATE_EXCEPTION);
    }

    /* set the tpm to start encoding */
    if(tpm_content_encode_start((uint32_t)SIZE_READ_BUFFER, scontent, NULL) < 0){
        return quit(&E_SM_TPM_CONTENT_ENCODE);
    }
    /* set the tpm to start hashing */
    if(tpm_sha_hash_start() < 0){
        tpm_content_encode_cancel();
        return quit(&E_SM_TPM_SHA_HASH);
    }
    
    /* save the data to a temporary file */
    if(dm_start_writing_large_file(SAVE_DIR_TEMP, TEMP_CONTENT_FILE, lfp) < 0){
        tpm_content_encode_cancel();
        tpm_sha_hash_cancel();
        return quit(&E_SM_WRITE_CONTENT);
    }
    
    /* set the size in the secured content to 0,
       we will increment it each time a part of the content is encoded
       so we eventually have the encrypted size stored here */
    scontent->content_length = 0;
    
    return 1;
}

int sm_stop_add_raw_content(session *sess, raw_content *content, large_file *lfp){
    
    /* allowed states: internal use only */
    if(sess->current_state != STATE_NEW_INTERNAL){
        return quit(&E_SM_STATE_EXCEPTION);
    }
    
    /* set the tpm to cancel the encoding and hashing */
    tpm_content_encode_cancel();
    tpm_sha_hash_cancel();
    
    /* close and remove the file at the data manager */
    dm_close_large_file(lfp);
    dm_remove_file(SAVE_DIR_TEMP, TEMP_CONTENT_FILE);
    
    /* set the state to finished */
    sess->current_state = STATE_FINISHED;
    
    return 1;
}

int sm_add_partof_raw_content(session *sess, raw_content *content, secured_content *scontent, large_file *lfp){
    char *result;
    uint32_t resultlen;
    
    /* allowed states: internal use only */
    if(sess->current_state != STATE_NEW_INTERNAL){
        return quit(&E_SM_STATE_EXCEPTION);
    }
    
    /* add data to hash */
    if(tpm_sha_hash_step(lfp->buffer, lfp->buffer_size) < 0){
        tpm_content_encode_cancel();
        dm_close_large_file(lfp);
        dm_remove_file(SAVE_DIR_TEMP, TEMP_CONTENT_FILE);
        return quit(&E_SM_TPM_SHA_HASH);
    }
    
    /* encode one step of data */
    if(tpm_content_encode_step(lfp->buffer, lfp->buffer_size, &result, &resultlen) < 0){
        dm_close_large_file(lfp);
        tpm_sha_hash_cancel();
        dm_remove_file(SAVE_DIR_TEMP, TEMP_CONTENT_FILE);
        return quit(&E_SM_TPM_CONTENT_ENCODE);
    }
    scontent->content_length += resultlen;
    
    /* write the data to the large file */
    if(dm_write_partof_large_file_data(result, resultlen, lfp) < 0){
        tpm_sha_hash_cancel();
        tpm_content_encode_cancel();
        dm_close_large_file(lfp);
        dm_remove_file(SAVE_DIR_TEMP, TEMP_CONTENT_FILE);
        return quit(&E_SM_WRITE_CONTENT);
    }
    
    /* done */
    return 1;
}

int sm_finalize_add_raw_content(session *sess, raw_content *content, secured_content *scontent, large_file *lfp){
    int status;
    char *result;
    u_int32_t resultlen;
    content_license clf;
    u_int16_t fileindex;

    /* allowed states: internal use only */
    if(sess->current_state != STATE_NEW_INTERNAL){
        return quit(&E_SM_STATE_EXCEPTION);
    }

    /* get the hash */
    if(tpm_sha_hash_stop(clf.info.hash) < 0){
        dm_close_large_file(lfp);
        dm_remove_file(SAVE_DIR_TEMP, TEMP_CONTENT_FILE);
        return quit(&E_SM_TPM_SHA_HASH);
    }

    /* perform the last encode step */
    if(tpm_content_encode_stop(&result, &resultlen) < 0){
        dm_close_large_file(lfp);
        dm_remove_file(SAVE_DIR_TEMP, TEMP_CONTENT_FILE);
        return quit(&E_SM_TPM_CONTENT_ENCODE);
    }
    scontent->content_length += resultlen;
    
    /* write the last data to the large file */
    if(dm_write_partof_large_file_data(result, resultlen, lfp) < 0){
        dm_close_large_file(lfp);
        dm_remove_file(SAVE_DIR_TEMP, TEMP_CONTENT_FILE);
        return quit(&E_SM_WRITE_CONTENT);
    }

    /* close the large file */
    dm_close_large_file(lfp);
    deallocate(result);

    /* check if we already own the new content */
    status = dm_search_incremental_file(SAVE_DIR_CLF, clf.info.hash, SHA_DIGEST_LENGTH, &fileindex);
    if(status == 1){
        return quit(&E_SM_CHECK_DUPLICATE_CONTENT);
    }

    /* copy the hash to the content info struct */
    if(memcpy((content->info).hash, clf.info.hash, SHA_DIGEST_LENGTH) == NULL){
        return quit(&E_SM_MEM_COPY);
    }

    /* generate the content license file */
    status = sm_generate_content_license_file(&(content->info), scontent->key, scontent->iv, scontent->content_length, &clf);
    if(status < 0){
        return LAST_ERROR;
    }

/* ! here we need to guarantee some atomicity with rollback functionality
   consult the paper for the details! */

    /* wait for the fileindex manipulation to be safe */
    if(enter(sem_fileindex) < 0){
        return quit(&E_DM_SEM_LOCK_EXCEPTION);
    }

    /* (1) first check if both content and clf directories are consistent and get file index */
    if(sm_check_clf_content_consistency(&fileindex) < 0){
        return LAST_ERROR;
    }
    clf.index = fileindex;

    /* (2) generate and store a hash of the license file */
    status = tpm_set_secure_hash_slot((char *)&clf, sizeof(content_license), clf.index);
    if(status < 0){
        return quit(&E_SM_WRITE_CONTENT);
    }

    /* (3) store the CLF to disk */
    status = dm_write_incremental_file(SAVE_DIR_CLF, clf.index, sizeof(content_license), (char *)&clf);
    if(status < 0){
        return quit(&E_SM_WRITE_CLF);
    }

    /* (4) save the content to disk (by moving the temporary file) */
    status = dm_move_to_incremental(SAVE_DIR_TEMP, TEMP_CONTENT_FILE, SAVE_DIR_CONTENT, clf.index);
    if(status < 0){
        /* remove the written clf to maintain consistency */
        dm_remove_incremental_file(SAVE_DIR_CLF, clf.index);
        return quit(&E_SM_WRITE_CONTENT);
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
