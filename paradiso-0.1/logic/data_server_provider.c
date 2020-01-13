
/* handle a provider-side incoming restore request
   note: this code looks a bit like the reseller get-request code */
PRIVATE int ds_handle_restore(int request_socket){
    int status;
    new_connection conn;
    session sess;
    mutualauth mutau;
    restored_payment respaym;
    secured_content content;
    large_file lfp;

    /* call the connection manager to read the new connection */
    status = cm_read_new_connection(&conn, request_socket);
    if(status < 0){
        return quit(&E_DS_READ_NEW_CONNECTION);
    }

    /* start a new security session */
    status = sm_start_session(&sess, &(conn.source));
    if(status < 0){
        return ds_generate_error(&sess, request_socket, &E_DS_NOT_TRUSTED);
    }

    /* get the mutualauth message */
    status = sm_get_mutualauth(&sess, &conn, &mutau);
    if(status < 0){
        return ds_generate_error(&sess, request_socket, &E_DS_GET_MUTUALAUTH);
    }

    /* write the mutualauth message */
    status = cm_write_mutualauth(&mutau, request_socket);
    if(status < 0){
        return quit(&E_DS_WRITE_MUTUALAUTH);
    }

    /* the customer replies with the restored payment */
    status = cm_read_restored_payment(&respaym, request_socket);
    if(status < 0){
        return quit(&E_DS_READ_PAYMENT);
    }

    /* check the restored payment and continue if accepted */
    status = sm_check_restored_payment(&sess, &respaym);
    if(status < 0){
        return ds_generate_error(&sess, request_socket, &E_DS_PAYMENT);
    }

    /* if the payment is accepted by the security manager
       then we can check at the bank if the payment can be
       accepted there also */

    /* check_bank */
    
	/* check if this message from the bank is oke --DOES NOTHING CURRENTLY-- */
	status = sm_validate_payment(&sess);
    if(status < 0){
        return ds_generate_error(&sess, request_socket, &E_DS_PAYMENT);
    }
    
    /* initialize the stepwise security and connection manager */
    if(sm_start_get_secured_content(&sess, &content, &lfp) < 0){
        return ds_generate_error(&sess, request_socket, &E_DS_START_GET_CONTENT);
    }
    if(cm_start_writing_large_file(request_socket, content.content_length, &lfp) < 0){
        return ds_generate_error(&sess, request_socket, &E_DS_START_WRITE_CONTENT);
    }
    
    /* loop until all data is processed */
    while(lfp.total_size > lfp.total_read){
        /* we get and send the content when it's oke */
        status = sm_get_partof_secured_content(&sess, &content, &lfp);
        if(status < 0){
            return ds_generate_error(&sess, request_socket, &E_DS_GET_CONTENT);
        }
    
        /* now we send the content to the customer */
        status = cm_write_partof_large_file(&lfp);
        if(status < 0){
            return quit(&E_DS_WRITE_CONTENT);
        }
    }
    
    /* finalize the last part of the content */
    status = sm_finalize_get_secured_content(&sess, &content, &lfp);
    if(status < 0){
        sm_stop_get_secured_content(&sess, &content, &lfp);
        return ds_generate_error(&sess, request_socket, &E_DS_GET_CONTENT);
    }
    status = cm_write_partof_large_file(&lfp);
    if(status < 0){
        return quit(&E_DS_WRITE_CONTENT);
    }
    
    /* restore request succeeded */
    return 1;
}

/* handle a provider-side incoming update (getDRL) request */
PRIVATE int ds_handle_update(int request_socket){
    int status;
    revocation_list drl;
    session sess;

    /* start a internal run of the security manager */
    status = sm_start_internal(&sess);

    /* get the drl from the security manager */
    status = sm_get_drl(&sess, &drl);
    if(status < 0){
        return ds_generate_error(&sess, request_socket, &E_DS_GET_DRL);
    }
printf("> write the DRL\n");
    /* sent the drl to the requester */
    status = cm_write_drl(&drl, request_socket);
    if(status < 0){
        return ds_generate_error(&sess, request_socket, &E_DS_WRITE_DRL);
    }

    /* free the DRL memory here */
    deallocate_pp(drl.revoked_keys, drl.len);
    
    /* sending of drl succeeded */
    return 1;
}
