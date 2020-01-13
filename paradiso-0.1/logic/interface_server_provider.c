/* handle a provider-side incoming add content request */
PRIVATE int is_handle_add_request(int request_socket){
    int status;
    session sess;
    raw_content content;
    large_file lfp;
    secured_content scontent;

    /* start the security manager for internal usage only */
    status = sm_start_internal(&sess);

    /* initialize the stepwise security and connection manager */
    if(cm_start_reading_large_file(request_socket, &lfp) < 0){
        return is_generate_error(&E_IS_READ_RAW_CONTENT, request_socket);
    }
    if(sm_start_add_raw_content(&sess, &content, &scontent, &lfp) < 0){
        return is_generate_error(&E_IS_SM_ENCODE_CONTENT, request_socket);
    }

    /* loop until all data is processed */
    while(lfp.total_size > lfp.total_read){
        status = cm_read_partof_large_file(&lfp);
printf("is_handle_add_request> content read/write loop: %i/%i\n", lfp.total_read, lfp.total_size);
        if(status < 0){
            sm_stop_add_raw_content(&sess, &content, &lfp);
            return is_generate_error(&E_IS_READ_RAW_CONTENT, request_socket);
        }

        /* check the content at the security manager and save if correct */
        status = sm_add_partof_raw_content(&sess, &content, &scontent, &lfp);
        if(status < 0){
            return is_generate_error(&E_IS_SM_ENCODE_CONTENT, request_socket);
        }
    }
    
    /* read the content information from the socket */
    status = cm_read_raw_content(&content, request_socket);
    if(status < 0){
        return is_generate_error(&E_IS_READ_RAW_CONTENT, request_socket);
    }
    
    status = sm_finalize_add_raw_content(&sess, &content, &scontent, &lfp);
    if(status < 0){
        return is_generate_error(&E_IS_SM_ENCODE_CONTENT, request_socket);
    }
    
    return is_indicate_succes(request_socket);
}

PRIVATE int is_handle_revoke_request(int request_socket){
    int status;
    session sess;
    nuovo_server revoke_me;

    /* read needed information from the interface socket */
    status = cm_read_nuovo_server(&revoke_me, request_socket);
    if(status < 0){
        return is_generate_error(&E_IS_READ_REVOKE, request_socket);
    }

    /* start the security manager for internal usage only */
    status = sm_start_internal(&sess);

    /* forward the request to the security manager */
    status = sm_revoke_device(&sess, &(revoke_me.pkey));
    if(status < 0){
        return is_generate_error(&E_IS_REVOKE_DEVICE, request_socket);
    }

    /* that's it, return succesfully */
    return is_indicate_succes(request_socket);
}
