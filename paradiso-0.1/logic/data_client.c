#include "data_client.h"

/* the data client implements the client side of the extended nuovo protocol */

/* generate an error message */
PRIVATE int dc_generate_error(session *sess, int socket, error_package *error){
    int status;
    protected_error failed;

    /* get error message and check for failure */
    status = sm_get_protected_error(sess, &failed);
    if(status < 0){
        return status;
    }

    /* send the error message */
    cm_write_protected_error(&failed, socket);
    
    /* close the socket */
    close(socket);

    /* quit the program */
    return quit(error);
}

/* initiate a complete outgoing get request */
PUBLIC int dc_handle_get(content_info *get_content, nuovo_server *target){
    int status, socket;
    new_connection conn;
    session sess;
    mutualauth mutau;
    payment paym;
    secured_content content;
    large_file lfp;

    /* start a security manager session */
    status = sm_start_session(&sess, &(target->pkey));
    if(status < 0){
        return quit(&E_DC_NOT_TRUSTED);
    }

    /* initiate a new connection */
    status = sm_get_nonce(&sess, &conn);
    if(status < 0){
        return quit(&E_DC_GET_NONCE);
    }

    /* now we initiate a socket connection */
    socket = socks_connect_init(target->port, target->hostname, MAX_CONNECT_WAIT_SECONDS);
    if(socket < 0){
        return quit(&E_DC_INIT_SOCKET);
    }

    /* sent the request type to the server to initiate connection */
    status = cm_write_uint16(DS_REQUEST_GET, socket);
    if(status < 0){
        return dc_generate_error(&sess, socket, &E_DC_WRITE_REQUEST_TYPE);
    }

    /* sent the new connection to the server */
    printf("> sent new connection `C, nC` to %s\n", (target->pkey).device_name);
    status = cm_write_new_connection(&conn, socket);
    if(status < 0){
        return dc_generate_error(&sess, socket, &E_DC_WRITE_NEW_CONNECTION);
    }

    /* read the mutualauth reply */
    printf("< receive mutualauth `{nR, nC, C}SK(R)`\n");
    status = cm_read_mutualauth(&mutau, socket);
    if(status < 0){
        return dc_generate_error(&sess, socket, &E_DC_READ_MUTUALAUTH);
    }

    /* check the mutualauth at the security manager */
    status = sm_check_mutualauth(&sess, &mutau);
    if(status < 0){
        return dc_generate_error(&sess, socket, &E_DC_CHECK_MUTUALAUTH);
    }

    /* get the payment */
    status = sm_get_payment(&sess, get_content, &paym);
    if(status < 0){
        return dc_generate_error(&sess, socket, &E_DC_GET_PAYMENT);
    }

    /* sent the payment to the server */
    printf("> sent payment `{nC, nR, h(M), R', R}SK(C)`\n");
    status = cm_write_payment(&paym, socket);
    if(status < 0){
        return dc_generate_error(&sess, socket, &E_DC_WRITE_PAYMENT);
    }

    /* receive the secured content */
    printf("< receive content `{M}K, {K}PK(C), {R', nC}SK(R)`\n");
     
    /* read the secured content details */
    status = cm_read_secured_content(&content, socket);
    if(status < 0){
        return quit(&E_DS_WRITE_CONTENT);
    }

    /* initialize the stepwise security and connection manager */
    if(cm_start_reading_large_file(socket, &lfp) < 0){
        return dc_generate_error(&sess, socket, &E_DC_START_READ_CONTENT);
    }
    if(sm_start_save_secured_content(&sess, get_content, &content, &lfp) < 0){
        return dc_generate_error(&sess, socket, &E_DC_START_SAVE_CONTENT);
    }

    /* loop until all data is processed */
    while(lfp.total_size > lfp.total_read){
        status = cm_read_partof_large_file(&lfp);
printf("dc_handle_get> content read/write loop: %i/%i\n", lfp.total_read, lfp.total_size);
        if(status < 0){
            sm_stop_save_secured_content(&sess, get_content, &content, &lfp);
            return dc_generate_error(&sess, socket, &E_DC_READ_CONTENT);
        }
        
        /* check the content at the security manager and save if correct */
        status = sm_save_partof_secured_content(&sess, get_content, &content, &lfp);
        if(status < 0){
            return dc_generate_error(&sess, socket, &E_DC_SAVE_CONTENT);
        }
    }
    
    /* finalize saving the secured content */
    status = sm_finalize_save_secured_content(&sess, get_content, &content, &lfp);
    if(status < 0){
        return dc_generate_error(&sess, socket, &E_DC_READ_CONTENT);
    }
    
    return 1;
}

/* initiate a restore request at a provider */
   /* note: this code looks a bit like the client get-request code */
PUBLIC int dc_handle_restore(u_int16_t restore_me, nuovo_server *restore_at){
    int status, socket;
    new_connection conn;
    session sess;
    mutualauth mutau;
    restored_payment respaym;
    secured_content content;
    large_file lfp;

    /* open the failed session from disk */
    status = dm_read_incremental_file(SAVE_DIR_SESSIONS, restore_me, sizeof(session), (char *)&sess);
    if(status < 0){
        return quit(&E_DC_OPEN_SESSION);
    }

    /* get a second new connection */
    status = sm_get_second_nonce(&sess, &(restore_at->pkey), &conn);
    if(status < 0){
        return quit(&E_DC_GET_SECOND_NONCE);
    }

    /* now we initiate a socket connection */
    socket = socks_connect_init(restore_at->port, restore_at->hostname, MAX_CONNECT_WAIT_SECONDS);
    if(socket < 0){
        return quit(&E_DC_INIT_SOCKET);
    }

    /* sent the request type to the server to initiate connection */
    status = cm_write_uint16(DS_REQUEST_RESTORE, socket);
    if(status < 0){
        return dc_generate_error(&sess, socket, &E_DC_WRITE_REQUEST_TYPE);
    }

    /* sent the new connection to the server */
    printf("> sent new connection `C, n'C` to %s\n", (restore_at->pkey).device_name);
    status = cm_write_new_connection(&conn, socket);
    if(status < 0){
        return dc_generate_error(&sess, socket, &E_DC_WRITE_NEW_CONNECTION);
    }

    /* read the mutualauth reply */
    printf("< receive mutualauth `{nP, n'C, C}SK(P)`\n");
    status = cm_read_mutualauth(&mutau, socket);
    if(status < 0){
        return dc_generate_error(&sess, socket, &E_DC_READ_MUTUALAUTH);
    }

    /* check the mutualauth at the security manager */
    status = sm_check_mutualauth(&sess, &mutau);
    if(status < 0){
        return dc_generate_error(&sess, socket, &E_DC_CHECK_MUTUALAUTH);
    }

    /* get the payment */
    status = sm_get_restored_payment(&sess, &respaym);
    if(status < 0){
        return dc_generate_error(&sess, socket, &E_DC_GET_RESTORED_PAYMENT);
    }

    /* sent the payment to the server */
    printf("> sent payment `{n'C, nP, <nC, nR, h(M), R', R>, P}SK(C)`\n");
    status = cm_write_restored_payment(&respaym, socket);
    if(status < 0){
        return dc_generate_error(&sess, socket, &E_DC_WRITE_RESTORED_PAYMENT);
    }

    /* receive the secured content */
    printf("< receive content `{M}K, {K}PK(C), {R', n'C}SK(P)`\n");
    
    /* initialize the stepwise security and connection manager */
    if(cm_start_reading_large_file(socket, &lfp) < 0){
        return dc_generate_error(&sess, socket, &E_DC_START_READ_CONTENT);
    }
    if(sm_start_save_secured_content(&sess, &(sess.info), &content, &lfp) < 0){
        return dc_generate_error(&sess, socket, &E_DC_START_SAVE_CONTENT);
    }

    /* loop until all data is processed */
    while(lfp.total_size > lfp.total_read){
        status = cm_read_partof_large_file(&lfp);
        if(status < 0){
            sm_stop_save_secured_content(&sess, &(sess.info), &content, &lfp);
            return dc_generate_error(&sess, socket, &E_DC_READ_CONTENT);
        }
    
        /* check the content at the security manager and save if correct */
        status = sm_save_partof_secured_content(&sess, &(sess.info), &content, &lfp);
        if(status < 0){
            return dc_generate_error(&sess, socket, &E_DC_SAVE_CONTENT);
        }
    }

    /* close the socket */
    close(socket);

    return 1;
}

PUBLIC int dc_handle_list(nuovo_server *list_at, content_info_list *cilist){
    int socket;
    int status;
    session sess;

    /* start a security manager session (checks the pkey) */
    status = sm_start_session(&sess, &(list_at->pkey));
    if(status < 0){
        return quit(&E_DC_NOT_TRUSTED);
    }

    /* now we initiate a socket connection */
    socket = socks_connect_init(list_at->port, list_at->hostname, MAX_CONNECT_WAIT_SECONDS);
    if(socket < 0){
        return quit(&E_DC_INIT_SOCKET);
    }

    /* sent the request type to the server to initiate connection */
    status = cm_write_uint16(DS_REQUEST_LIST, socket);
    if(status < 0){
        return dc_generate_error(&sess, socket, &E_DC_WRITE_REQUEST_TYPE);
    }

    /* read the list from the socket */
    status = cm_read_content_info_list(cilist, socket);
    if(status < 0){
        return dc_generate_error(&sess, socket, &E_DC_READ_CONTENT_LIST);
    }

    /* close the socket */
    close(socket);

    return 1;
}

PUBLIC int dc_handle_update(nuovo_server *update_at){
    int socket;
    int status;
    revocation_list drl;
    session sess;

    /* start a security manager session (checks the pkey) */
    status = sm_start_session(&sess, &(update_at->pkey));
    if(status < 0){
        return quit(&E_DC_NOT_TRUSTED);
    }

    /* now we initiate a socket connection */
    socket = socks_connect_init(update_at->port, update_at->hostname, MAX_CONNECT_WAIT_SECONDS);
    if(socket < 0){
        return quit(&E_DC_INIT_SOCKET);
    }

    /* sent the request type to the server to initiate connection */
    status = cm_write_uint16(DS_REQUEST_UPDATE, socket);
    if(status < 0){
        return dc_generate_error(&sess, socket, &E_DC_WRITE_REQUEST_TYPE);
    }

    /* read the revocation list from the socket */
    status = cm_read_drl(&drl, socket);
    if(status < 0){
        return dc_generate_error(&sess, socket, &E_DC_READ_DRL);
    }
printf("> DRL of size %i read from socket\n", drl.len);

    /* forward the DRL to the security manager to save it */
    status = sm_update_drl(&sess, &drl);
printf("> update DRL returned: %i\n", status);
    if(status < 0){
        return dc_generate_error(&sess, socket, &E_DC_UPDATE_DRL);
    }

    /* free the list */
    deallocate_pp(drl.revoked_keys, drl.len);

    /* close the socket */
    close(socket);

    return 1;
}
