#include "data_server.h"

/* the data server implements the server part of the extended nuovo protocol */

PRIVATE int ds_generate_error(session *sess, int request_socket, error_package *error){
    int status;
    protected_error failed;

    /* get error message and check for failure */
    status = sm_get_protected_error(sess, &failed);
    if(status < 0){
        return status;
    }

    /* send the error message */
    cm_write_protected_error(&failed, request_socket);

    /* quit the program */
    return quit(error);
}

/* handle a complete incoming get request */
PRIVATE int ds_handle_get(int request_socket){
    int status;
    new_connection conn;
    session sess;
    mutualauth mutau;
    payment paym;
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
    
    /* the customer replies with the payment */
    status = cm_read_payment(&paym, request_socket);
    if(status < 0){
        return quit(&E_DS_READ_PAYMENT);
    }
    
/* note: possible problem here is that we should be sure that
   the payment is originating from the customer and not from
   someone else. If someone else can succeed in sending a false
   payment message then we would incorrectly terminate the
   connection */

    /* check the payment and continue if accepted */
    status = sm_check_payment(&sess, &paym);
    if(status < 0){
        return ds_generate_error(&sess, request_socket, &E_DS_PAYMENT);
    }

    /* initialize the stepwise security manager */
    if(sm_start_get_secured_content(&sess, &content, &lfp) < 0){
        return ds_generate_error(&sess, request_socket, &E_DS_START_GET_CONTENT);
    }
    
    /* write the secured content details */
    status = cm_write_secured_content(&content, request_socket);
    if(status < 0){
        return quit(&E_DS_WRITE_CONTENT);
    }
    
    /* initialize the stepwise connection manager */    
    if(cm_start_writing_large_file(request_socket, content.content_length, &lfp) < 0){
        return ds_generate_error(&sess, request_socket, &E_DS_START_WRITE_CONTENT);
    }
    
    /* loop until all data is processed */
    while(lfp.total_size > lfp.total_read){
        /* we get and send the content when it's oke */
        status = sm_get_partof_secured_content(&sess, &content, &lfp);
printf("ds_handle_get> content read/write loop: %i/%i\n", lfp.total_read, lfp.total_size);
        if(status < 0){
            sm_stop_get_secured_content(&sess, &content, &lfp);
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

    /* get request succeeded */
    return 1;
}

/* handle an incoming list request */
PRIVATE int ds_handle_list(request_socket){
    int status;
    content_info_list clist;

    /* get the content list at the data manager */
    status = dm_get_content_info_list(&clist);
    if(status < 0){
        return quit(&E_DS_GET_CONTENT_LIST);
    }

    status = cm_write_content_info_list(&clist, request_socket);
    if(status < 0){
        deallocate_pp((char **)clist.list, clist.len);
        return quit(&E_DS_WRITE_CONTENT_LIST);
    }

    /* free the list memory here */
    deallocate_pp((char **)clist.list, clist.len);

    /* list request succeeded */
    return 1;
}

/* include if needed the provider methods */
#ifdef _PROVIDER_
#include "data_server_provider.c"
#endif

/* handle a request by checking the request type and calling the corresponding method */
PUBLIC int ds_handle_request(int request_socket){
    uint16_t request_type;

    /* the first thing we receive is an integer denoting the type of interaction */
    if(cm_read_uint16(&request_type, request_socket) < 0){
        /* request type couldn't be read from the line correctly */
        return quit(&E_DS_READ_REQUEST_TYPE);
    }

printf("< new DS request, %i\n", request_type);

    switch(request_type){
        case DS_REQUEST_GET:
            return ds_handle_get(request_socket);
            break;
        case DS_REQUEST_RESTORE:
            /* we can only receive restore requests when we are the provider */
#ifdef _PROVIDER_
            return ds_handle_restore(request_socket);
#else
            return ds_generate_error(NULL, request_socket, &E_DS_NO_PROVIDER);
#endif /* _PROVIDER_ */
            break;
        case DS_REQUEST_LIST:
            return ds_handle_list(request_socket);
            break;
        case DS_REQUEST_UPDATE:
            /* we can only receive update requests when we are the provider */
#ifdef _PROVIDER_
            return ds_handle_update(request_socket);
#else
            return ds_generate_error(NULL, request_socket, &E_DS_NO_PROVIDER);
#endif /* _PROVIDER_ */
            break;
        case DS_REQUEST_CASH:
            /* there exists no nuovo implementation to be run by the bank */
            return ds_generate_error(NULL, request_socket, &E_DS_NO_BANK);
            break;
        default:
            /* we received some unknown request type */
            return quit(&E_DS_UNKNOWN_REQUEST_TYPE);
    }
    return 1;
}
