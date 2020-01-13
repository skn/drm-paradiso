#include "interface_server.h"

/* normally we take care of error indication on the socket
   ourselves, only when we sent lists we let the connection manager
   take care of it */

PRIVATE int is_generate_error(error_package *error, int request_socket){
    cm_send_error_identifier(error->code, request_socket);
    return quit(error);
}

PRIVATE int is_indicate_succes(int request_socket){
    int status;

    status = cm_send_error_identifier(CM_CONTINUE, request_socket);
    if(status < 0){
        return quit(&E_IS_WRITE_REPLY_STATUS);
    }
    return status;
}

PRIVATE int is_handle_get_request(int request_socket){
    int status;
    u_int16_t index;
    interface_request_get is_get;

    /* read needed information from the interface socket */
    status = cm_read_request_get(&is_get, request_socket);
    if(status < 0){
        return is_generate_error(&E_IS_READ_REQUEST_GET, request_socket);
    }
    
    /* check if we already own the requested content */
    status = dm_search_incremental_file(SAVE_DIR_CLF, is_get.info.hash, SHA_DIGEST_LENGTH, &index);
    if(status == 1){
        return is_generate_error(&E_IS_DUPLICATE_CONTENT, request_socket);
    }

    /* forward the request to the data client */
    status = dc_handle_get(&is_get.info, &is_get.request_at);
    if(status < 0){
        return is_generate_error(&E_IS_REQUEST_GET, request_socket);
    }

    return is_indicate_succes(request_socket);
}

PRIVATE int is_handle_sessions_request(int request_socket){
    int status;
    interface_reply_session_list slist;

    /* get a list of all open sessions from the data manager */
    status = dm_get_session_list(&slist);
    if(status < 0){
        /* indicate failure to the interface client and quit */
        return is_generate_error(&E_IS_GET_SESSION_LIST, request_socket);
    }

    /* return the list of sessions to the interface */
    status = cm_write_if_session_list(&slist, request_socket);
    if(status < 0){
        return quit(&E_IS_WRITE_SESSION_LIST);
    }

    /* free the list */
    deallocate_pp((char **)slist.list, slist.len);

    /* that was all */
    return 1;
}

PRIVATE int is_handle_restore_request(int request_socket){
    int status;
    interface_request_restore is_restore;

    /* read needed information from the interface socket */
    status = cm_read_request_restore(&is_restore, request_socket);
    if(status < 0){
        return is_generate_error(&E_IS_READ_REQUEST_RESTORE, request_socket);
    }

    /* forward the request to the data client */
    status = dc_handle_restore(is_restore.index, &is_restore.restore_at);
    if(status < 0){
        return is_generate_error(&E_IS_REQUEST_RESTORE, request_socket);
    }
    return is_indicate_succes(request_socket);
}

/* customer wants to see a list of content at another server */
PRIVATE int is_handle_list_request(int request_socket){
    int status;
    nuovo_server list_at;
    content_info_list cilist;

    /* read needed information from the interface socket */
    status = cm_read_nuovo_server(&list_at, request_socket);
    if(status < 0){
        return is_generate_error(&E_IS_READ_REQUEST_LIST, request_socket);
    }

    /* forward the request to the data client */
    status = dc_handle_list(&list_at, &cilist);
    if(status < 0){
        deallocate_pp((char **)cilist.list, cilist.len);
        return is_generate_error(&E_IS_REQUEST_LIST, request_socket);
    }

    /* reply the list to the interface client */
    status = cm_write_content_info_list(&cilist, request_socket);
    if(status < 0){
        deallocate_pp((char **)cilist.list, cilist.len);
        return quit(&E_IS_WRITE_CONTENT_INFO_LIST);
    }

    /* now free the list */
    deallocate_pp((char **)cilist.list, cilist.len);

    return 1;
}

PRIVATE int is_handle_update_request(int request_socket){
    int status;
    nuovo_server update_at;

    /* read needed information from the interface socket */
    status = cm_read_nuovo_server(&update_at, request_socket);
    if(status < 0){
        return is_generate_error(&E_IS_READ_REQUEST_UPDATE, request_socket);
    }

    /* forward the request to the data client */
    status = dc_handle_update(&update_at);
    if(status < 0){
        return is_generate_error(&E_IS_REQUEST_UPDATE, request_socket);
    }

    /* indicate the command was processed succesfully */
    return is_indicate_succes(request_socket);
}

PRIVATE int is_handle_scan_request(int request_socket){
    int status;
    interface_reply_scan_list slist;

    /* let the broadcast client collect all nuovo servers on the local network */
    status = bc_collect_nuovo_servers(&slist);
    if(status < 0){
        /* indicate failure to the interface client and quit */
        return is_generate_error(&E_IS_PERFORM_SCAN, request_socket);
    }

    /* return the list of nuovo servers to the interface */
    status = cm_write_if_scan_list(&slist, request_socket);
    
    /* now free the list */
    deallocate_pp((char **)slist.list, slist.len);
    
    /* check for failure */
    if(status < 0){
        return quit(&E_IS_WRITE_SCAN_LIST);
    }

    /* that was all */
    return 1;
}

PRIVATE int is_handle_play_request(int request_socket){
    int status;
    content_info play_me;
    raw_content save_me;
    session sess;
    large_file lfp;

    /* read needed information from the interface socket */
    status = cm_read_content_info(&play_me, request_socket);
    if(status < 0){
        return is_generate_error(&E_IS_READ_REQUEST_PLAY, request_socket);
    }

/* the implementation of the play request is still under heavy development
   we just sent commands to the tpm directly to get some raw content back
   and store the raw content to disk. In a real live situation the tpm
   should decode small parts of the content during playback, nothing should
   be written to disk as unencrypted temporary file :P */

    /* start the security manager for internal usage only */
    status = sm_start_internal(&sess);

    /* initialize the stepwise security and connection manager */
    if(dm_start_writing_large_file(SAVE_DIR_TEMP, TEMP_PLAY_FILE, &lfp) < 0){
        return is_generate_error(&E_IS_START_WRITE_CONTENT, request_socket);
    }
    
    /* initialize getting content from the security manager */
    if(sm_start_get_raw_content(&sess, play_me.hash, &save_me, &lfp) < 0){
        return is_generate_error(&E_IS_START_GET_CONTENT, request_socket);
    }
    
    /* loop until all data is processed */
    while(lfp.total_size > lfp.total_read){
        /* we get and send the content when it's oke */
        status = sm_get_partof_raw_content(&sess, &save_me, &lfp);
        if(status < 0){
            return is_generate_error(&E_DS_GET_CONTENT, request_socket);
        }
    
        /* now we send the content to the customer */
        status = cm_write_partof_large_file(&lfp);
        if(status < 0){
            sm_stop_get_raw_content(&sess, &save_me, &lfp);
            return quit(&E_DS_WRITE_CONTENT);
        }
    }
    
    /* decode and send last part to customer */
    status = sm_finalize_get_raw_content(&sess, &save_me, &lfp);
    if(status < 0){
        return is_generate_error(&E_DS_GET_CONTENT, request_socket);
    }
    status = cm_write_partof_large_file(&lfp);
    if(status < 0){
        return quit(&E_DS_WRITE_CONTENT);
    }
    

#ifdef _NEUROS_
#ifndef _PROVIDER_

    /* fork off a new process to handle the playing only if the content is audio */
    if(play_me.type == CONTENT_TYPE_AUDIO){
        int pid;
        pid = fork();
        if(pid == 0){ /* child process */
            media_info_t media_info;
            int cur_time;
            
            if (NmsInit()){
    	        printf("NMS initialization failed!\n");
                exit(1);
            }
    
            NmsStart();	
       
            NmsGetMediaInfo(TEMP_PLAY_FILE,&media_info);
    
            printf("stop record\n");
            NmsStopRecord();
    
            printf("start playing\n");
            NmsPlay(0, TEMP_PLAY_FILE);

            for(;;){
                sleep(1);
                cur_time = NmsGetPlaytime();
                printf("PLAY: %i\n", cur_time);
                if(cur_time == -1){
                    break;
                }
            }

            NmsStopPlay();
            exit(1);
        }
    }
#endif
#endif

    /* indicate the command was processed succesfully */
    return is_indicate_succes(request_socket);
}

PRIVATE int is_handle_pkey_request(int request_socket){
    nuovo_server result;
    session sess;
    int status;

    /* start a new security manager session for internal usage */
    status = sm_start_internal(&sess);

    /* request the security manager for our public key */
    status = sm_get_public_key(&sess, &(result.pkey));
    if(status < 0){
        return quit(&E_IS_GET_PKEY);
    }
    result.port = DS_PORT;
    
    /* sent the public key */
    status = cm_write_nuovo_server(&result, request_socket);
    if(status < 0){
        return quit(&E_IS_WRITE_SERVER);
    }

    /* indicate the command was processed succesfully */
    return 1;
}

/* include if needed the provider methods */
#ifdef _PROVIDER_
#include "interface_server_provider.c"
#endif

/* handle a request by checking the request type and calling the corresponding method */
PUBLIC int is_handle_request(int request_socket){
    uint16_t request_type;
    int status;

    /* the first thing we receive is an integer denoting the type of interaction */
    if(cm_read_uint16(&request_type, request_socket) < 0){
        /* request type couldn't be read from the socket correctly */
        return quit(&E_IS_READ_REQUEST_TYPE);
    }

printf("< interface server got request %i\n", request_type);

    /* now start each function associated with the received request type */
    switch(request_type){
        case IS_REQUEST_GET:
            status = is_handle_get_request(request_socket);
            break;
        case IS_REQUEST_SESSIONS:
            status = is_handle_sessions_request(request_socket);
            break;
        case IS_REQUEST_RESTORE:
            status = is_handle_restore_request(request_socket);
            break;
        case IS_REQUEST_LIST:
            status = is_handle_list_request(request_socket);
            break;
        case IS_REQUEST_UPDATE:
            status = is_handle_update_request(request_socket);
            break;
        case IS_REQUEST_CASH:
            return is_generate_error(&E_IS_NOT_IMPLEMENTED, request_socket);
            break;
        case IS_REQUEST_SCAN:
            status = is_handle_scan_request(request_socket);
            break;
        case IS_REQUEST_ADD:
#ifdef _PROVIDER_
            /* this method is only available for providers */
            status = is_handle_add_request(request_socket);
            break;
#else
            return is_generate_error(&E_IS_NO_PROVIDER, request_socket);
#endif /* _PROVIDER_ */
        case IS_REQUEST_REVOKE:
#ifdef _PROVIDER_
            /* this method is only available for providers */
            status = is_handle_revoke_request(request_socket);
            break;
#else
            return is_generate_error(&E_IS_NO_PROVIDER, request_socket);
#endif /* _PROVIDER_ */
        case IS_REQUEST_PLAY:
            status = is_handle_play_request(request_socket);
            break;
        case IS_REQUEST_PKEY:
            status = is_handle_pkey_request(request_socket);
            break;
        default:
            /* we received some unknown request type */
            return quit(&E_IS_UNKNOWN_REQUEST_TYPE);
            break;
    }

    /* return if the method succeeded */
    return status;
}
