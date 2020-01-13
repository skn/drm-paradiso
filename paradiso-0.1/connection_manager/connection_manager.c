#include "connection_manager.h"

/* this method checks, using identifier codes, if there happens
   to be an protected error message on the socket */
PUBLIC int cm_check_unexpected_error(int socket){
    int status;
    int16_t identifier;
    protected_error perr;

    /* try to receive the identifier from the socket */
    status = socks_recv_all((char *)&identifier, sizeof(int16_t), socket);
    if(status < 0){
        /* this probably means that the connection is terminated without
           an error message: not good */
        return quit(&E_CM_NO_IDENTIFIER);
    }

    /* can we continue ? */
    if(identifier == CM_CONTINUE){
        return 1;
    }

    /* can we expect an protected error message on the socket? */
    if(identifier == CM_ERROR){
        status = cm_read_protected_error(&perr, socket);
        if(status < 0){
            /* failed reading error message: not good either */
            return quit(&E_CM_NO_ERROR_PACKAGE);
        }


        /* check if we can accept this error message */
        /* ** TODO ** */

        /* return indication of failure */
        return -1;
    }
    
    /* check for incorrect identifier */
    if(identifier > 0){
        return quit(&E_CM_UNKNOWN_IDENTIFIER);
    }
    
    /* some other error was detected, so just return the identifier */
    return identifier;
}

/* this methode writes an identifier code, for error indication, on the socket */
PUBLIC int cm_send_error_identifier(int16_t identifier, int socket){
    return socks_send_all((char *)&identifier, sizeof(int16_t), socket);
}

/* convert rights struct from host to network order */
PRIVATE void cm_hton_rights(rights *content_rights){
    content_rights->resell_count = htons(content_rights->resell_count);
    content_rights->resell_depth = htons(content_rights->resell_depth);
    content_rights->resell_total = htons(content_rights->resell_total);
    content_rights->price        = htonl(content_rights->price);
}

/* convert rights struct from network to host order */
PRIVATE void cm_ntoh_rights(rights *content_rights){
    content_rights->resell_count = ntohs(content_rights->resell_count);
    content_rights->resell_depth = ntohs(content_rights->resell_depth);
    content_rights->resell_total = ntohs(content_rights->resell_total);
    content_rights->price        = ntohl(content_rights->price);
}

PRIVATE void cm_hton_content_info(content_info *info){
    cm_hton_rights(&(info->content_rights));
    info->content_size = htonl(info->content_size);
}

PRIVATE void cm_ntoh_content_info(content_info *info){
    cm_ntoh_rights(&(info->content_rights));
    info->content_size = ntohl(info->content_size);
}

/* read a protected error message from the socket */
PUBLIC int cm_read_protected_error(protected_error *perr, int socket){
        return socks_recv_all((char *)&CM_ERROR_MESSAGE, sizeof(protected_error), socket);
}

/* the integer in the protected_error struct is only 1 byte so
   we don't need any network-to-host conversion */
PUBLIC int cm_write_protected_error(protected_error *perr, int socket){
    if(cm_send_error_identifier(CM_ERROR, socket) < 0){
        return -1;
    }
    /* send the struct */
    return socks_send_all((char*)perr, sizeof(protected_error), socket);
}

/* read integer of type uint16_t from socket */
PUBLIC int cm_read_uint16(uint16_t *result, int socket){
    int status;
 	status = socks_recv_all((char *)result, sizeof(uint16_t), socket);
    
    /* convert the result to host order and return status */
    *result = ntohs(*result);
    return status;
}

/* write integer of type uint16_t to socket */
PUBLIC int cm_write_uint16(uint16_t src, int socket){
    uint16_t src_n = htons(src);
	return socks_send_all((char *)&src_n, sizeof(uint16_t), socket);
}

/* read integer of type uint32_t from socket */
PUBLIC int cm_read_uint32(uint32_t *result, int socket){
    int status;
 	status = socks_recv_all((char *)result, sizeof(uint32_t), socket);
    
    /* convert the result to host order and return status */
    *result = ntohl(*result);
    return status;
}

/* write integer of type uint32_t to socket */
PUBLIC int cm_write_uint32(uint32_t src, int socket){
    uint32_t src_n = htonl(src);
	return socks_send_all((char *)&src_n, sizeof(uint32_t), socket);
}

PUBLIC int cm_read_new_connection(new_connection *conn, int socket){
    int status = cm_check_unexpected_error(socket);
    if(status < 0){
        return status;
    }
    return socks_recv_all((char*)conn, sizeof(new_connection), socket);
}
PUBLIC int cm_write_new_connection(new_connection *conn, int socket){
    if(cm_send_error_identifier(CM_CONTINUE, socket) < 0){
        return -1;
    }
    return socks_send_all((char*)conn, sizeof(new_connection), socket);
}

PUBLIC int cm_read_mutualauth(mutualauth *mutau, int socket){
    int status = cm_check_unexpected_error(socket);
    if(status < 0){
        return status;
    }
    return socks_recv_all((char*)mutau, sizeof(mutualauth), socket);
}
PUBLIC int cm_write_mutualauth(mutualauth *mutau, int socket){
    if(cm_send_error_identifier(CM_CONTINUE, socket) < 0){
        return -1;
    }
    return socks_send_all((char*)mutau, sizeof(mutualauth), socket);
}

PUBLIC int cm_read_payment(payment *paym, int socket){
    int status;
    
    status = cm_check_unexpected_error(socket);
    if(status < 0){
        return status;
    }

    /* receive the struct and check for failure */
    status = socks_recv_all((char*)paym, sizeof(payment), socket);
    if(status < 0){
        return status;
    }

    /* convert the struct to host order */
    cm_ntoh_rights(&(paym->content_rights));

    return status;
}
PUBLIC int cm_write_payment(payment *paym, int socket){
    int status;

    /* send continue identifier */
    if(cm_send_error_identifier(CM_CONTINUE, socket) < 0){
        return -1;
    }

    /* convert the struct to network order */
    cm_hton_rights(&(paym->content_rights));

    /* send the struct */
    status = socks_send_all((char*)paym, sizeof(payment), socket);

    /* restore the struct to host order in case someone wants to use it */
    cm_ntoh_rights(&(paym->content_rights));

    /* return possible failure */
    return status;
}

/* this method reads data of variable length */
PRIVATE int cm_read_varlen_data(u_int32_t *len, char **data, int socket){
    int status;

    /* read the length */
    status = cm_read_uint32(len, socket);
    if(status < 0){
        return status;
    }

    /* allocate memory for the data */
    *data = allocate(*len);
    if(*data == NULL){
        return LAST_ERROR;
    }

    /* receive the data */
    return socks_recv_all(*data, *len, socket);
}
PRIVATE int cm_write_varlen_data(u_int32_t len, char *data, int socket){
    int status;

    /* write the length */
    status = cm_write_uint32(len, socket);
    if(status < 0){
        return status;
    }

    /* write the data */
    return socks_send_all(data, len, socket);
}

PUBLIC int cm_read_secured_content(secured_content *content, int socket){
    int status;

    status = cm_check_unexpected_error(socket);
    if(status < 0){
        return status;
    }

    /* read the struct */
    status = socks_recv_all((char*)content, sizeof(secured_content), socket);
    if(status < 0){
        return status;
    }

    /* convert from network to host order */
    cm_ntoh_rights(&(content->content_rights));

    return status;
}
PUBLIC int cm_write_secured_content(secured_content *content, int socket){
    int status;

    /* send continue identifier */
    if(cm_send_error_identifier(CM_CONTINUE, socket) < 0){
        return -1;
    }

    /* convert the host order rights struct to network order */
    cm_hton_rights(&(content->content_rights));

    /* send the remaining part of the struct */
    status = socks_send_all((char*)content, sizeof(secured_content), socket);

    /* restore the rights struct to host order in case someone wants to use it */
    cm_ntoh_rights(&(content->content_rights));

    /* return possible failure */
    return status;
}

PUBLIC int cm_read_raw_content(raw_content *content, int socket){
    int status;

    status = socks_recv_all((char *)content, sizeof(raw_content), socket);
    if(status < 0){
        return status;
    }

    /* convert from network to host order */
    cm_ntoh_content_info(&(content->info));
    return status;
}
PUBLIC int cm_write_raw_content(raw_content *content, int socket){
    int status;


    /* convert to host order */
    cm_ntoh_content_info(&(content->info));

    /* send the remaining part of the struct */
    status = socks_send_all((char*)content, sizeof(raw_content), socket);

    /* restore to host order in case someone wants to use it */
    cm_hton_content_info(&(content->info));

    /* return possible failure */
    return status;
}

PRIVATE int cm_read_list(char ***list, uint16_t *listlen, size_t partlen, int socket){
    int status, i;
    
    /* we need these temporary variables otherwise the neuros
       compiler makes a mess of our code */
    uint16_t len;
    int resvlen;
    char *tempbuf_p;
    char **tempbuf_pp;

    status = cm_check_unexpected_error(socket);
    if(status < 0){
        return status;
    }

    /* we first read the length of the list and check for failure */
    status = cm_read_uint16(&len, socket);
    if(status < 0){
        return status;
    }

    /* check for empty list */
    if(len == 0){
        *listlen = 0;
        return 1;
    }
    *listlen = len;

    /* reserve memory for the pointers */
    resvlen = (int)(sizeof(char **) * len);
    tempbuf_pp = (char **)allocate(resvlen);
    if(tempbuf_pp == NULL){
        return LAST_ERROR;
    }
    /* now we start reading each part from the socket and reserve memory for each of them */
    for(i = 0; i < len; i++){
        tempbuf_p = (char *)allocate(partlen);
        tempbuf_pp[i] = tempbuf_p;
        if(tempbuf_p == NULL){
            /* owh noo, some error occured at a real nasty point */
            deallocate_pp(tempbuf_pp, i);
            return LAST_ERROR;
        }
        /* now we read the part from the socket */
        status = socks_recv_all(tempbuf_p, partlen, socket);
        if(status < 0){
            deallocate_pp(tempbuf_pp, i+1);
            return LAST_ERROR;
            /* note: i+1 because the memory for the i-th pointer was reserved correctly */
        }
    }

    *list = tempbuf_pp;

    /* we finished */
    return status;
}
PRIVATE int cm_write_list(char **list, u_int16_t *listlen, int partlen, int socket){
    int status, i;
    /* this is much easier than reading, because we already have the memory available */
    
    /* send continue identifier */
    if(cm_send_error_identifier(CM_CONTINUE, socket) < 0){
        return -1;
    }

    /* first write the length of the list */
    status = cm_write_uint16(*listlen, socket);
    if(status < 0){
        return status;
    }
    

    /* empty list exception */
    if(*listlen == 0){
        return 1;
    }

    /* then we write each data partlen */
    for(i=0; i<*listlen; i++){
        status = socks_send_all(list[i], partlen, socket);
        if(status < 0){
            return status;
        }
    }
    
    /* that was all */
    return status;
}

PUBLIC int cm_read_content_info_list(content_info_list *clist, int socket){
    char **temp;
    int status, i;
    
    /* just like all the other methods below which make a call to cm_read_list
       we need some temporary variabele declared in the scope of this method
       to store the results in before we can write it to list struct. Before
       we supplied the pointer with '(char ***)&(clist->list)' and this
       worked perfect for a normal linux computer with normal gcc compiler, but
       for the neuros with the arm compiler this resulted in unexplainable
       segmentation faults and only using this temp variabele solved the problem */

    status = cm_read_list((char ***)&temp, &(clist->len), sizeof(content_info), socket);
    clist->list = (content_info **)temp;
    if(status < 0){
        return status;
    }
    
    /* convert to host order */
    for(i=0; i<clist->len; i++){
        cm_ntoh_content_info(clist->list[i]);
    }

    return status;
}
PUBLIC int cm_write_content_info_list(content_info_list *clist, int socket){
    int status, i;

    /* first convert from host to network order */
    for(i=0; i<clist->len; i++){
        cm_hton_content_info(clist->list[i]);
    }

    /* write the list */
    status = cm_write_list((char **)clist->list, &(clist->len), sizeof(content_info), socket);

    /* restore the struct to host order in case someone wants to use it */
    for(i=0; i<clist->len; i++){
        cm_ntoh_content_info(clist->list[i]);
   }

    return status;
}

PUBLIC int cm_read_drl(revocation_list *drl, int socket){
    char **temp;
    int status, offset;
    
    status = cm_read_list(&temp, &(drl->len), RSA_PKEY_RAW_LENGTH, socket);
    if(status < 0){
        return status;
    }
    drl->revoked_keys = temp;

    offset = sizeof(u_int16_t) + sizeof(char **);
    return socks_recv_all(((char*)drl) + offset, sizeof(revocation_list) - offset, socket);
}
PUBLIC int cm_write_drl(revocation_list *drl, int socket){
    int status, offset;
    
    status = cm_write_list((char **)drl->revoked_keys, &(drl->len), RSA_PKEY_RAW_LENGTH, socket);
    if(status < 0){
        return status;
    }
    
    offset = sizeof(u_int16_t) + sizeof(char **);
    return socks_send_all(((char*)drl) + offset, sizeof(revocation_list) - offset, socket);
}

PUBLIC int cm_read_restored_payment(restored_payment *respaym, int request_socket){
    int status;

    status = cm_check_unexpected_error(request_socket);
    if(status < 0){
        return status;
    }

    /* receive the struct and check for failure */
    status = socks_recv_all((char*)respaym, sizeof(restored_payment), request_socket);
    if(status < 0){
        return status;
    }

    /* now the hard part, convert the struct to host order */
    cm_ntoh_rights(&((respaym->restore).content_rights));

    return status;
}
PUBLIC int cm_write_restored_payment(restored_payment *respaym, int request_socket){
    int status;

    /* send continue identifier */
    if(cm_send_error_identifier(CM_CONTINUE, request_socket) < 0){
        return -1;
    }

    /* the hard part, convert the struct to network order */
    cm_hton_rights(&((respaym->restore).content_rights));

    /* send the struct */
    status = socks_send_all((char*)respaym, sizeof(restored_payment), request_socket);

    /* restore the struct to host order in case someone wants to use it */
    cm_ntoh_rights(&((respaym->restore).content_rights));

    /* return status, possible failure */
    return status;
}

PUBLIC int cm_read_payment_list(payment_list *plist, int socket){
    int status, i;
    char **temp;

    /* read the list from the socket */
    status = cm_read_list((char ***)&temp, &(plist->len), sizeof(payment), socket);
    plist->payments = (payment **)temp;
    if(status < 0){
        return status;
    }

    /* now convert from network to host order */
    for(i = 0; i < plist->len; i++){
        cm_ntoh_rights(&((plist->payments[i])->content_rights));
    }

    return status;
}
PUBLIC int cm_write_payment_list(payment_list *plist, int socket){
    int status, i;

    /* first convert from host to network order */
    for(i=0; i<plist->len; i++){
        cm_hton_rights(&((plist->payments[i])->content_rights));
   }

    /* now write the struct to the socket */
    status = cm_write_list((char **)plist->payments, &(plist->len), sizeof(payment), socket);

    /* restore the struct to host order in case someone wants to use it */
    for(i=0; i<plist->len; i++){
        cm_ntoh_rights(&((plist->payments[i])->content_rights));
    }

    /* return status, possible failure */
    return status;
}

PUBLIC int cm_read_request_get(interface_request_get *is_get, int socket){
    int status;

    status = cm_check_unexpected_error(socket);
    if(status < 0){
        return status;
    }
    status = socks_recv_all((char*)is_get, sizeof(interface_request_get), socket);
    if(status < 0){
        return status;
    }

    /* convert from network to host order */
    cm_ntoh_content_info(&(is_get->info));
    (is_get->request_at).port = ntohs((is_get->request_at).port);

    return status;
}
PUBLIC int cm_write_request_get(interface_request_get *is_get, int socket){
    int status;
    
    if(cm_send_error_identifier(CM_CONTINUE, socket) < 0){
        return -1;
    }

    cm_hton_content_info(&(is_get->info));
    (is_get->request_at).port = htons((is_get->request_at).port);
    status = socks_send_all((char*)is_get, sizeof(interface_request_get), socket);
    cm_ntoh_content_info(&(is_get->info));
    (is_get->request_at).port = ntohs((is_get->request_at).port);
    
    return status;
}

PUBLIC int cm_read_request_restore(interface_request_restore *is_restore, int socket){
    int status;

    status = cm_check_unexpected_error(socket);
    if(status < 0){
        return status;
    }

    /* receive the struct and check for failure */
    status = socks_recv_all((char*)is_restore, sizeof(interface_request_restore), socket);
    if(status < 0){
        return status;
    }

    /* convert to host order */
    is_restore->index = ntohs(is_restore->index);
    (is_restore->restore_at).port = ntohs((is_restore->restore_at).port);

    return status;
}
PUBLIC int cm_write_request_restore(interface_request_restore *is_restore, int socket){
    int status;

    /* send continue identifier */
    if(cm_send_error_identifier(CM_CONTINUE, socket) < 0){
        return -1;
    }

    /* convert to network order */
    is_restore->index = htons(is_restore->index);
    (is_restore->restore_at).port = htons((is_restore->restore_at).port);

    /* send the struct */
    status = socks_send_all((char*)is_restore, sizeof(interface_request_restore), socket);

    /* restore to host order in case someone wants to use it */
    is_restore->index = ntohs(is_restore->index);
    (is_restore->restore_at).port = ntohs((is_restore->restore_at).port);

    /* return possible failure */
    return status;
}

PUBLIC int cm_read_nuovo_server(nuovo_server *server, int socket){
    int status;
    
    status = cm_check_unexpected_error(socket);
    if(status < 0){
        return status;
    }

    status = socks_recv_all((char*)server, sizeof(nuovo_server), socket);
    if(status < 0){
        return status;
    }

    server->port = ntohs(server->port);

    return status;
}
PUBLIC int cm_write_nuovo_server(nuovo_server *server, int socket){
    int status;

    if(cm_send_error_identifier(CM_CONTINUE, socket) < 0){
        return -1;
    }
    server->port = htons(server->port);
    status = socks_send_all((char*)server, sizeof(nuovo_server), socket);
    server->port = ntohs(server->port);

    return status;
}
PUBLIC int cm_recv_nuovo_server(nuovo_server *server, int socket){
    struct sockaddr_in from;
    int status;
    
    /* start receiving */
    status = socks_udp_recv((char *)server, sizeof(nuovo_server), socket, &from);
    if(status < 0){
        return status;
    }

    /* convert the port from network to host order */
    server->port = ntohs(server->port);

    /* save and convert the received ip-addr */
    if(inet_ntop(AF_INET, &(from.sin_addr), server->hostname, MAXLEN_HOSTNAME) == NULL){
        return -1;
    }

    return 1;
}
PUBLIC int cm_send_nuovo_server(nuovo_server *server, nuovo_server *sendto){
    int status;

    server->port = htons(server->port);
    status = socks_udp_send((char *)server, sizeof(nuovo_server), sendto->port, sendto->hostname);

//socks_udp_send((char *)server, sizeof(nuovo_server), sendto->port, "192.168.1.100");
//socks_udp_send((char *)server, sizeof(nuovo_server), sendto->port, "192.168.1.101");
//socks_udp_send((char *)server, sizeof(nuovo_server), sendto->port, "192.168.1.102");

    server->port = ntohs(server->port);

    return status;
}
PUBLIC int cm_bcast_nuovo_server(nuovo_server *server, int port){
    int status;

    server->port = htons(server->port);
    status = socks_udp_send_bcast((char *)server, sizeof(nuovo_server), port);
/* we manually send to ip .100 .101 and .102 so we can solve the non-wireless udp broadcast problem */

//socks_udp_send((char *)server, sizeof(nuovo_server), port, "192.168.1.100");
//socks_udp_send((char *)server, sizeof(nuovo_server), port, "192.168.1.101");
//socks_udp_send((char *)server, sizeof(nuovo_server), port, "192.168.1.11");

    server->port = ntohs(server->port);

    return status;
}

PUBLIC int cm_read_content_info(content_info *info, int socket){
    int status;

    status = cm_check_unexpected_error(socket);
    if(status < 0){
        return status;
    }
    status = socks_recv_all((char*)info, sizeof(content_info), socket);
    if(status < 0){
        return status;
    }

    /* convert from network to host order */
    cm_ntoh_content_info(info);

    return status;
}
PUBLIC int cm_write_content_info(content_info *info, int socket){
    int status;
    
    if(cm_send_error_identifier(CM_CONTINUE, socket) < 0){
        return -1;
    }

    cm_hton_content_info(info);
    status = socks_send_all((char*)info, sizeof(content_info), socket);
    cm_ntoh_content_info(info);
    
    return status;
}

PUBLIC int cm_read_if_session_list(interface_reply_session_list *slist, int socket){
    int status, i;
    char **temp;

    status = cm_read_list((char ***)&temp, &(slist->len), sizeof(open_session), socket);
    slist->list = (open_session **)temp;
    if(status < 0){
        return status;
    }
    
    /* now convert from network to host order */
    for(i=0; i<slist->len; i++){
        (slist->list[i])->index = ntohs((slist->list[i])->index);
        cm_ntoh_content_info(&((slist->list[i])->info));
    }

    return status;
}
PUBLIC int cm_write_if_session_list(interface_reply_session_list *slist, int socket){
    int status, i;

    /* convert from host to network order */
    for(i=0; i<slist->len; i++){
        (slist->list[i])->index = htons((slist->list[i])->index);
        cm_hton_content_info(&((slist->list[i])->info));
    }

    /* write the list */
    status = cm_write_list((char **)slist->list, &(slist->len), sizeof(open_session), socket);

    /* now convert from network to host order */
    for(i=0; i<slist->len; i++){
        (slist->list[i])->index = ntohs((slist->list[i])->index);
        cm_ntoh_content_info(&((slist->list[i])->info));
    }

    return status;
}

PUBLIC int cm_read_if_scan_list(interface_reply_scan_list *rscan, int socket){
    int status, i;
    char **temp;

    status = cm_read_list((char ***)&temp, &(rscan->len), sizeof(nuovo_server), socket);
    rscan->list = (nuovo_server **)temp;
    if(status < 0){
        return status;
    }

    /* now convert from network to host order */
    for(i=0; i<rscan->len; i++){
        (rscan->list[i])->port = ntohs((rscan->list[i])->port);
    }

    return status;
}
PUBLIC int cm_write_if_scan_list(interface_reply_scan_list *rscan, int socket){
    int status, i;

    /* convert from host to network order */
    for(i=0; i<rscan->len; i++){
        (rscan->list[i])->port = htons((rscan->list[i])->port);
    }

    /* write the list */
    status = cm_write_list((char **)rscan->list, &(rscan->len), sizeof(nuovo_server), socket);

    /* now convert from network to host order */
    for(i=0; i<rscan->len; i++){
        (rscan->list[i])->port = ntohs((rscan->list[i])->port);
    }

    return status;
}

PUBLIC int cm_start_writing_large_file(int socket, u_int32_t len, large_file *lfp){
    lfp->socket = socket;
    lfp->total_size = len;
    if(cm_write_uint32(len, socket) < 0){
        return -1;
    }
    return 1;
}

PUBLIC int cm_write_partof_large_file(large_file *lfp){
    uint32_t size = lfp->buffer_size;
    
    if(cm_send_error_identifier(CM_CONTINUE, lfp->socket) < 0){
        return -1;
    }
    if(cm_write_uint32(size, lfp->socket) < 0){
        return -1;
    }
    return socks_send_all(lfp->buffer, lfp->buffer_size, lfp->socket);
}

PUBLIC int cm_start_reading_large_file(int socket, large_file *lfp){
    if(cm_read_uint32(&(lfp->total_size), socket) < 0){
        return -1;
    }
    lfp->socket = socket;
    return 1;
}

PUBLIC int cm_read_partof_large_file(large_file *lfp){
    int status;
    uint32_t size;
    
    status = cm_check_unexpected_error(lfp->socket);
    if(status < 0){
        return status;
    }
    
    /* read the buffer size */
    if(cm_read_uint32(&size, lfp->socket) < 0){
        return -1;
    }
    lfp->buffer_size = (uint32_t)size;
    
    if(socks_recv_all(lfp->buffer, lfp->buffer_size, lfp->socket) < 0){
        return -1;
    }
    
    lfp->total_read += lfp->buffer_size;
    return 1;
}
