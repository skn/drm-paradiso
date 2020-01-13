#include "bcast_client.h"

/* the bcast client sends out a broadcast message and
   collects all replies to it */

void sig_alrm(int signo){
    /* do nothing :-) */
}

PUBLIC int bc_collect_nuovo_servers(interface_reply_scan_list *slist){
    nuovo_server request;
    nuovo_server *input_cache[MAX_NROF_BCAST_REPLIES];
    session sess;
    int status, collect_socket, cnt, input;

    /* start a new security manager session (without protection) */
    status = sm_start_internal(&sess);
    if(status < 0){
        return quit(&E_BC_START_SECURITY_MANAGER);
    }

    /* request the security manager for our public key */
    status = sm_get_public_key(&sess, &(request.pkey));
    if(status < 0){
        return quit(&E_BC_GET_PKEY);
    }

    /* set the reply port 
       note: hostname is set by the connection manager */
    request.port = COLLECT_PORT;

    /* open a udp socket so we can collect the replies */
    collect_socket = socks_udp_recv_init(COLLECT_PORT);
    if(status < 0){
        return quit(&E_BC_UDP_RECV_INIT);
    }

    /* broadcast our udp collection port */
    /*status = socks_udp_send_bcast((char *)&request, sizeof(nuovo_server), BCAST_PORT);*/
    printf("> broadcast public key '%s'\n", request.pkey.device_name);
    status = cm_bcast_nuovo_server(&request, BCAST_PORT);
    if(status < 0){
        return quit(&E_BC_BROADCAST);
    }
    
    /* now we start receiving nuovo servers */
    input = 0;

    /* loop as long as there is no timeout */
    for(;;){
        /* first check for maximum replies */
        if(input == MAX_NROF_BCAST_REPLIES){
            break; /* maximum number of replies reached */
        }

        /* reserve space for the incoming reply */
        input_cache[input] = allocate(sizeof(nuovo_server));
        if(input_cache[input] == NULL){
            /* we are probably out of memory but we can still return the results */
            break;
        }

        /* set the time out */
        signal(SIGALRM, sig_alrm);
        siginterrupt(SIGALRM, 1);
        alarm(MAX_BCAST_WAIT_SECONDS);
        /* receive the reply */
        status = cm_recv_nuovo_server(input_cache[input], collect_socket);

        /* turn off the alarm */
        alarm(0);

        if(status < 0 && errno != EINTR){
            /* we are probably out of memory but we can still return the other results */
            deallocate(input_cache[input]);
            break;
        }

        /* did we encounter a timeout? */
        if(errno == EINTR){
            deallocate(input_cache[input]);
            break;
        } else {
            /* only use the public key if it isn't ours, ignore device name */
            if(memcmp((const void *)&request + MAXLEN_DEVICENAME, (const void *)input_cache[input] + MAXLEN_DEVICENAME, sizeof(public_key) - MAXLEN_DEVICENAME) != 0){
                printf("< received public key from %s\n", ((input_cache[input])->pkey).device_name);
                /* increment counter for next iteration */
                input++;
            } else {
                deallocate(input_cache[input]);
            }
        }
    } /* forever */

    /* close udp socket */
    close(collect_socket);
    
    /* set the number of results */
    slist->len = input;

    /* check for empty list */
    if(slist->len == 0){
        slist->list = NULL;
        return 1;
    }

    /* allocate pointer memory for the results */
    slist->list = allocate(sizeof(nuovo_server *) * input);
    if(slist->list == NULL){
        /* free the cache when there is no memory left */
        for(cnt = 0; cnt < input; cnt++){
            deallocate(input_cache[cnt]);
        }
        return LAST_ERROR;
    }

    /* copy the pointers */
    for(cnt = 0; cnt < input; cnt++){
        slist->list[cnt] = input_cache[cnt];
    }

    /* done */
    return 1;
}
