#include "bcast_server.h"

/* the bcast server receives broadcasted messages and replies to them */

PUBLIC int bs_handle_request(int socket){
    int status;
    session sess;
    nuovo_server incoming;
    nuovo_server reply;

    /* wait for a new request */
    status = cm_recv_nuovo_server(&incoming, socket);
    if(status < 0){
        return quit(&E_BS_RECV_BCAST);
    }
printf("bs_handle_request> new BS request from %s @ %s\n", (incoming.pkey).device_name, incoming.hostname);
    /* start a new security manager session and
       validate the incoming request */
    status = sm_start_session(&sess, &(incoming.pkey));
    if(status < 0){
        /* the incoming sender is probably listed on the DRL */
        return quit(&E_BS_NOT_TRUSTED);
    }

    /* request the security manager for our public key */
    status = sm_get_public_key(&sess, &(reply.pkey));
    if(status < 0){
        return quit(&E_BS_GET_PKEY);
    }

    /* set the reply port and target
       note: the incoming nuovo_server contains the port where we should
             reply to, our reply contains our DS port so the requester can
             connect to our data server
             our hostname however is added to the connection manager on receipt
             automatically so there is no need for us to fill reply->hostname */
    reply.port = DS_PORT;

    /* reply with our nuovo_server package */
    status = cm_send_nuovo_server(&reply, &incoming);
    if(status < 0){
        return quit(&E_BS_CM_REPLY);
    }
    
    /* success */
    return 1;
}
