#ifndef _BCAST_SERVER_H_
#define _BCAST_SERVER_H_ 1

#include "../security_manager/security_manager.h"
#include "../connection_manager/connection_manager.h"
#include "data_server.h"

DEFERROR(E_BS_RECV_BCAST,   "Could not receive broadcast message.",                    -2300);
DEFERROR(E_BS_NOT_TRUSTED,  "Received broadcast message from non-trustable provider.", -2301);
DEFERROR(E_BS_GET_PKEY,     "Could not get public key from security manager.",         -2302);
DEFERROR(E_BS_CM_REPLY,     "Sending reply to broadcast message failed.",              -2303);

PUBLIC int bs_handle_request(int socket);

#endif /* _BCAST_SERVER_H_ */
