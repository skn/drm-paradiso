#ifndef _BCAST_CLIENT_H_
#define _BCAST_CLIENT_H_ 1

#include "../security_manager/security_manager.h"
#include "../connection_manager/connection_manager.h"
#include <signal.h>

/* ports used to broadcast on and to reply on */
#define BCAST_PORT 9000
#define COLLECT_PORT 9090

#define MAX_NROF_BCAST_REPLIES 64    /* maximum number of broadcast replies we can receive */
#define MAX_BCAST_WAIT_SECONDS 1     /* maximum number of seconds to wait for broadcast replies */

DEFERROR(E_BC_START_SECURITY_MANAGER, "Could not initialize security manager.",          -2400);
DEFERROR(E_BC_GET_PKEY,               "Could not get public key from security manager.", -2401);
DEFERROR(E_BC_UDP_RECV_INIT,          "Could not initialize the udp collect socket.",    -2402);
DEFERROR(E_BC_BROADCAST,              "Could not broadcast the message.",                -2403);

PUBLIC int bc_collect_nuovo_servers(interface_reply_scan_list *slist);

#endif /* _BCAST_CLIENT_H_ */
