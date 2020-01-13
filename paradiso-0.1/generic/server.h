#ifndef _SERVER_H_
#define _SERVER_H_ 1

#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>

#include "socks.h"

/* declare error packages */
DEFERROR(E_SERVER_FIRST_PROCESS_CREATION, "Start of server process failed.",       -20);
DEFERROR(E_SERVER_CREATION,               "Could not fork off server process.",    -21);
DEFERROR(E_SERVER_ACCEPT,                 "Accepting of new request failed.",      -22);
DEFERROR(E_SERVER_SERVER_CREATION,        "Start of server child process failed.", -23);
DEFERROR(E_SERVER_SETPGID,                "Setting of process group ID failed.",   -24);
DEFERROR(E_SERVER_INIT,                   "Initialize server socket failed.",      -25);

/* declare public variables */
PUBLIC int cm_server_stop(pid_t pid);
PUBLIC int cm_server_start(int port, int (*function)(int), int (*cleanup)());
PUBLIC int cm_server_udp_bcast_start(int port, int (*function)(int), int (*cleanup)());

#endif /* _CM_SERVER_H_ */
