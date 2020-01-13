#ifndef _SOCKS_H_
#define _SOCKS_H_ 1

#include <stdio.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>

#include "generic.h"

/* the size in bytes of the read/write buffer */
#define BUFFER_LENGTH   512

/* the maximum size the TCP queue may grow */
/* note that it is set to a static value while the maximum
   value could be read with the sysctl program */
#define BACKLOG 1024

/* declare global socket error related variables */
DEFERROR(E_SOCKS_CREATE,  "Socket creation failed.",         -10);
DEFERROR(E_SOCKS_CONNECT, "Socket connect failed.",          -11);
DEFERROR(E_SOCKS_BIND,    "Socket bind failed.",             -12);
DEFERROR(E_SOCKS_LISTEN,  "Socket listen failed.",           -13);
DEFERROR(E_SOCKS_CLOSE,   "Socket close failed.",            -14);
DEFERROR(E_SOCKS_ACCEPT,  "Socket accept failed.",           -15);
DEFERROR(E_SOCKS_SETOPT,  "Socket set option failed.",       -16);
DEFERROR(E_SOCKS_RESOLVE, "Resolving of ip-address failed.", -17);

DEFERROR(E_SOCKS_READ_ALL, "Read from socket failed.",       -18);
DEFERROR(E_SOCKS_WRITE_ALL, "Write to socket failed.",       -19);

DEFERROR(E_SOCKS_BCAST, "Write UDP broadcast message failed.", -20);
DEFERROR(E_SOCK_RECVFROM, "Could not read UDP message.",       -21);

DEFERROR(E_SOCKS_TIMEOUT, "Timeout while trying to connect.", -22);

/* public methods declaration */
PUBLIC int socks_listen_init(int port);
PUBLIC int socks_connect_init(int port, char *target, int timeout_seconds);
PUBLIC int socks_udp_bcast_recv_init(int port);
PUBLIC int socks_udp_recv_init(int port);
PUBLIC int socks_accept_request(int server_socket);
PUBLIC int socks_prepare_close(int socket_io);

PUBLIC int socks_recv_all(char *target, int recvlen, int server_socket);
PUBLIC int socks_send_all(char *src, int srclen, int client_socket);

PUBLIC int socks_udp_send_bcast(char *src, int srclen, int port);
PUBLIC int socks_udp_send(char *src, int srclen, int port, char *hostname);

PUBLIC int socks_udp_recv(char *target, int recvlen, int udp_socket, struct sockaddr_in *from);
#endif /* _SOCKS_H_ */
