#include "socks.h"

void socks_sig_alrm(int signo){}

/* initializes the socketaddress struct */
PRIVATE struct sockaddr_in init_sockaddr(struct in_addr addr, int port) {
	struct sockaddr_in result;

	result.sin_addr = addr;
	result.sin_port = htons(port);
	result.sin_family = AF_INET;

	return result;
}

/* gets the in_addr struct and resolves a hostname if the provided string isn't an ip address */
PRIVATE int socks_get_in_addr(char *name, struct in_addr *result){
	struct hostent *h;
	in_addr_t addr;

    /* first try if the given string is an ip-address already */
	addr = inet_addr(name);

    /* start resolving if it isn't */
	if(addr == -1) {
        if(strcmp("", name) == 0){
            h = gethostbyname("localhost");
        } else {
		    h = gethostbyname(name);
        }

        /* check for failure */
		if(h == NULL) {
            return quit(&E_SOCKS_RESOLVE);
		}

    	/* when the hostname is successfully resolved we need to copy
           the memory because gethostbyname is a real buggy function */
        memcpy(&addr, h->h_addr_list[0], 4);
	}

    /* save the ip-address to the struct and return */
	result->s_addr = addr;
	return 1;
}

/* initialize a socket to receive UDP broadcast messages */
PUBLIC int socks_udp_bcast_recv_init(int port){
	struct sockaddr_in sock_address;
	struct in_addr in_address;
	int socket_in;
	int on = 1;

    /* create the socket */
    socket_in = socket(AF_INET, SOCK_DGRAM, 0);
    if(socket_in == -1) {
		return quit(&E_SOCKS_CREATE);
    }

    /* set option so we receive broadcasted requests */
    if(setsockopt(socket_in, SOL_SOCKET, SO_BROADCAST, &on, sizeof(on))) {
		return quit(&E_SOCKS_SETOPT);
    }

	/* Initialize connection variables */
    in_address.s_addr = htonl(INADDR_BROADCAST);
    sock_address = init_sockaddr(in_address, port);

    /* bind to the specified port and address */
    if(bind(socket_in, (struct sockaddr *)&sock_address, sizeof(struct sockaddr_in)) < 0){
		return quit(&E_SOCKS_BIND);
    }

    /* return the socket */
    return socket_in;
}

/* initialize a socket to receive normal UDP messages */
PUBLIC int socks_udp_recv_init(int port){
	struct sockaddr_in sock_address;
	struct in_addr in_address;
	int socket_in;

    /* create the socket */
    socket_in = socket(AF_INET, SOCK_DGRAM, 0);
    if(socket_in == -1) {
		return quit(&E_SOCKS_CREATE);
    }

	/* Initialize connection variables */
    in_address.s_addr = htonl(INADDR_ANY);
    sock_address = init_sockaddr(in_address, port);

    /* bind to the specified port and address */
    if(bind(socket_in, (struct sockaddr *)&sock_address, sizeof(struct sockaddr_in)) < 0){
		return quit(&E_SOCKS_BIND);
    }

    /* return the socket */
    return socket_in;
}


/* initialize a socket to receive TCP connections on */
PUBLIC int socks_listen_init(int port){
	struct sockaddr_in sock_address;
	struct in_addr in_address;
	int socket_in;
	int on = 1;

    /* create the socket */
	socket_in = socket(AF_INET, SOCK_STREAM, 0);
	if(socket_in < 0){
		return quit(&E_SOCKS_CREATE);
	}
	
    /* set option to prevent bind error */
	if(setsockopt(socket_in, SOL_SOCKET, SO_REUSEADDR, (char * ) & on, sizeof (on)) < 0){
		return quit(&E_SOCKS_SETOPT);
	}

	/* Initialize connection variables */
	in_address.s_addr = htonl(INADDR_ANY);
	sock_address = init_sockaddr(in_address, port);

	/* assign a name to the socket */
	if(bind(socket_in, (struct sockaddr *)&sock_address, sizeof(struct sockaddr_in)) < 0){
		return quit(&E_SOCKS_BIND);
	}

	/* the server should start listening for requests */
	if(listen(socket_in, BACKLOG) < 0){
		close(socket_in);
		return quit(&E_SOCKS_LISTEN);
	}

    /* return the socket */
    return socket_in;
}

/* initialize a socket to initiate connections with */
PUBLIC int socks_connect_init(int port, char *target, int timeout_seconds){
    int socket_out;
	struct in_addr in_address;
	struct sockaddr_in sock_address;

    /* create the socket */
	socket_out = socket(AF_INET, SOCK_STREAM, 0);
	if(socket_out < 0){
		return quit(&E_SOCKS_CREATE);
	}

    /* initialize connection variables, possibly resolve hostname */
    if(socks_get_in_addr(target, &in_address) < 0){
        return LAST_ERROR;
    }
    
    /* initialize the socket address */
	sock_address = init_sockaddr(in_address, port);

    /* initialize the timeout */
    signal(SIGALRM, socks_sig_alrm);
    siginterrupt(SIGALRM, 1);
    alarm(timeout_seconds);

	/* Connect to server */
	if(connect(socket_out, (struct sockaddr*)&sock_address, sizeof(struct sockaddr)) < 0){
        alarm(0);
		return quit(&E_SOCKS_CONNECT);
	}
    
    alarm(0);
    
    /* did we encounter a timeout? */
    if(errno == EINTR){
        return quit(&E_SOCKS_TIMEOUT);
    }

    /* return the socket on succes */
    return socket_out;
}

/* prepare the socket to close */
PUBLIC int socks_prepare_close(int socket_io){
	char buf[BUFFER_LENGTH];
	/* read until client closes connection */
	while(read(socket_io, buf, BUFFER_LENGTH > 0)){
		/* do nothing */
	}
    return 1;
}

/* accept a request */
PUBLIC int socks_accept_request(int server_socket){
	int client_socket;
	struct sockaddr_in client_sock_address;
	socklen_t client_addrlen;

	/* accept incoming request, we should keep trying even if we are interrupted */
	client_addrlen = sizeof(struct sockaddr_in);
	do{
		client_socket = accept(server_socket, (struct sockaddr *)&client_sock_address, &client_addrlen);
	} while(client_socket == -1 && errno == EINTR);

    if(client_socket < 0){
        return quit(&E_SOCKS_ACCEPT);
    }
	return client_socket;
}

/* receives all data from the socket */
PUBLIC int socks_recv_all(char *target, int recvlen, int server_socket){
	int recv;
 	int n_bytes = 0;

	/* keep reading until an error occurs or all bytes are received */
	do{
		n_bytes += (recv = read(server_socket, target + n_bytes, recvlen - n_bytes));
	} while(n_bytes < recvlen && recv > 0);

	/* check for failure */
	if(n_bytes < recvlen || recv < 0){
		return quit(&E_SOCKS_READ_ALL);
	}

    /* finished with succes */
    return 1;
}

/* sends all specified data over the socket */
PUBLIC int socks_send_all(char *src, int srclen, int client_socket){
	int sent;
 	int n_bytes = 0;

	/* keep writing until an error occurs or all bytes are sent */
	do{
		n_bytes += (sent = write(client_socket, src + n_bytes, srclen - n_bytes));
	} while(n_bytes < srclen && sent > 0);

	/* check for failure */
	if(n_bytes < srclen || sent < 0){
		return quit(&E_SOCKS_WRITE_ALL);
	}

    /* finished with succes */
    return 1;
}



/* broadcasts one piece of data over UDP */
PUBLIC int socks_udp_send_bcast(char *src, int srclen, int port){
    struct sockaddr_in broadcast;
    struct in_addr in_address;
    int socket_out, status, on = 1;

    /* create socket */
    socket_out = socket(AF_INET, SOCK_DGRAM, 0);
    if(socket_out < 0){
        return quit(&E_SOCKS_CREATE);
    }

    /* set option so we send a broadcast */
    if(setsockopt(socket_out, SOL_SOCKET, SO_BROADCAST, &on, sizeof(on))) {
		return quit(&E_SOCKS_SETOPT);
    }

    /* set the address to broadcast */
    in_address.s_addr = htonl(INADDR_BROADCAST);
    broadcast = init_sockaddr(in_address, port);

    /* broadcast! */
    status = sendto(socket_out, src, srclen, 0, (struct sockaddr *)&broadcast, sizeof(broadcast));
    if(status == -1){
        close(socket_out);
        return quit(&E_SOCKS_BCAST);
    }

    /* close the socket */
    close(socket_out);

    /* finished with succes */
    return 1;
}

PUBLIC int socks_udp_send(char *src, int srclen, int port, char *hostname){
    struct sockaddr_in sock_address;
    struct in_addr in_address;
    int socket_out, status;

    /* create socket */
    socket_out = socket(AF_INET, SOCK_DGRAM, 0);
    if(socket_out < 0){
        return quit(&E_SOCKS_CREATE);
    }

    /* initialize connection variables, possibly resolve hostname */
    if(socks_get_in_addr(hostname, &in_address) < 0){
        return LAST_ERROR;
    }
    
    /* initialize the socket address */
	sock_address = init_sockaddr(in_address, port);

    /* now we can send the udp message */
    status = sendto(socket_out, src, srclen, 0, (struct sockaddr *)&sock_address, sizeof(sock_address));
    if(status == -1){
        close(socket_out);
        return quit(&E_SOCKS_BCAST);
    }

    /* close the socket */
    close(socket_out);

    /* finished with succes */
    return 1;
}

PUBLIC int socks_udp_recv(char *target, int recvlen, int udp_socket, struct sockaddr_in *from){
    int status;
    int fromlen;
    
    fromlen = sizeof(struct sockaddr_in);

    status = recvfrom(udp_socket, target, recvlen, 0, (struct sockaddr *)from, &fromlen);
    if(status < 0){
        if(errno == EINTR){ /* we received some signal */
            /* this is an error but quit should not be called for it */
            return -1;
        }
        return quit(&E_SOCK_RECVFROM);
    }

    /* finished with succes */
    return 1;
}
