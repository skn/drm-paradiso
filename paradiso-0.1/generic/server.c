#include "server.h"

/* declaration of global variables */
GLOBAL int server_socket;                 /* the server socket for incoming connections */
GLOBAL int process_count;                 /* total number of running processes */
GLOBAL int server_pid;                    /* pid of the server process */
GLOBAL int (*function_cleanup)();         /* method to be called when process exits */

/* this method is called when a child of the server process dies or exits */
PRIVATE void cm_server_sigchld(int signo) {
    /* we first wait for the child(s) to properly die */
	while(waitpid(0, NULL, WNOHANG) > 0) {
		/* just waiting for child to die */
	}

    /* re-setting not needed for linux but added for backwards compatibility */
    signal(SIGCHLD, cm_server_sigchld);

    /* now we clean up our process count
        note: this is non-critical code because
        it is only executed by the parent process */
    if(SA_SIGINFO != CLD_CONTINUED || SA_SIGINFO != CLD_STOPPED){
        process_count--;
    }
}

/* close the data server process */
PRIVATE void cm_server_sigquit(int signo){
    /* signal all children in the same process group to die */
    kill(0, SIGQUIT);

    /* clean up children */
	while(waitpid(0, NULL, WNOHANG) > 0) {
		/* just waiting for child to die */
	}

    /* cleanup all memory */
    function_cleanup();
    
    /* now close the socket and exit */
    close(server_socket);

    exit(1);
}

/* this method forks a new process to handle the supplied request */
PRIVATE int cm_server_fork_request(int request_socket, int (*function)(int)){
    pid_t pid;
    int status;

    /* create new process to handle the request */
    pid = fork();
	if(pid < 0){
        /* some forking error occured */
		return quit(&E_SERVER_CREATION);
	}
	else if(pid != 0) { /* parent process */
        /* forking succeeded, increment process count */
        process_count++;

        /* return to accept more requests */
        return 1;
    }

    /* handle the request */
    status = function(request_socket);

    /* try to read the client call to close */
    socks_prepare_close(request_socket);

    /* ready so cleanup and exit */
    function_cleanup();
    close(request_socket);

    exit(status);
}

/* start accepting server requests, one new process is forked for each request */
PRIVATE int cm_server_accept_request(int (*function)(int)){
    int status;
    int request_socket; /* the incoming request */
    
    /* accept new request on server socket */
    request_socket = socks_accept_request(server_socket);

	/* check for failure */
	if(request_socket < 0){
		return quit(&E_SERVER_ACCEPT);
	}

    /* fork off a new process to handle the request */
    status = cm_server_fork_request(request_socket, function);

    /* the parent should clean-up the socket */
    close(request_socket);
    
    /* return the possible failure */
    return status;
}

/* starts a server process on a specified port which forks off
   new processes who start computing the supplied method
   RETURNS: pid of new server process */
PUBLIC int cm_server_start(int port, int (*function)(int), int (*cleanup)()){
    int pid;

    /* fork a new process for the server */
    pid = fork();
	if(pid < 0){
        /* some forking error occured, stop the server */
		return quit(&E_SERVER_FIRST_PROCESS_CREATION);
	}
	else if(pid != 0) { /* parent process */
        /* forking succeeded, return the pid of the new process */
        return pid;
    }

    /* the new server process stores his pid */
    server_pid = getpid();

    /* we set the process group ID to ours so we can easily signal all children */
    if(setpgid(0, 0) < 0){
        return quit(&E_SERVER_SETPGID);
    }

    /* now the new server process initializes the socket */
    server_socket = socks_listen_init(port);
    if(server_socket < 0){
        /* initialize socket failed */
        return quit(&E_SERVER_INIT);
    }

    /* set the trash handler */
    function_cleanup = cleanup;

    /* set correct signal handlers */
    signal(SIGCHLD, cm_server_sigchld);
    signal(SIGQUIT, cm_server_sigquit);
	signal(SIGINT, NULL);

    /* and starts accepting new requests forever and ever and ever and ... */
    for(;;){
        cm_server_accept_request(function);
        /* no error checking needed because this method may fail */
    }
}

/* starts a server which is able to receive broadcasted requests
   on a specified port and calls the handler for each incoming
   request (so it does not fork to handle requests)
   RETURNS: pid of new broadcast server process */
PUBLIC int cm_server_udp_bcast_start(int port, int (*function)(int), int (*cleanup)()){
    int pid;

    /* fork a new process for the broadcast server */
    pid = fork();
	if(pid < 0){
        /* some forking error occured, stop the server */
		return quit(&E_SERVER_FIRST_PROCESS_CREATION);
	}
	else if(pid != 0) { /* parent process */
        /* forking succeeded, return the pid of the new process */
        return pid;
    }

    /* the new broadcast server process stores his pid */
    server_pid = getpid();

    /* we set the process group ID to ours so we can easily signal all children */
    if(setpgid(0, 0) < 0){
        return quit(&E_SERVER_SETPGID);
    }

    /* now the new broadcast server process initializes the socket */
    server_socket = socks_udp_bcast_recv_init(port);
    if(server_socket < 0){
        /* initialize socket failed */
        return quit(&E_SERVER_INIT);
    }

    /* set the trash handler */
    function_cleanup = cleanup;

    /* set correct signal handlers */
    signal(SIGCHLD, cm_server_sigchld);
    signal(SIGQUIT, cm_server_sigquit);
	signal(SIGINT, NULL);

    /* and starts handling broadcasted requests forever and ever and ever and ... */
    for(;;){
        function(server_socket);
        /* no error checking needed because this method may fail */
    }
}

/* stop the data server */
PUBLIC int cm_server_stop(pid_t pid){
    /* signal the server process to die */
    kill(pid, SIGQUIT);

    /* cleanup the process */
	while(waitpid(pid, NULL, WNOHANG) > 0 ){
		/* just waiting for the process to die */
	}
    
    return 1;
}

/* create semaphore */
//sem = init_semaphore();

/* destroy our semaphore */
//destroy_semaphore(sem);
