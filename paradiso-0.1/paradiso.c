#include "paradiso.h"

/* global variables */
GLOBAL pid_t  bs_pid, ds_pid, is_pid;

/* this method is called when the main program is signaled to exit
   and closes all child processes properly */
PRIVATE void paradiso_close(int signo) {
	printf("Server going down...\n");

	/* kill all servers */
    cm_server_stop(bs_pid);
    cm_server_stop(ds_pid);
    cm_server_stop(is_pid);

    /* close the security manager and cleanup memory */
    sm_close();
    sm_cleanup();

	/* stop running */
	exit(1);
}

int main(int argc, char *argv[]){
    /* check arguments */
    if(argc != 2){
        printf("Wrong number of arguments. Usage %s <devicename>\n", argv[0]);
        exit(0);
    }

    /* initialize the security manager so it, subsequently initializes the 
       TPM so it can buffer the public/private key information */
    if(sm_init(argv[1]) < 0){
        /* we should immediately stop when the tpm fails to initialize */
        exit(LAST_ERROR);
    }

    /* start the broadcast server (P1) */
    bs_pid = cm_server_udp_bcast_start(BCAST_PORT, bs_handle_request, sm_cleanup);
    if(ds_pid < 0){
        sm_close();
        exit(bs_pid);
    }

    /* start the data server (P2) */
    ds_pid = cm_server_start(DS_PORT, ds_handle_request, sm_cleanup);
    if(ds_pid < 0){
        cm_server_stop(bs_pid);
        sm_close();
        exit(ds_pid);
    }

    /* start the interface server (P3) */
    is_pid = cm_server_start(IS_PORT, is_handle_request, sm_cleanup);
    if(is_pid < 0){
        cm_server_stop(bs_pid);
        cm_server_stop(ds_pid);
        sm_close();
        exit(is_pid);
    }
    printf("Paradiso server %s started:\n    main process: %i\n    bcast server: %i\n    data server: %i\n    interface server: %i\n", argv[1], getpid(), bs_pid, ds_pid, is_pid);

	/* set the signal handlers for this process (P0) */
	signal(SIGQUIT, paradiso_close);
	signal(SIGINT, paradiso_close);

    /* our work is finished, so start doing 'nothing' :) */
	while(1) {
		pause();
	}

	/* the following code is never reached... */
    cm_server_stop(bs_pid);
    cm_server_stop(ds_pid);
    cm_server_stop(is_pid);
    sm_close();
}
