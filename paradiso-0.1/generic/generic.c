/* this is the source code for generic methods */

#include <string.h>
#include <errno.h>

#include "generic.h"

#ifdef DEBUG
int allocated_memory_count = 0;
#endif

/* allocates a chunk of memory and checks for out of memory condition */
void *allocate(size_t size) {
    void *result = malloc(size);

    /* check out of memory condition */
    if(result == NULL) {
		quit(&E_OUT_OF_MEMORY);
    }
#ifdef DEBUG
    if(result != NULL) {
printf("%i> ++ allocate %i\n", getpid(), allocated_memory_count);
		/* increase number of allocated chunks only if memory is allocated */
		allocated_memory_count++;
    }
#endif
    return result;
}

/* deallocates an allocated chunk of memory */
void deallocate(void *pointer) {
    free(pointer);
#ifdef DEBUG
printf("%i> -- deallocate %i\n", getpid(), allocated_memory_count);
    /* decrease number of allocated chunks */
    allocated_memory_count--;
#endif
}

void deallocate_pp(char **ppointer, int len){
    int i;
    if(len == 0){
        return;
    }
    for(i=0; i<len; i++){
        deallocate(ppointer[i]);
    }
    deallocate(ppointer);
}

void print_layer_name(int error_id){
    error_id = -1 * error_id;
    
    if(error_id >= 4000){
        fprintf(stderr, "data manager");
    } else if(error_id >= 3100){
        fprintf(stderr, "security manager tpm");
    } else if(error_id >= 3000){
        fprintf(stderr, "security manager");
    } else if(error_id >= 2400){
        fprintf(stderr, "logic broadcast client");
    } else if(error_id >= 2300){
        fprintf(stderr, "logic broadcast server");
    } else if(error_id >= 2200){
        fprintf(stderr, "logic data client");
    } else if(error_id >= 2100){
        fprintf(stderr, "logic interface server");
    } else if(error_id >= 2000){
        fprintf(stderr, "logic data server");
    } else if(error_id >= 1100){
        fprintf(stderr, "provider connection manager");
    } else if(error_id >= 1000){
        fprintf(stderr, "connection manager");
    } else if(error_id >= 30){
        fprintf(stderr, "semaphore");
    } else if(error_id >= 20){
        fprintf(stderr, "server");
    } else if(error_id >= 10){
        fprintf(stderr, "socket");
    } else {
        fprintf(stderr, "generic");
    }
}

/* prints an error message */
int quit(error_package *error) {
    /* be sure fprintf does not destroy the errno value */
    int errsv = errno;
    char ssl_err[120];
    long e;

    /* print the message from the error package */
    fprintf(stderr, "%04i> ", getpid());
    print_layer_name(error->code);
    fprintf(stderr, " :%i: %s\n", error->code, error->message);

    /* print errno */
    if(errno != 0){
        fprintf(stderr, "      Errno: %i - ", errsv);
        fprintf(stderr, "%s\n", strerror(errsv));
    }

    /* print openssl errors */
    ERR_load_crypto_strings();
    while( (e = ERR_get_error()) != 0){
        ERR_error_string(e, ssl_err);
        printf("OPENSSL error: %s\n", ssl_err);
    }

#ifdef DEBUG
    fprintf(stderr, "%i> The number of allocated memory chunks was %d.\n", getpid(), allocated_memory_count);
#endif
    
    return (LAST_ERROR = error->code);
}
