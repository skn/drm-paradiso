/* this is the header file for generic methods */

#ifndef _GENERIC_H_
#define _GENERIC_H_ 1

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

/* the following definition is inspired by Andy's Minix source code,
   it enables us to only define the error_packages on one location
   instead of having one header file with it's declaration and another
   c file with its definition, see generic/def.c also */
#ifdef _DEFINE
#define DEFERROR(name, message, code) error_package name = {message, code}
#define DEFEXTERN(type, name, value) type name = value
#else /* DECLARE */
#define DEFERROR(name, message, code) extern error_package name
#define DEFEXTERN(type, name, value) extern type name
#endif

/* some definitions to enhance source code reading */
#define NULL        ((void *)0)

/* for private methods (within one file) */
#define PRIVATE
/* for public methods (between files) */
#define PUBLIC

/* for public variables within one file */
#define GLOBAL static

/* error codes */
/*
    code layout: XXCC
    XX denodes the class and CC the error code
    XX=00   generic errors
            CC=0D   generic errors
            CC=1D   socket related errors
            CC=2D   server related errors
            CC=3D   semaphore related errors
    XX=10   connection manager errors
            CC=1D   process related errors
    XX=11   provider connection manager errors

    XX=20   logic data server errors
    XX=21     "   interface server errors
    XX=22     "   data client errors
    XX=23     "   broadcast server errors
    XX=24     "   broadcast client errors

    XX=30   security manager errors
    XX=31   security manager tpm errors
    
    XX=40   data manager errors

note: in the source code normally each layer has it's own
set of error codes, so quit can possibly be called multiple
times when some error occures. In the connection manager code
however many errors created by the socks layer are returned
directly... too bad we don't have exceptions....

*/

struct _error_package{
    char *message;
    int code;
} __attribute__((__packed__));
typedef struct _error_package error_package;

/* declare global generic error variables */
DEFERROR(E_OUT_OF_MEMORY, "Program out of memory.", -1);
DEFERROR(E_FINISHED, "Process finished.", -2);

/* global indicator for errors */
DEFEXTERN(int, LAST_ERROR, 0);

/* public methods declaration */
void *allocate(size_t size);       /* allocates a chunk of memory and checks for out of memory condition */
void deallocate(void *pointer);    /* deallocates an allocated chunk of memory */
void deallocate_pp(char **ppointer, int len); /* deacllocates a pointer to a list of pointers */
int quit(error_package *error);    /* prints an error message and returns the error code */

#endif /* _GENERIC_H_ */
