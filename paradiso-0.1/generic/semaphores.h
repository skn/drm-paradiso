#ifndef _SEMAPHORES_H_
#define _SEMAPHORES_H_ 1

#include <stdio.h>
#include <stdlib.h>

#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/sem.h>

#include <sys/stat.h>
#include <sys/wait.h>

#include "generic.h"

/* declare sem union which is used to store semaphore data */
#if defined(__GNU_LIBRARY__) && !defined(_SEM_SEMUN_UNDEFINED)
/* union semun is defined by including <sys/sem.h> */
#else
/* according to X/OPEN we have to define it ourselves */
typedef union semun {
    int val;                  /* value for SETVAL */
    struct semid_ds *buf;     /* buffer for IPC_STAT, IPC_SET */
    unsigned short *array;    /* array for GETALL, SETALL */
                              /* Linux specific part: */
    struct seminfo *__buf;    /* buffer for IPC_INFO */
} semun;
#endif

DEFERROR(E_SEM_KEY_CREATION_FAILED,     "Could not create key identifier for semaphore.",  -30);
DEFERROR(E_SEM_CREATION_FAILED,         "Could not create semaphore.",                     -31);
DEFERROR(E_SEM_CTL_FAILED,              "Could not initialize semaphore.",                 -32);
DEFERROR(E_SEM_DESTRUCTION_FAILED,      "Could not destroy semaphore.",                    -33);
DEFERROR(E_SEM_UP_FAILED,               "Could not perform up operation on semaphore.",    -34);
DEFERROR(E_SEM_DOWN_FAILED,             "Could not perform down operation on semaphore.",  -35);

int init_semaphore(int *sem);
int destroy_semaphore(int sem);
int enter(int sem);
int leave(int sem);

#endif /* _SEMAPHORES_H_ */
