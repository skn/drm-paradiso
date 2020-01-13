#include "semaphores.h"

/* Initializes and creates semaphore */
int init_semaphore(int *sem){
    key_t sem_key;
    semun sem_un;

    /* Get unique key for semaphore. */
    if((sem_key = ftok("/tmp", 'b')) == (key_t) -1){
    	return quit(&E_SEM_KEY_CREATION_FAILED);
    }

    /* register semaphore */
    *sem = semget(sem_key, 1, IPC_CREAT | IPC_EXCL | S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);
    if(sem < 0){
    	return quit(&E_SEM_CREATION_FAILED);
    }

    /* set initial state of semaphore to 1 */
    sem_un.val = 1;
    if(semctl(*sem, 0, SETVAL, sem_un) < 0){
    	return quit(&E_SEM_CTL_FAILED);
    }

    /* success */
    return 1;
}

/* Removes the semaphore */
int destroy_semaphore(int sem){
    if(semctl(sem, 0, IPC_RMID) < 0){
	   return quit(&E_SEM_DESTRUCTION_FAILED);
    }
    return 1;
}

/* Leaves the critical region */
int leave(int sem) {
    struct sembuf sem_up = {0, 1, 0};
    if(semop(sem, &sem_up, 1) < 0) {
	   return quit(&E_SEM_UP_FAILED);
    }
    return 1;
}

/* Enters the critical region */
int enter(int sem) {
    struct sembuf sem_down = {0, -1, 0};
    if(semop(sem, &sem_down, 1) < 0) {
	   return quit(&E_SEM_DOWN_FAILED);
    }
    return 1;
}
