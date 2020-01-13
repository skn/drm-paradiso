#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>

int main(int argc, char *argv[]){
    FILE *fp;
    u_int16_t length = htons(0);
    int written;

    /* open file in binary read mode */
    fp = fopen(argv[1], "wb");
    if(fp == NULL){
        return -1;
    }
    
    /* write zero to beginning of file */
    written = fwrite((char *)&length, sizeof(uint16_t), 1, fp);
    if(written != 1){
        return -1;
    }

    /* close file */
    fclose(fp);
    
    /* done */
    return 0;
}
