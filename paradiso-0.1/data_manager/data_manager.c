#include "data_manager.h"

PRIVATE int dm_change_dir(char *directory){
    static int len = 0;
    static char cwd[PATH_MAXLEN];

    /* get the current working directory if this is the first call */
    if(len == 0){
        if(getcwd(cwd, PATH_MAXLEN) == NULL){
            return quit(&E_DM_CWD_FAILED);
        }
        len = strlen(cwd);
    }

    /* change directory to requested one relative to startup cwd */
    if(chdir(cwd) < 0){
        return quit(&E_DM_CHDIR_FAILED);
    }
    if(chdir(directory) < 0){
        return quit(&E_DM_CHDIR_FAILED);
    }
    return 1;
}

PUBLIC int dm_get_drl(revocation_list *drl){
    FILE *fp;
    int read, status, cnt;

    /* change to correct directory */
    status = dm_change_dir(SAVE_DIR_MAIN);
    if(status < 0){
        return status;
    }

    /* open file in binary read mode */
    fp = fopen(REVOCATION_LIST_FILE, "rb");
    if(fp == NULL){
        return quit(&E_DM_FOPEN);
    }

    /* read the nr of items */
    read = fread((char *)&(drl->len), sizeof(u_int16_t), 1, fp);
    if(read != 1){
        fclose(fp);
        return quit(&E_DM_FREAD);
    }

    /* check for empty list */
    if(drl->len == 0){
        drl->revoked_keys = NULL;
        return 1;
    }

    /* allocate memory for the pointers */
    drl->revoked_keys = allocate(drl->len);
    if(drl->revoked_keys == NULL){
        fclose(fp);
        return LAST_ERROR;
    }
    
    /* read the keys from the file */
    for(cnt = 0; cnt < drl->len; cnt++){
        /* allocate memory for the key */
        drl->revoked_keys[cnt] = allocate(RSA_PKEY_RAW_LENGTH);
        if(drl->revoked_keys[cnt] == NULL){
            fclose(fp);
            deallocate_pp(drl->revoked_keys, cnt);
            return LAST_ERROR;
        }
        
        /* read from the file */
        read = fread(drl->revoked_keys[cnt], sizeof(unsigned char), RSA_PKEY_RAW_LENGTH, fp);
        if(read != RSA_PKEY_RAW_LENGTH){
            fclose(fp);
            deallocate_pp(drl->revoked_keys, cnt + 1);
            return quit(&E_DM_FREAD);
        }
    }

    /* read the remaining data from the file */
    read = fread(drl->signature, sizeof(unsigned char), RSA_SHA1_SIGLEN + sizeof(public_key), fp);
    if(read != (RSA_SHA1_SIGLEN + sizeof(public_key))){
        fclose(fp);
        deallocate_pp(drl->revoked_keys, cnt);
        return quit(&E_DM_FREAD);
    }

    /* close file and return */
    fclose(fp);
    return 1;
}
PUBLIC int dm_write_drl(revocation_list *drl){
    FILE *fp;
    int written, cnt, status;

    /* change to correct directory */
    status = dm_change_dir(SAVE_DIR_MAIN);
    if(status < 0){
        return status;
    }

    /* truncate and create file in binary mode */
    fp = fopen(REVOCATION_LIST_FILE, "wb");
    if(fp == NULL){
        return quit(&E_DM_FOPEN);
    }

    /* write nr of items to the file */
    written = fwrite((char *)&(drl->len), sizeof(u_int16_t), 1, fp);
    if(written != 1){
        fclose(fp);
        return quit(&E_DM_FWRITE);
    }

    /* write the keys to the file */
    for(cnt = 0; cnt < drl->len; cnt++){
        written = fwrite(drl->revoked_keys[cnt], sizeof(unsigned char), RSA_PKEY_RAW_LENGTH, fp);
        if(written != RSA_PKEY_RAW_LENGTH){
            fclose(fp);
            return quit(&E_DM_FWRITE);
        }
    }
    
    /* write the rest */
    written = fwrite(drl->signature, sizeof(unsigned char), RSA_SHA1_SIGLEN + sizeof(public_key), fp);
    if(written != (RSA_SHA1_SIGLEN + sizeof(public_key))){
        fclose(fp);
        return quit(&E_DM_FWRITE);
    }
    
    /* close file and return */
    fclose(fp);
    return 1;
}

/* read a content info list from disk */
PRIVATE int dm_read_directory_to_list(char ***list, uint16_t *listlen, size_t partlen, char *directory){
    FILE *fp;
    DIR *dp;
    struct dirent *file;
    struct stat fstat;
    int status, read, cur, resvlen;
    uint16_t len;
    char *tempbuf_p;
    char **tempbuf_pp;

    /* change to correct directory */
    status = dm_change_dir(directory);
    if(status < 0){
        return status;
    }

    /* count the number of files */
    status = dm_count_incremental_files(directory, &len);
    if(status < 0){
        return LAST_ERROR;
    }
    
    /* check for empty list */
    if(len == 0){
        *listlen = 0;
        return 1;
    }
    *listlen = len;

    /* allocate the correct amount of memory for the pointers */
    resvlen = (int)(sizeof(char **) * len);
    tempbuf_pp = (char **)allocate(resvlen);
    if(tempbuf_pp == NULL){
        return LAST_ERROR;
    }
    
    /* open the directory */
    dp = opendir(".");
    if(dp == NULL){
        deallocate(tempbuf_pp);
        return quit(&E_DM_OPENDIR);
    }
    
    /* iterate over all files in the directory, order doesn't matter */
    cur = 0;
    while((file = readdir(dp)) != NULL){
        /* get file stat to check for normal file */
        if(stat(file->d_name, &fstat)!=0){
            closedir(dp);
            deallocate(tempbuf_pp);
            return quit(&E_DM_STAT);
        }
        if(S_ISREG(fstat.st_mode)){
            /* open the file for reading binary */
            fp = fopen(file->d_name, "rb");
            if(fp == NULL){
                closedir(dp);
                deallocate_pp(tempbuf_pp, cur);
                return quit(&E_DM_FOPEN);
            }

            /* allocate memory for the open_session */
            tempbuf_p = (char *)allocate(partlen);
            tempbuf_pp[cur] = tempbuf_p;
            if(tempbuf_p == NULL){
                deallocate_pp(tempbuf_pp, cur);
                fclose(fp);
                closedir(dp);
                return LAST_ERROR;
            }

            /* read the file data block of partlen */
            read = fread(tempbuf_p, partlen, 1, fp);
            if(read != 1){
                deallocate_pp(tempbuf_pp, cur + 1);
                fclose(fp);
                closedir(dp);
                return quit(&E_DM_FREAD);
            }

            /* close the file */
            fclose(fp);
            cur++;
        }
    }

    /* set the result pointer */
    *list = tempbuf_pp;

    /* close dir and return */
    closedir(dp);
    return 1;
}

PUBLIC int dm_get_content_info_list(content_info_list *cilist){
    char **temp;
    int status;

    status = dm_read_directory_to_list((char ***)&temp, &(cilist->len), sizeof(content_info), SAVE_DIR_CLF);
    cilist->list = (content_info **)temp;
    
    return status;
}

PUBLIC int dm_get_session_list(interface_reply_session_list *slist){
    char **temp;
    int status;

    status = dm_read_directory_to_list((char ***)&temp, &(slist->len), sizeof(open_session), SAVE_DIR_SESSIONS);
    slist->list = (open_session **)temp;
    
    return status;
}

/*PUBLIC int dm_get_pkey(public_key *pkey){
    int len, status;
    char *buf;

    status = dm_change_dir(SAVE_DIR_KEYS);
    if(status < 0){
        return status;
    }

    status = dm_read_custom_file(DEVICE_PUBLIC_KEY_FILE, SAVE_DIR_KEYS, &len, &buf);
    if(ERROR_OCCURED < 0){
        return ERROR_OCCURED;
    }
    if(len != RSA_PKEY_RAW_LENGTH){
        return quit(&E_DM_PKEY_CORRUPTED);
    }
    pkey->device_pkey = buf;
}*/

PUBLIC int dm_create_file(char *filename, char *directory, int len, char *source){
    FILE *fp;
    int written, status;

    /* change to correct directory */
    status = dm_change_dir(directory);
    if(status < 0){
        return status;
    }

    /* truncate or create file in binary mode */
    fp = fopen(filename, "wb");
    if(fp == NULL){
        return quit(&E_DM_FOPEN);
    }

    /* write the data to the file */
    written = fwrite(source, sizeof(unsigned char), len, fp);
    if(written != len){
        return quit(&E_DM_FWRITE);
    }
    
    /* close file and return */
    fclose(fp);
    return 1;
}

/* writes len bytes from source to file name starting at location offset
   and creates the file if it does not exists */
PUBLIC int dm_read_file(char *filename, char *directory, int len, char *target){
    FILE *fp;
    int read, status;

    /* change to correct directory */
    status = dm_change_dir(directory);
    if(status < 0){
        return status;
    }

    /* open file in binary read mode */
    fp = fopen(filename, "rb");
    if(fp == NULL){
        return quit(&E_DM_FOPEN);
    }

    /* read the data from the file */
    read = fread(target, sizeof(unsigned char), len, fp);
    if(read != len){
        return quit(&E_DM_FREAD);
    }
    
    /* close file and return */
    fclose(fp);
    return 1;
}

/* writes len bytes from source to file name starting at location offset
   and creates the file if it does not exist */
PUBLIC int dm_write_file(char *name, char *directory, int len, int offset, char *source){
    FILE *fp;
    int written, status;

    /* change to correct directory */
    status = dm_change_dir(directory);
    if(status < 0){
        return status;
    }

    /* open file for appending in binary mode */
    fp = fopen(name, "ab");
    if(fp == NULL){
        return quit(&E_DM_FOPEN);
    }

    /* go to the correct position in the file */
    if(fseek(fp, offset, SEEK_SET) != 0){
        return quit(&E_DM_FSEEK);
    }

    /* write the data to the file */
    written = fwrite(source, sizeof(unsigned char), len, fp);
    if(written != len){
        return quit(&E_DM_FWRITE);
    }
    
    /* close file and return */
    fclose(fp);
    return 1;
}

/* reads file name and writes len bytes to buf, assumes the file is
   written in our custom format, where the data length precedes the
   actual data */
PUBLIC int dm_read_custom_file(char *name, char *directory, int *len, unsigned char **buf){
    FILE *fp;
    int read, status;
    uint16_t size;

    /* for some reason we need this temporary buffer
       otherwise The Neuros gives an segmentation fault on
       fread, while my normal linux computer just runs without problems */
    unsigned char *tempbuf;

    /* change to correct directory */
    status = dm_change_dir(directory);
    if(status < 0){
        return status;
    }

    /* open file in binary read mode */
    fp = fopen(name, "rb");
    if(fp == NULL){
        return quit(&E_DM_FOPEN);
    }

    /* read the size and convert to host order */
    read = fread((char *)&size, sizeof(uint16_t), 1, fp);
    if(read != 1){
        return quit(&E_DM_FREAD);
    }
    *len = ntohs(size);

    /* allocate the memory */
    tempbuf = allocate(*len);
    if(tempbuf == NULL){
        return LAST_ERROR;
    }

    /* read the data from the file */
    read = fread(tempbuf, sizeof(unsigned char), *len, fp);
    if(read != *len){
        return quit(&E_DM_FREAD);
    }

    *buf = tempbuf;

    /* close file and return */
    fclose(fp);
    return 1;
}

/* writes len bytes from source to file name, and creates the
   file if it does not exists, it writes the file in our custom
   format in which the data size precedes the data */
PUBLIC int dm_write_custom_file(char *name, char *directory, int len, char *source){
    FILE *fp;
    int status, written;
    uint16_t size;

    /* change to correct directory */
    status = dm_change_dir(directory);
    if(status < 0){
        return status;
    }

    /* truncate and create file in binary mode */
    fp = fopen(name, "wb");
    if(fp == NULL){
        return quit(&E_DM_FOPEN);
    }

    /* write the size in network order to the file */
    size = htons(len);
    written = fwrite((char *)&size, sizeof(uint16_t), 1, fp);

    if(written != 1){
        return quit(&E_DM_FWRITE);
    }

    /* write the data to the file */
    written = fwrite(source, sizeof(unsigned char), len, fp);
    if(written != len){
        return quit(&E_DM_FWRITE);
    }
    
    /* close file and return */
    fclose(fp);
    return 1;
}

/* if someone calls the method dm_count_incremental_files and subsequently
   calls write then he should prevent collision between processes by using
   a semaphore for example, or file locking... */
PRIVATE void dm_get_incremental_filename(u_int16_t index, char *filename){
    char format[5];

    /* first set the correct 0-padding length for the filename format */
    snprintf(format, 5, "%%0%ii", INCRFILE_MAXLEN-1);

    /* now create the filename from the given index */
    snprintf(filename, INCRFILE_MAXLEN, format, index);
}

/* write incremental file 'index', overwrites the file entirely if it exists already */
PUBLIC int dm_write_incremental_file(char *groupname, u_int16_t index, int len, char *source){
    char filename[INCRFILE_MAXLEN];

    /* get the filename */
    dm_get_incremental_filename(index, (char *)filename);

    /* write the source to the incremental file */
    if(dm_create_file(filename, groupname, len, source) < 0){
        return LAST_ERROR;
    }

    /* return success */
    return 1;
}

/* reads len bytes to target from incremental file index */
PUBLIC int dm_read_incremental_file(char *groupname, u_int16_t index, int len, char *target){
    char filename[INCRFILE_MAXLEN];

    /* get the filename */
    dm_get_incremental_filename(index, (char *)filename);

    /* read from the file */
    if(dm_read_file(filename, groupname, len, target) < 0){
        return LAST_ERROR;
    }

    /* return success */
    return 1;
}

/* count the number of incremental files in a certain directory, checks also for inconsistency */
PUBLIC int dm_count_incremental_files(char *groupname, u_int16_t *index){
    DIR *dp;
    struct dirent *file;
    struct stat fstat;
    int status;
    long num_files;
    u_int16_t index_cur, index_buf;

    /* in case something fails we set index to 0 */
    *index = 0;

    /* change to correct directory */
    status = dm_change_dir(groupname);
    if(status < 0){
        return status;
    }
    
    /* open the directory */
    dp = opendir(".");
    if(dp == NULL){
        return quit(&E_DM_OPENDIR);
    }
    
    /* iterate over all files in the directory, order doesn't matter */
    index_buf = 0;
    num_files = 0;
    while((file = readdir(dp)) != NULL){
        /* is it a file? */
        if(stat(file->d_name, &fstat)!=0){
            closedir(dp);
            return quit(&E_DM_STAT);
        }
        if(S_ISREG(fstat.st_mode)){
            /* get the largest filename */
            index_cur = (u_int16_t)strtol(file->d_name, (char **)NULL, 10);
            index_buf = (index_cur > index_buf) ? index_cur : index_buf;

            /* keep track of the total number of files */
            num_files++;
        }
    }

    /* close dir */
    closedir(dp);

    /* if there are no files then we can immediately return, index is still set to 0 */
    if(num_files == 0){
        return 1;
    }

    /* check if there are so much files that we exceeded the integer limit */
    if( (num_files - 1) == ULONG_MAX){
        return quit(&E_DM_INTEGER_OVERFLOW);
    }

    /* check if the total number of files corresponds with the highest index, there's a gap otherwise */
    if( (num_files - 1) != index_buf){
        return quit(&E_DM_GAP_DETECTED);
    }

    index_buf += 1;
    *index = index_buf;

    /* return success */
    return 1;
}

/* remove an incremental file, make sure this method is called in a critical region
   note: the file with the largest index will be moved over the file to be removed */
PUBLIC int dm_remove_incremental_file(char *groupname, u_int16_t index){
    u_int16_t index_last;
    char filename[INCRFILE_MAXLEN];
    char filename_last[INCRFILE_MAXLEN];
  
    /* first get the the highest index */
    if(dm_count_incremental_files(groupname, &index_last) < 0){
        return LAST_ERROR;
    }

    /* get the filename */
    dm_get_incremental_filename(index, (char *)filename);  

    /* check if the highest indexed file should be removed, no moving is needed then */
    if( (index_last - 1) == index){
        if(unlink(filename) != 0){
            return quit(&E_DM_UNLINK);
        }
        return 1; /* success */
    }

    /* get the highest indexed filename */
    dm_get_incremental_filename(index_last, (char *)filename_last);  

    /* overwrite the file to be removed with the highest indexed file */
    if(rename(filename, filename_last) != 0){
        return quit(&E_DM_MOVE);
    }

    /* success */
    return 1;
}

/* searches for a incremental file which starts with the given startdata */
PUBLIC int dm_search_incremental_file(char *groupname, char *startdata, int datalen, u_int16_t *index){
    FILE *fp;
    DIR *dp;
    struct dirent *file;
    struct stat fstat;
    int status, read, cur;
    unsigned char buffer[datalen];

    /* change to correct directory */
    status = dm_change_dir(groupname);
    if(status < 0){
        return status;
    }
    
    /* open the directory */
    dp = opendir(".");
    if(dp == NULL){
        return quit(&E_DM_OPENDIR);
    }
    
//printf("dm_search_incremental_file> start: %03i %03i %03i %03i %03i %03i %03i %03i %03i %03i\n", startdata[0], startdata[1], startdata[2], startdata[3], startdata[4], startdata[5], startdata[6], startdata[7], startdata[8], startdata[9]);
    /* iterate over all files in the directory, order doesn't matter */
    cur = 0;
    while((file = readdir(dp)) != NULL){
        /* is it a file? */
        if(stat(file->d_name, &fstat)!=0){
            closedir(dp);
            return quit(&E_DM_STAT);
        }
        if(S_ISREG(fstat.st_mode)){
            /* open the file for reading binary */
            fp = fopen(file->d_name, "rb");
            if(fp == NULL){
                closedir(dp);
                return quit(&E_DM_FOPEN);
            }

            /* read the first datalen bytes from the file */
            read = fread(&buffer, sizeof(unsigned char), datalen, fp);
            if(read != datalen){
                fclose(fp);
                closedir(dp);
                return quit(&E_DM_FREAD);
            }

            /* close the file */
            fclose(fp);
//printf("dm_search_incremental_file> %s: %03i %03i %03i %03i %03i %03i %03i %03i %03i %03i\n", file->d_name, buffer[0], buffer[1], buffer[2], buffer[3], buffer[4], buffer[5], buffer[6], buffer[7], buffer[8], buffer[9]);

            /* compare the data and return index if match */
            if(memcmp((const void *)buffer, (const void *)startdata, datalen) == 0){
                closedir(dp);
                *index = (u_int16_t)strtol(file->d_name, (char **)NULL, 10);
                if(errno == ERANGE){
                    return quit(&E_DM_INVALID_FILENAME);
                }
                return 1;
            }
        }
    }

    /* close dir and return failure */
    closedir(dp);
    return quit(&E_DM_FILE_NOTFOUND);
}

/* this method opens a large file and sets the lfp accordingly */
PUBLIC int dm_start_writing_large_incremental_file(char *groupname, u_int16_t index, large_file *lfp){
    int status;
    char filename[INCRFILE_MAXLEN];

    /* change to correct directory */
    status = dm_change_dir(groupname);
    if(status < 0){
        return status;
    }

    /* get the filename */
    dm_get_incremental_filename(index, (char *)filename);  

    /* truncate or create file in binary mode */
    lfp->fp = fopen(filename, "wb");
    if(lfp->fp == NULL){
        return quit(&E_DM_FOPEN);
    }
    return 1;
}

PUBLIC int dm_start_writing_large_file(char *groupname, char *filename, large_file *lfp){
    int status;

    /* change to correct directory */
    status = dm_change_dir(groupname);
    if(status < 0){
        return status;
    }

    /* truncate or create file in binary mode */
    lfp->fp = fopen(filename, "wb");
    if(lfp->fp == NULL){
        return quit(&E_DM_FOPEN);
    }
    return 1;
}

/* this method writes the data stored in lfp to the file */
PUBLIC int dm_write_partof_large_file(large_file *lfp){
    int written;
    
    /* write the data to the file */
    written = fwrite(lfp->buffer, sizeof(unsigned char), lfp->buffer_size, lfp->fp);
    if(written != lfp->buffer_size){
        return quit(&E_DM_FWRITE);
    }
    return 1;
}

PUBLIC int dm_write_partof_large_file_data(char *data, u_int32_t len, large_file *lfp){
    int written;
    /* write the data to the file */
    written = fwrite(data, sizeof(unsigned char), len, lfp->fp);
    if(written != len){
        return quit(&E_DM_FWRITE);
    }
    return 1;
}

/* this method opens a large file to be read from disk */
PUBLIC int dm_start_reading_large_incremental_file(char *groupname, u_int16_t index, u_int32_t len, large_file *lfp){
    int status;
    char filename[INCRFILE_MAXLEN];
    
    /* change to correct directory */
    status = dm_change_dir(groupname);
    if(status < 0){
        return status;
    }

    /* get the filename */
    dm_get_incremental_filename(index, (char *)filename);  

    /* open file in binary read mode */
    lfp->fp = fopen(filename, "rb");
    if(lfp->fp == NULL){
        return quit(&E_DM_FOPEN);
    }
    lfp->total_size = len;
    lfp->buffer_size = lfp->total_read = 0;
    return 1;
}

/* this method reads a new block of data from the large file */
PUBLIC int dm_read_partof_large_file(large_file *lfp){
    /* read the data from the file */
    lfp->total_read += (lfp->buffer_size = fread(lfp->buffer, sizeof(unsigned char), SIZE_READ_BUFFER, lfp->fp));
    if((lfp->buffer_size != SIZE_READ_BUFFER) && (lfp->total_read != lfp->total_size)){
        return quit(&E_DM_FREAD);
    }
    return 1;
}

/* this method closes a opened large file */
PUBLIC int dm_close_large_file(large_file *lfp){
    fclose(lfp->fp);
    return 1;
}

PUBLIC int dm_remove_file(char *groupname, char *filename){
    int status;
    
    /* change to correct directory */
    status = dm_change_dir(groupname);
    if(status < 0){
        return status;
    }
    
    /* remove the file */
    if(unlink(filename) != 0){
        return quit(&E_DM_UNLINK);
    }
    return 1;
}

PUBLIC int dm_move_to_incremental(char *groupname, char *filename, char *target_groupname, u_int16_t target_index){
    int status;
    char new_filename[INCRFILE_MAXLEN];
    char targetname[PATH_MAXLEN];
        
    /* change to correct directory */
    status = dm_change_dir(groupname);
    if(status < 0){
        return status;
    }
    
    /* get the filename */
    dm_get_incremental_filename(target_index, (char *)new_filename);
    
    /* create the targetname string */
    snprintf(targetname, PATH_MAXLEN, "../../%s/%s", target_groupname, new_filename);

    /* move the file */
    if(rename(filename, targetname) == -1){
        return quit(&E_DM_RENAME_FILE);
    }
    
    return 1;
}

