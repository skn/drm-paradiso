#ifndef _DATA_MANAGER_H_
#define _DATA_MANAGER_H_ 1

#include <sys/types.h>
#include <openssl/sha.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <errno.h>

#include "../generic/generic.h"
#include "../interface.h"
#include "../data.h"

#define PATH_MAXLEN 512 /* maximum length of the directory path */
#define INCRFILE_MAXLEN 5 /* maximum length of the incremental file */

/* names of directories for storage of several files */
#define SAVE_DIR_MAIN                   "data"            /* root directory to save files */
#define SAVE_DIR_KEYS                   "data/keys"       /* directory where rsa keys reside */
#define SAVE_DIR_CLF                    "data/clf"        /* directory where content license files reside */
#define SAVE_DIR_SESSIONS               "data/sessions"   /* directory where critical sessions reside */
#define SAVE_DIR_PAYM                   "data/payments"   /* directory for incoming payment messages */
#define SAVE_DIR_RESPAYM                "data/respayments"/* directory for incoming restored payment messages */
#define SAVE_DIR_CONTENT                "data/content"    /* directory where the content resides */
#define SAVE_DIR_TPM                    "data/tpm"        /* temporary directory for TPM related files */
#define SAVE_DIR_TEMP                   "data/temp"       /* directory to store temporary files */

/* file names */
#define REVOCATION_LIST_FILE            "drl.data"
/* #define CONTENT_INFO_LIST_FILE          "content.info.data" */
#define TPM_SECURED_STORAGE_FILE        "tpm.secured.storage.mem"       /* temporary for the TPM */
#define TEMP_CONTENT_FILE               "temp.content.data"             /* temporary file to store encrypted content */
#define TEMP_PLAY_FILE                  "temp.play.mp3"                 /* filename of file to play */

/* names of all key/sig files */
#define TPM_PRIVATE_KEY_FILE            "device.private.key"               /* temporary for the TPM */
#define DEVICE_PUBLIC_KEY_FILE          "device.public.key"
#define DEVICE_PKEY_SIG_FILE            "device.manufacturer.sig"
#define MANUFACTURER_PUBLIC_KEY_FILE    "manufacturer.public.key"
#define MANUFACTURER_PKEY_SIG_FILE      "manufacturer.licenseorg.sig"
#define LICENSEORG_PUBLIC_KEY_FILE      "licenseorg.public.key"

/* declare global generic error variables */
DEFERROR(E_DM_FOPEN,            "Could not open file.",                                     -4000);
DEFERROR(E_DM_FREAD,            "Could not read from file.",                                -4001);
DEFERROR(E_DM_FSEEK,            "Could not seek in file.",                                  -4002);
DEFERROR(E_DM_FWRITE,           "Could not write to file.",                                 -4003);
DEFERROR(E_DM_CWD_FAILED,       "Get current directory failed.",                            -4004);
DEFERROR(E_DM_CHDIR_FAILED,     "Change directory failed.",                                 -4005);
DEFERROR(E_DM_OPENDIR,          "Open specified directory failed.",                         -4006);
DEFERROR(E_DM_STAT,             "Get file stats failed.",                                   -4007);
DEFERROR(E_DM_INTEGER_OVERFLOW, "Integer overflow for incremental filename detected.",      -4008);
DEFERROR(E_DM_GAP_DETECTED,     "Inconsistency in filesystem, gap in incremental files.",   -4009);
DEFERROR(E_DM_UNLINK,           "Failed to unlink file.",                                   -4010);
DEFERROR(E_DM_MOVE,             "Failed to move file.",                                     -4011);
DEFERROR(E_DM_INVALID_FILENAME, "Invalied file or filename in filesystem.",                 -4012);
DEFERROR(E_DM_SET_FPOS,         "Could not go to first byte in file.",                      -4013);
DEFERROR(E_DM_FILE_NOTFOUND,    "File could not be found in incremental directory.",        -4014);
DEFERROR(E_DM_RENAME_FILE,      "File rename failed.",                                      -4015);

/* TODO (#2#): data should be stored in network order on disk, and converted when read from disk
   so there should be some layer between the file reading and writing to do that */

/* declare datatypes */

PUBLIC int dm_get_drl(revocation_list *drl);
PUBLIC int dm_write_drl(revocation_list *drl);

PUBLIC int dm_get_content_info_list(content_info_list *cilist);
PUBLIC int dm_get_session_list(interface_reply_session_list *slist);
//PUBLIC int dm_get_pkey(public_key *pkey);

PUBLIC int dm_create_file(char *filename, char *directory, int len, char *source);
PUBLIC int dm_read_file(char *filename, char *directory, int len, char *target);
PUBLIC int dm_write_file(char *filename, char *directory, int len, int offset, char *source);

PUBLIC int dm_read_custom_file(char *name, char *directory, int *len, unsigned char **buf);
PUBLIC int dm_write_custom_file(char *name, char *directory, int len, char *source);

PUBLIC int dm_write_incremental_file(char *groupname, u_int16_t index, int len, char *source);
PUBLIC int dm_read_incremental_file(char *groupname, u_int16_t index, int len, char *target);
PUBLIC int dm_count_incremental_files(char *groupname, u_int16_t *index);
PUBLIC int dm_remove_incremental_file(char *groupname, u_int16_t index);
PUBLIC int dm_search_incremental_file(char *groupname, char *startdata, int datalen, u_int16_t *index);

PUBLIC int dm_start_writing_large_incremental_file(char *groupname, u_int16_t index, large_file *lfp);
PUBLIC int dm_start_writing_large_file(char *groupname, char *filename, large_file *lfp);
PUBLIC int dm_write_partof_large_file(large_file *lfp);
PUBLIC int dm_write_partof_large_file_data(char *data, u_int32_t len, large_file *lfp);
PUBLIC int dm_start_reading_large_incremental_file(char *groupname, u_int16_t index, u_int32_t len, large_file *lfp);
PUBLIC int dm_read_partof_large_file(large_file *lfp);
PUBLIC int dm_close_large_file(large_file *lfp);

PUBLIC int dm_remove_file(char *groupname, char *filename);
PUBLIC int dm_move_to_incremental(char *groupname, char *filename, char *target_groupname, u_int16_t target_index);

#endif /* _DATA_MANAGER_H_ */
