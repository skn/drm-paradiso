#include "generic/generic.h"
#include "generic/socks.h"
#include "connection_manager/connection_manager.h"
#include "logic/data_server.h"
#include "logic/interface_server.h"
#include "interface.h"

#include <fcntl.h>
#include <math.h>

#define MAX_COMMAND_LENGTH 128
#define TIMEOUT_SECONDS 5

int connection;
char *hostname;
nuovo_server localserver;

int start_read_file(char *filename, large_file *lfp){
    int fd;
    struct stat buf;
        
    fd = open(filename, O_RDONLY);
    if(fd == -1){
        printf("     > could not find file\n");
        return -1;
    }
    if(fstat(fd, &buf)!=0){
        close(fd);
        printf("     > could not stat file\n");
        return -1;
    }
    lfp->total_size = buf.st_size;
    close(fd);
    
    printf("     > filesize: %i, start reading now\n", lfp->total_size);

    /* open file in binary read mode */
    lfp->fp = fopen(filename, "rb");
    if(lfp->fp == NULL){
        printf("     > could not open file\n");
        return -1;
    }
    
    lfp->buffer_size = lfp->total_read = 0;
    
    /* the lfp is ready */
    return 1;
}

int read_partof_file(large_file *lfp){
    lfp->total_read += (lfp->buffer_size = fread(lfp->buffer, sizeof(unsigned char), SIZE_READ_BUFFER, lfp->fp));
    if(lfp->buffer_size != SIZE_READ_BUFFER && lfp->total_read != lfp->total_size){
        fclose(lfp->fp);
        printf("     > error reading file at %i\n", lfp->total_read);
        return -1;
    }
    
    /* close the file pointer if needed */
    if(lfp->total_read == lfp->total_size){
        fclose(lfp->fp);
    }
    return 1;
}

int read_command(char *command, int *command_length) {
	unsigned char c;
	*command_length = 0;
	
	/* read line */
	while((c = getchar()) != '\n') {
        if((unsigned int)c != 255){
    		command[(*command_length)++] = (char)c;
    		
    		/* check command length */
    		if(*command_length >= MAX_COMMAND_LENGTH) {
    			printf("Command too large\n");
                return -1;
    		}
        }
	}
	
	/* insert string terminator */
	command[*command_length] = '\0';
    return 1;
}

int content_rights(rights *old, rights *result){
    char count[MAX_COMMAND_LENGTH];
/*    char price[MAX_COMMAND_LENGTH];*/
    int len;
    
    printf("     > what resell count do you want? (max %i)\n", old->resell_count);
    if(read_command(count, &len) < 0){
        return -1;
    }
 /*   printf("     > what do you want to pay for the content in cents? (min %i)\n", old->price);
    if(read_command(price, &len) < 0){
        return -1;
    }*/

    result->resell_count = strtol(count, (char **)NULL, 10);
    result->resell_depth = old->resell_depth - 1;
    result->resell_total = old->resell_total;
    result->price = old->price; //strtol(price, (char **)NULL, 10);

    return 1;
}

void perform_get(nuovo_server *target, content_info *cinfo){
    interface_request_get request;
    int status;
    
    /* copy data to the interface struct */
    if(memcpy(&(request.info), cinfo, sizeof(content_info)) == NULL){
        printf("     > could not copy content info\n");
        return;
    }
    if(memcpy(&(request.request_at), target, sizeof(nuovo_server)) == NULL){
        printf("     > could not copy target data\n");
        return;
    }
    
    /* ask user for rights */
    if(content_rights( &(cinfo->content_rights), &(request.info.content_rights) ) < 0){
        return;
    }
    
    connection = socks_connect_init(IS_PORT, hostname, TIMEOUT_SECONDS);
    if(connection < 0){
        printf("     > could not connect to nuovo server\n");
        return;
    }

    uint16_t request_type = IS_REQUEST_GET;
    if(cm_write_uint16(request_type, connection) < 0){
        printf("     > could not write command\n");
        close(connection);
        return;
    }
    status = cm_write_request_get(&request, connection);
    if(status < 0){
        printf("     > nuovo server failed to scan:, errorcode: %i\n", status);
        close(connection);
        return;
    }

    /* see if the command succeeded */
    status = cm_check_unexpected_error(connection);
    if(status < 0){
        printf("     > target server could not complete request: %i\n", status);
        close(connection);
        return;
    }
    printf("     > target server processed request succesfully\n");

    /* close the connection */
    close(connection);
}

int content_menu(nuovo_server *target, content_info *cinfo){
        char input[MAX_COMMAND_LENGTH];
        int len;
        char *content_types[CONTENT_TYPE_TEXT+1];
        
        content_types[CONTENT_TYPE_AUDIO] = "audio";
        content_types[CONTENT_TYPE_VIDEO] = "video";
        content_types[CONTENT_TYPE_IMAGE] = "image";
        content_types[CONTENT_TYPE_TEXT] = "text";
        content_types[CONTENT_TYPE_SOFT] = "software";
        
        printf("****** CONTENT DETAILS ********************\n");
        printf("title:  %s\n", cinfo->title);
        printf("author: %s\n", cinfo->author);
        printf("type:   %s\n", content_types[cinfo->type]);
        printf("size:   %ikB\n", (int)ceil(cinfo->content_size/1024.00));
        printf("rights: %i resell count, %i resell depth\n", (cinfo->content_rights).resell_count, (cinfo->content_rights).resell_depth);
        printf("price:  %01.2f EURO\n", ((cinfo->content_rights).price) / 100.00);
        printf("\n");
        printf("  1) Buy this content\n");
        printf("  2) Return to content list\n");
        printf("*******************************************\n");

        if(read_command(input, &len) < 0){
            return 1;
        }
        input[1] = '\0';
        
        switch(strtol(input, (char **)NULL, 10)){
            case 1:
                perform_get(target, cinfo);
                break;
            case 2:
                return 1;
                break;
            default:
                printf("unknown command '%s'\n", input);
        }
        return 1;
}

int content_list_menu(content_info_list *ilist){
    int i, len, choice;
    content_info *cinfo;
    char input[MAX_COMMAND_LENGTH];
    
    if(ilist->len == 0){
        printf("     > no content available!\n");
        return -1;
    }

    printf("****** CONTENT LIST ***********************\n");

    printf("Total of %i items, please make a choice:\n", ilist->len);

    for(i=0; i<ilist->len; i++){
        cinfo = (ilist->list)[i];
        printf("  % 4i) %s - %s\n", i+1, cinfo->title, cinfo->author);
    }
    printf("  % 4i) Return to action menu\n", i+1);
    printf("*******************************************\n");

    if(read_command(input, &len) < 0){
        return -2;
    }
    choice = strtol(input, (char **)NULL, 10) - 1;

    if(choice == i){
        return -1;
    }

    if(choice >= ilist->len || choice < 0){
        printf("     > unknown content\n");
        return -2;
    }
    return choice;
}

int list_content(nuovo_server *target, content_info_list *result){
    int status;

    /* connect to the data server */
    connection = socks_connect_init(IS_PORT, hostname, TIMEOUT_SECONDS);
    if(connection < 0){
        printf("     > could not connect to nuovo server\n");
        return -1;
    }

    uint16_t request_type = IS_REQUEST_LIST;
    if(cm_write_uint16(request_type, connection) < 0){
        printf("     > could not write command\n");
        close(connection);
        return -1;
    }

    /* write the nuovo server */
    if(cm_write_nuovo_server(target, connection) < 0){
        printf("     > could not write target nuovo server\n");
        close(connection);
        return -1;
    }

    status = cm_read_content_info_list(result, connection);
    if(status < 0){
        printf("     > could not retrieve content info list: %i\n", status);
        close(connection);
        return -1;
    }

    /* close the connection */
    close(connection);

    return 1;
}
void perform_update(nuovo_server *target){
    int status;
    
    /* connect to the data server */
    connection = socks_connect_init(IS_PORT, hostname, TIMEOUT_SECONDS);
    if(connection < 0){
        printf("     > could not connect to nuovo server\n");
        return;
    }

    uint16_t request_type = IS_REQUEST_UPDATE;
    if(cm_write_uint16(request_type, connection) < 0){
        printf("     > could not write command\n");
        close(connection);
        return;
    }

    /* write the nuovo server */
    if(cm_write_nuovo_server(target, connection) < 0){
        printf("     > could not write target nuovo server\n");
        close(connection);
        return;
    }

    /* see if the command succeeded */
    status = cm_check_unexpected_error(connection);
    if(status < 0){
        printf("     > target server could not complete request: %i\n", status);
        close(connection);
        return;
    }
    printf("     > target server processed request succesfully\n");
}
void perform_revoke(nuovo_server *target){
    int status;
    
    /* connect to the data server */
    connection = socks_connect_init(IS_PORT, hostname, TIMEOUT_SECONDS);
    if(connection < 0){
        printf("     > could not connect to nuovo server\n");
        return;
    }

    uint16_t request_type = IS_REQUEST_REVOKE;
    if(cm_write_uint16(request_type, connection) < 0){
        printf("     > could not write command\n");
        close(connection);
        return;
    }

    /* write the nuovo server */
    if(cm_write_nuovo_server(target, connection) < 0){
        printf("     > could not write target nuovo server\n");
        close(connection);
        return;
    }

    /* see if the command succeeded */
    status = cm_check_unexpected_error(connection);
    if(status < 0){
        printf("     > target server could not complete request: %i\n", status);
        close(connection);
        return;
    }
    printf("     > target server processed request succesfully\n");
}
int action_menu(nuovo_server *target){
        char input[MAX_COMMAND_LENGTH];
        int len, choice;
        

       content_info_list cilist;

        printf("****** ACTION MENU ************************\n");
        printf("What do you want to do at %s %s?\n", (target->pkey).type==NUOVO_SERVER_TYPE_RESELLER ? "reseller" : "provider", (target->pkey).device_name);
        printf("  1) List all available content\n");
        printf("  2) Request a new DRL\n");
        printf("  3) Add this device to our DRL\n");
        printf("  4) Return to main menu\n");
        printf("*******************************************\n");

        if(read_command(input, &len) < 0){
            return 1;
        }
        input[1] = '\0';
        
        switch(strtol(input, (char **)NULL, 10)){
            case 1:
                if(list_content(target, &cilist) < 0){
                    break;
                }
                while((choice = content_list_menu(&cilist)) >= 0){
                    content_menu(target, (cilist.list)[choice]);
                }
                break;
            case 2:
                perform_update(target);
                break;
            case 3:
                perform_revoke(target);
                break;
            case 4:
                return -1;
            default:
                printf("unknown command '%s'\n", input);
        }
        return 1;
}

int scan_menu(interface_reply_scan_list *result){
    int i, len, choice;
    char input[MAX_COMMAND_LENGTH];
    
    if(result->len == 0){
        printf("     > no other nuovo devices found\n");
        return -1;
    }
    printf("     > found %i device(s), please make a choice:\n", result->len);
    for(i=0; i<result->len; i++){
        printf("  % 4i) %s %s\n", i+1, (((result->list)[i])->pkey).type==NUOVO_SERVER_TYPE_RESELLER ? "reseller" : "provider", (((result->list)[i])->pkey).device_name);
        printf("        %s:%i\n", ((result->list)[i])->hostname, ((result->list)[i])->port);
    }

    printf("  % 4i) Return to main menu\n", i+1);
    
    if(read_command(input, &len) < 0){
        return -2;
    }
    choice = strtol(input, (char **)NULL, 10) -1;

    if(choice == i){
        return -1;
    }

    if(choice >= result->len || choice < 0){
        printf("     > unknown choice '%i'\n", choice);
        return -2;
    }

    return choice;
}

int perform_bcast(interface_reply_scan_list *result){
    int status;
    
    /* connect to the data server */
    connection = socks_connect_init(IS_PORT, hostname, TIMEOUT_SECONDS);
    if(connection < 0){
        printf("     > could not connect to nuovo server\n");
        return -1;
    }

    uint16_t request_type = IS_REQUEST_SCAN;
    if(cm_write_uint16(request_type, connection) < 0){
        printf("     > could not write command\n");
        close(connection);
        return -1;
    }
    status = cm_read_if_scan_list(result, connection);
    if(status < 0){
        printf("     > nuovo server failed to scan:, errorcode: %i\n", status);
        close(connection);
        return -1;
    }

    /* close the connection */
    close(connection);
    
    return 1;
}

void perform_restore(open_session *sess, nuovo_server *target){
    interface_request_restore request;
    int status;
    
    /* copy data to the interface struct */
    request.index = sess->index;
    if(memcpy(&(request.restore_at), target, sizeof(nuovo_server)) == NULL){
        printf("     > could not copy target data\n");
        return;
    }
    
    connection = socks_connect_init(IS_PORT, hostname, TIMEOUT_SECONDS);
    if(connection < 0){
        printf("     > could not connect to nuovo server\n");
        return;
    }

    uint16_t request_type = IS_REQUEST_RESTORE;
    if(cm_write_uint16(request_type, connection) < 0){
        printf("     > could not write command\n");
        close(connection);
        return;
    }
    status = cm_write_request_restore(&request, connection);
    if(status < 0){
        printf("     > nuovo server failed to scan:, errorcode: %i\n", status);
        close(connection);
        return;
    }

    /* see if the command succeeded */
    status = cm_check_unexpected_error(connection);
    if(status < 0){
        printf("     > target server could not complete request: %i\n", status);
        close(connection);
        return;
    }
    printf("     > target server processed request succesfully\n");

    /* close the connection */
    close(connection);
}

int restore_menu(interface_reply_session_list *slist){
    int i, len, choice;
    char input[MAX_COMMAND_LENGTH];
    
    if(slist->len == 0){
        printf("     > there are no broken sessions\n");
        return -1;
    }
    printf("     > found %i broken session(s), please make a choice:\n", slist->len);
    for(i=0; i<slist->len; i++){
        printf("  % 4i) %s - %s\n", i+1, (((slist->list)[i])->info).title, (((slist->list)[i])->info).author);
        printf("        @ %s %s\n", (((slist->list)[i])->target).type==NUOVO_SERVER_TYPE_RESELLER ? "reseller" : "provider", (((slist->list)[i])->target).device_name);
    }

    printf("  % 4i) Return to main menu\n", i+1);
    
    if(read_command(input, &len) < 0){
        return 1;
    }
    choice = strtol(input, (char **)NULL, 10) -1;

    if(choice == i){
        return -1;
    }

    if(choice >= slist->len || choice < 0){
        printf("     > unknown choice '%i'\n", choice);
        return 1;
    }
    
    return choice;
}

int perform_session_list(interface_reply_session_list *slist){
    int status;
    
    /* connect to the data server */
    connection = socks_connect_init(IS_PORT, hostname, TIMEOUT_SECONDS);
    if(connection < 0){
        printf("     > could not connect to target server\n");
        return -1;
    }

    /* indicate that we want to cash our money */
    uint16_t request_type = IS_REQUEST_SESSIONS;
    if(cm_write_uint16(request_type, connection) < 0){
        printf("     > could not write command\n");
        close(connection);
        return -1;
    }

    /* read the session list from the socket */
    status = cm_read_if_session_list(slist, connection);
    if(status < 0){
        printf("     > nuovo server failed read session list: %i\n", status);
        close(connection);
        return -1;
    }

    /* close the connection */
    close(connection);

    return 1;
}

void perform_cash(){
    int status;
    
    /* connect to the data server */
    connection = socks_connect_init(IS_PORT, hostname, TIMEOUT_SECONDS);
    if(connection < 0){
        printf("     > could not connect to target server\n");
        return;
    }

    /* indicate that we want to cash our money */
    uint16_t request_type = IS_REQUEST_CASH;
    if(cm_write_uint16(request_type, connection) < 0){
        printf("     > could not write command\n");
        close(connection);
        return;
    }

    /* see if the command succeeded */
    status = cm_check_unexpected_error(connection);
    if(status < 0){
        printf("     > target server could not complete request: %i\n", status);
        close(connection);
        return;
    }
    printf("     > target server processed request succesfully\n");

    /* close the connection */
    close(connection);
}

int content_type(uint8_t *type){
    int len;
    char str_type[MAX_COMMAND_LENGTH];

    printf("    %i) audio\n", CONTENT_TYPE_AUDIO);
    printf("    %i) video\n", CONTENT_TYPE_VIDEO);
    printf("    %i) image\n", CONTENT_TYPE_IMAGE);
    printf("    %i) text\n", CONTENT_TYPE_TEXT);
    printf("    %i) software\n", CONTENT_TYPE_SOFT);

    if(read_command(str_type, &len) < 0){
        return -1;
    }
    str_type[1] = '\0';
    *type = strtol(str_type, (char **)NULL, 10);
    
    switch(*type){
        case CONTENT_TYPE_AUDIO:
        case CONTENT_TYPE_VIDEO:
        case CONTENT_TYPE_IMAGE:
        case CONTENT_TYPE_TEXT:
        case CONTENT_TYPE_SOFT:
            return 1;
    }
    return -1;
}

int new_content_rights(rights *result){
    char count[MAX_COMMAND_LENGTH];
    char depth[MAX_COMMAND_LENGTH];
    char price[MAX_COMMAND_LENGTH];
    int len;
    
    printf("     > how often can we resell this?\n");
    if(read_command(count, &len) < 0){
        return -1;
    }
    printf("     > what is the maximum resell depth?\n");
    if(read_command(depth, &len) < 0){
        return -1;
    }
    printf("     > what is the minimum price in cents?\n");
    if(read_command(price, &len) < 0){
        return -1;
    }

    result->resell_count = strtol(count, (char **)NULL, 10);
    result->resell_depth = strtol(depth, (char **)NULL, 10);
    result->resell_total = 0;
    result->price = strtol(price, (char **)NULL, 10);

    return 1;
}

int content_details(char *filename, raw_content *content){
    int len;

    printf("     > please type the filename:\n");
    if(read_command(filename, &len) < 0){
        return -1;
    }
    printf("     > please choose the content type:\n");
    if(content_type(&((content->info).type)) < 0){
        return -1;
    }
    printf("     > please type a title for the content:\n");
    if(read_command((content->info).title, &len) < 0){
        return -1;
    }
    printf("     > please type the author or artist of the content:\n");
    if(read_command((content->info).author, &len) < 0){
        return -1;
    }

    if(new_content_rights( &((content->info).content_rights) ) < 0){
        return -1;
    }

    return 1;
}

void perform_add_content(){
    raw_content content;
    large_file lfp;
    int status;
    char filename[MAX_COMMAND_LENGTH];
    
    /* request the user for the content details */
    if(content_details(filename, &content) < 0){
        return;
    }

    if(start_read_file(filename, &lfp) < 0){
        close(connection);
        return;
    }
    content.info.content_size = lfp.total_size;

    /* connect to the data server */
    connection = socks_connect_init(IS_PORT, hostname, TIMEOUT_SECONDS);
    if(connection < 0){
        printf("     > could not connect to target server\n");
        return;
    }

    /* indicate that we want to add new content */
    uint16_t request_type = IS_REQUEST_ADD;
    if(cm_write_uint16(request_type, connection) < 0){
        printf("     > could not write command\n");
        close(connection);
        return;
    }

    /* initilialize writing of a large file to the socket */
    if(cm_start_writing_large_file(connection, lfp.total_size, &lfp) < 0){
        printf("     > could not initialize writing of large file\n");
        close(connection);
        return;
    }
printf("start loop %i/%i\n", lfp.total_read, lfp.total_size);
    /* sent the new content in chunks */    
    while(lfp.total_size > lfp.total_read){
        printf("LOOP: %i/%i\n", lfp.total_read, lfp.total_size);
        if(read_partof_file(&lfp) < 0){
            close(connection);
            return;
        }
        if(cm_write_partof_large_file(&lfp) < 0){
            printf("     > could not write part of raw content\n");
            close(connection);
            return;
        }
    }
    
    /* write the content details */
    status = cm_write_raw_content(&content, connection);
    if(status < 0){
        printf("     > could not write raw content information\n");
        close(connection);
        return;
    }
    
    /* see if the command succeeded */
    status = cm_check_unexpected_error(connection);
    if(status < 0){
        printf("     > target server could not complete request: %i\n", status);
        close(connection);
        return;
    }
    printf("     > target server processed request succesfully\n");

    /* close the connection */
    close(connection);
}

int perform_local_pkey(nuovo_server *result){
    int status;
    
    /* connect to the data server */
    connection = socks_connect_init(IS_PORT, hostname, TIMEOUT_SECONDS);
    if(connection < 0){
        printf("     > could not connect to target server\n");
        return -1;
    }

    /* indicate that we want the public key */
    uint16_t request_type = IS_REQUEST_PKEY;
    if(cm_write_uint16(request_type, connection) < 0){
        printf("     > could not write command\n");
        close(connection);
        return -1;
    }

    /* read the reply */
    status = cm_read_nuovo_server(result, connection);
    if(status < 0){
        printf("     > nuovo server failed to get pkey:, errorcode: %i\n", status);
        close(connection);
        return -1;
    }

    /* close the connection */
    close(connection);
    return 1;
}

void perform_play(content_info *cinfo){
    int status;
    
    /* connect to the data server */
    connection = socks_connect_init(IS_PORT, hostname, TIMEOUT_SECONDS);
    if(connection < 0){
        printf("     > could not connect to target server\n");
        return;
    }

    /* indicate that we want to play some content */
    uint16_t request_type = IS_REQUEST_PLAY;
    if(cm_write_uint16(request_type, connection) < 0){
        printf("     > could not write command\n");
        close(connection);
        return;
    }

    /* sent the content info we want to play */
    if(cm_write_content_info(cinfo, connection) < 0){
        printf("     > could not write content info\n");
        close(connection);
        return;
    }

    /* see if the command succeeded */
    status = cm_check_unexpected_error(connection);
    if(status < 0){
        printf("     > target server could not complete request: %i\n", status);
        close(connection);
        return;
    }
    printf("     > target server processed request succesfully\n");

    /* close the connection */
    close(connection);
}

int main_menu(){
        char input[MAX_COMMAND_LENGTH];
        int len=0, choice=0, choice2=0;

        content_info_list cilist;

        interface_reply_scan_list scanlist;
        interface_reply_session_list sessionlist;
        
        printf("****** MAIN MENU **************************\n");
        printf("Connected to: %s, please make a choice:\n", localserver.pkey.device_name);
        printf("  1) Scan for other nuovo devices\n");
        printf("  2) Restore a failed session\n");
        printf("  3) Cash all payment messages\n");
        printf("  4) Add new content to the system\n");
        printf("  5) Play local content\n");
        printf("  6) Quit the commandline utility\n");
        printf("*******************************************\n");

        if(read_command(input, &len) < 0){
            return 1;
        }
        input[1] = '\0';
        
        switch(strtol(input, (char **)NULL, 10)){
            case 1:
                if(perform_bcast(&scanlist) < 0){
                    break;
                }
                while((choice = scan_menu(&scanlist)) >= 0){
                    while(action_menu((scanlist.list)[choice]) > 0){
                    }
                }
                break;
            case 2:
                if(perform_session_list(&sessionlist) < 0){
                    break;
                }
                if((choice = restore_menu(&sessionlist)) >= 0){
                    if(perform_bcast(&scanlist) < 0){
                        break;
                    }
                    if((choice2 = scan_menu(&scanlist)) >= 0){
                        perform_restore((sessionlist.list)[choice], (scanlist.list)[choice2]);
                    }
                }
                break;
            case 3:
                perform_cash();
                break;
            case 4:
                perform_add_content();
                break;
            case 5:
                if(list_content(&localserver, &cilist) < 0){
                    break;
                }
                choice = content_list_menu(&cilist);
                if(choice >= 0){
                    perform_play((cilist.list)[choice]);
                }
                break;
            case 6:
                printf("Exiting commandline...\n");
                return -1;
            default:
                printf("unknown command '%s'\n", input);
        }
        return 1;
}

int main(int argc, char *argv[]){
    if(MAXLEN_CONTENT_INFO > MAX_COMMAND_LENGTH){
        printf("Command length failure.\n");
        return 1;
    }

	/* Check command parameters */
	if(argc < 2) {
		//fprintf(stdout, "Usage: %s <hostname/ip>\n", argv[0]);
		//return -1;
        printf("     > Using localhost as server\n");
        hostname = "localhost";
	} else {
        hostname = argv[1];
    }

    /* now connect to nuovo */
    if(perform_local_pkey(&localserver) < 0){
        printf("Connect failed\n");
        return 1;
    }
    strncpy(localserver.hostname, hostname, MAXLEN_HOSTNAME);

    while(main_menu() != -1){
    }

    /* done */
    return 0;
}
