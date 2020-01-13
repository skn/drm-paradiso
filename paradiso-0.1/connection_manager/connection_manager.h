#ifndef _CONNECTION_MANAGER_H_
#define _CONNECTION_MANAGER_H_ 1

/* the connection manager has 3 points of input:
    data server: tcp socket for data requests
    data client: function calls from child handling requests
    interface server: tcp socket for interface requests (normally results in data client calls)
*/

#include "../generic/generic.h"
#include "../generic/socks.h"
#include "../security_manager/security_manager.h"
#include "../data_manager/data_manager.h"

/* identifiers to indicate a protected error message on the socket */
#define CM_CONTINUE 1
#define CM_ERROR    2

/* variable to save a protected error message if occured
   note: intended to become global, but no need for it at this point */
protected_error CM_ERROR_MESSAGE;

/* declare global generic connection manager error packages */
DEFERROR(E_CM_FAILED_REQUEST_TYPE,  "Error reading request type from socket.", -1010);
DEFERROR(E_CM_READ_NEW_CONNECTION,  "Error reading new connection struct.",    -1011);
DEFERROR(E_CM_READ_PAYMENT,         "Error reading payment struct.",           -1012);
DEFERROR(E_CM_CONNECTION_PANIC,     "Connection terminated unexpectedly.",     -1013);
DEFERROR(E_CM_NO_IDENTIFIER,        "No identifier on socket.",                -1014);
DEFERROR(E_CM_NO_ERROR_PACKAGE,     "Expected error package on socket.",       -1015);
DEFERROR(E_CM_UNKNOWN_IDENTIFIER,   "Received unknown identifier.",            -1015);
DEFERROR(E_CM_EMPTY_LIST_READ,      "Could not read empty list.",              -1016);


/* declaration of public methods */
PUBLIC int cm_check_unexpected_error(int socket);
PUBLIC int cm_send_error_identifier(int16_t identifier, int socket);

PUBLIC int cm_read_protected_error(protected_error *perr, int socket);
PUBLIC int cm_write_protected_error(protected_error *perr, int socket);


PUBLIC int cm_write_uint16(uint16_t src, int socket_out);
PUBLIC int cm_read_uint16(uint16_t *result, int socket_in);
PUBLIC int cm_write_uint32(uint32_t src, int socket_out);
PUBLIC int cm_read_uint32(uint32_t *result, int socket_in);

PUBLIC int cm_read_new_connection(new_connection *conn, int socket);
PUBLIC int cm_write_new_connection(new_connection *conn, int socket);

PUBLIC int cm_read_mutualauth(mutualauth *mutau, int socket);
PUBLIC int cm_write_mutualauth(mutualauth *mutau, int socket);

PUBLIC int cm_read_payment(payment *paym, int socket);
PUBLIC int cm_write_payment(payment *paym, int socket);

PUBLIC int cm_read_secured_content(secured_content *content, int socket);
PUBLIC int cm_write_secured_content(secured_content *content, int socket);

PUBLIC int cm_read_raw_content(raw_content *content, int socket);
PUBLIC int cm_write_raw_content(raw_content *content, int socket);

PUBLIC int cm_read_drl(revocation_list *drl, int socket);
PUBLIC int cm_write_drl(revocation_list *drl, int socket);

PUBLIC int cm_read_restored_payment(restored_payment *respaym, int request_socket);
PUBLIC int cm_write_restored_payment(restored_payment *respaym, int request_socket);

PUBLIC int cm_read_payment_list(payment_list *plist, int socket);
PUBLIC int cm_write_payment_list(payment_list *plist, int socket);

PUBLIC int cm_read_request_get(interface_request_get *is_get, int socket);
PUBLIC int cm_write_request_get(interface_request_get *is_get, int socket);

PUBLIC int cm_read_request_restore(interface_request_restore *is_restore, int socket);
PUBLIC int cm_write_request_restore(interface_request_restore *is_restore, int socket);

PUBLIC int cm_read_nuovo_server(nuovo_server *server, int socket);
PUBLIC int cm_write_nuovo_server(nuovo_server *server, int socket);
PUBLIC int cm_recv_nuovo_server(nuovo_server *server, int socket);
PUBLIC int cm_send_nuovo_server(nuovo_server *server, nuovo_server *sendto);
PUBLIC int cm_bcast_nuovo_server(nuovo_server *server, int port);

PUBLIC int cm_read_content_info(content_info *info, int socket);
PUBLIC int cm_write_content_info(content_info *info, int socket);

PUBLIC int cm_read_if_session_list(interface_reply_session_list *slist, int socket);
PUBLIC int cm_write_if_session_list(interface_reply_session_list *slist, int socket);

PUBLIC int cm_read_if_scan_list(interface_reply_scan_list *rscan, int socket);
PUBLIC int cm_write_if_scan_list(interface_reply_scan_list *rscan, int socket);

PUBLIC int cm_read_content_info_list(content_info_list *cilist, int socket);
PUBLIC int cm_write_content_info_list(content_info_list *cilist, int socket);

/* methods for large file support */
PUBLIC int cm_start_writing_large_file(int socket, u_int32_t len, large_file *lfp);
PUBLIC int cm_write_partof_large_file(large_file *lfp);
PUBLIC int cm_start_reading_large_file(int socket, large_file *lfp);
PUBLIC int cm_read_partof_large_file(large_file *lfp);

#endif /* _CONNECTION_MANAGER_H_ */
