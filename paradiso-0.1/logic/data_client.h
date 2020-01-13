#ifndef _CM_DATA_CLIENT_H_
#define _CM_DATA_CLIENT_H_ 1

#include <openssl/rsa.h>
#include <openssl/aes.h>
#include <openssl/sha.h>
#include <openssl/engine.h>

#include "../generic/generic.h"
#include "../interface.h"
#include "../data.h"
#include "data_server.h"
#include "../connection_manager/connection_manager.h"
#include "../generic/socks.h"

#define MAX_CONNECT_WAIT_SECONDS 5   /* maximum number of seconds to wait for connecting to another server */

/* declare global error packages */
DEFERROR(E_DC_NOT_TRUSTED,          "Target device not trusted.",                           -2200);
DEFERROR(E_DC_GET_NONCE,            "Get nonce failed.",                                    -2201);
DEFERROR(E_DC_WRITE_NEW_CONNECTION, "Send new connection failed.",                          -2202);
DEFERROR(E_DC_READ_MUTUALAUTH,      "Read mutual authenticaition failed.",                  -2203);
DEFERROR(E_DC_CHECK_MUTUALAUTH,     "Verify mutual authentication failed.",                 -2204);
DEFERROR(E_DC_GET_PAYMENT,          "Get payment failed.",                                  -2205);
DEFERROR(E_DC_WRITE_PAYMENT,        "Send payment failed.",                                 -2206);
DEFERROR(E_DC_READ_CONTENT,         "Receive of content failed.",                           -2207);
DEFERROR(E_DC_SAVE_CONTENT,         "Save content to disk failed.",                         -2208);
DEFERROR(E_DC_INIT_SOCKET,          "Initialize connection failed.",                        -2209);
DEFERROR(E_DC_WRITE_REQUEST_TYPE,   "Send request type failed.",                            -2210);
DEFERROR(E_DC_GET_SECOND_NONCE,     "Get second nonce in session restore failed.",          -2211);
DEFERROR(E_DC_GET_RESTORED_PAYMENT, "Read restored payment failed.",                        -2212);
DEFERROR(E_DC_WRITE_RESTORED_PAYMENT, "Send restored payment failed.",                      -2213);
DEFERROR(E_DC_READ_CONTENT_LIST,    "Read content info list failed.",                       -2214);
DEFERROR(E_DC_READ_DRL,             "Read revocaiton list failed.",                         -2215);
DEFERROR(E_DC_UPDATE_DRL,           "Security manager could not process new DRL.",          -2216);
DEFERROR(E_DC_OPEN_SESSION,         "Could not read requested session from disk.",          -2217);
DEFERROR(E_DC_START_READ_CONTENT,   "Could not initiliaze reading of file from socket.",    -2218);
DEFERROR(E_DC_START_SAVE_CONTENT,   "Could not initiliaze saving of large file to disk.",   -2219);

/* declare public methods */
PUBLIC int dc_handle_get(content_info *get_content, nuovo_server *target);
PUBLIC int dc_handle_restore(u_int16_t restore_me, nuovo_server *restore_at);
PUBLIC int dc_handle_list(nuovo_server *list_at, content_info_list *cilist);
PUBLIC int dc_handle_update(nuovo_server *update_at);


#endif /* _CM_DATA_CLIENT_H_ */
