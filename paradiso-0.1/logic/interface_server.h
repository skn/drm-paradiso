#ifndef _CM_INTERFACE_SERVER_H_
#define _CM_INTERFACE_SERVER_H_ 1


#include <openssl/rsa.h>
#include <openssl/aes.h>
#include <openssl/sha.h>
#include <openssl/engine.h>

#include "../generic/generic.h"
#include "../generic/server.h"
#include "../interface.h"
#include "../data.h"

#include "data_client.h"
#include "bcast_client.h"
#include "../connection_manager/connection_manager.h"

#ifdef _NEUROS_
#include "generic-nms.h"
#include "client-nms.h"
#include "nmsplugin.h"
#endif

/* the port on which the interface server will listen to */
#define IS_PORT 1818

/* the request types used by the interface server are defined in interface.h
   to support 3rd party interfaces */

/* declare global error packages */
DEFERROR(E_IS_READ_REQUEST_TYPE,    "Could not read request type.",                         -2100);
DEFERROR(E_IS_UNKNOWN_REQUEST_TYPE, "Received an unknown request type.",                    -2101);
DEFERROR(E_IS_NOT_IMPLEMENTED,      "This request is not yet implemented.",                 -2102);
DEFERROR(E_IS_WRITE_REPLY_STATUS,   "Could not write reply status to interface.",           -2103);
DEFERROR(E_IS_READ_REQUEST_GET,     "Could not read get request data from interface.",      -2104);
DEFERROR(E_IS_REQUEST_GET,          "Data client failed to process get request.",           -2105);
DEFERROR(E_IS_GET_SESSION_LIST,     "Could not get session list from data manager.",        -2106);
DEFERROR(E_IS_WRITE_SESSION_LIST,   "Could not write session list to interface.",           -2107);
DEFERROR(E_IS_READ_REQUEST_RESTORE, "Could not read restore request data from interface.",  -2108);
DEFERROR(E_IS_REQUEST_RESTORE,      "Data client failed to process restore request.",       -2109);
DEFERROR(E_IS_READ_REQUEST_LIST,    "Could not read list request data from interface.",     -2110);
DEFERROR(E_IS_REQUEST_LIST,         "Data client failed to process list request.",          -2111);
DEFERROR(E_IS_WRITE_CONTENT_INFO_LIST, "Could not write list to interface.",                -2112);
DEFERROR(E_IS_READ_REQUEST_UPDATE,  "Could not read update request data from interface.",   -2113);
DEFERROR(E_IS_REQUEST_UPDATE,       "Data client failed to process update request.",        -2114);
DEFERROR(E_IS_READ_RAW_CONTENT,     "Provider request sent to non-provider.",               -2115);
DEFERROR(E_IS_SM_ENCODE_CONTENT,    "Security manager failed to encode the content.",        -2116);
DEFERROR(E_IS_READ_REVOKE,          "Could not read device to revoke from interface.",      -2117);
DEFERROR(E_IS_REVOKE_DEVICE,        "Security manager failed to add the device to the DRL.",-2118);
DEFERROR(E_IS_PERFORM_SCAN,         "Could not get nuovo servers from broadcast client.",   -2119);
DEFERROR(E_IS_WRITE_SCAN_LIST,      "Could not write scan results to interface server.",    -2120);
DEFERROR(E_IS_NO_PROVIDER,          "Provider only request sent to non-provider.",          -2121);
DEFERROR(E_IS_DUPLICATE_CONTENT,    "Content you requested is already present on device.",  -2122);
DEFERROR(E_IS_READ_REQUEST_PLAY,    "Could not read play request from interface.",          -2123);
DEFERROR(E_IS_GET_RAW_CONTENT,      "Could not get raw content from security manager.",     -2124);
DEFERROR(E_IS_SAVE_TEMP_FILE,       "Data manager could not create temporary file.",        -2125);
DEFERROR(E_IS_GET_PKEY,             "Could not get public key from security manager.",      -2126);
DEFERROR(E_IS_WRITE_SERVER,         "Could not write nuovo server to interface.",           -2127);
DEFERROR(E_IS_START_WRITE_CONTENT,  "Initialize write content to disk failed.",             -2128);
DEFERROR(E_IS_START_GET_CONTENT,    "Initialize get content from security manager failed.", -2129);

/* declare public methods */
PUBLIC int is_handle_request();

#endif /* _CM_INTERFACE_SERVER_H_ */
