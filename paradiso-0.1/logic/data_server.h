#ifndef _CM_DATA_SERVER_H_
#define _CM_DATA_SERVER_H_ 1

#include <openssl/rsa.h>
#include <openssl/aes.h>
#include <openssl/sha.h>
#include <openssl/engine.h>

#include "../generic/generic.h"
#include "../interface.h"
#include "../data.h"
#include "../connection_manager/connection_manager.h"
#include "../security_manager/security_manager.h"
#include "../generic/server.h"

/* the port on which the data server will listen */
#define DS_PORT 1414

/* the request types used by the data server */
#define DS_REQUEST_GET      1
#define DS_REQUEST_RESTORE  2
#define DS_REQUEST_LIST     3
#define DS_REQUEST_UPDATE   4
#define DS_REQUEST_CASH     5

/* declare global error packages */
DEFERROR(E_DS_READ_REQUEST_TYPE,    "Could nog read request type.",                     -2000);
DEFERROR(E_DS_UNKNOWN_REQUEST_TYPE, "Received an unknown request type.",                -2001);
DEFERROR(E_DS_READ_NEW_CONNECTION,  "Error reading new connection.",                    -2002);
DEFERROR(E_DS_NOT_TRUSTED,          "Target device not trusted.",                       -2003);
DEFERROR(E_DS_GET_MUTUALAUTH,       "Get mutual authentication failed.",                -2004);
DEFERROR(E_DS_WRITE_MUTUALAUTH,     "Send mutual authentication failed.",               -2005);
DEFERROR(E_DS_READ_PAYMENT,         "Read payment failed.",                             -2006);
DEFERROR(E_DS_PAYMENT,              "Payment not accepted.",                            -2007);
DEFERROR(E_DS_GET_CONTENT,          "Get content failed.",                              -2008);
DEFERROR(E_DS_WRITE_CONTENT,        "Send content failed.",                             -2009);
DEFERROR(E_DS_NO_PROVIDER,          "Provider request sent to non-provider.",           -2010);
DEFERROR(E_DS_NO_BANK,              "Bank request sent to non-bank.",                   -2011);
DEFERROR(E_DS_GET_DRL,              "Get DRL failed.",                                  -2012);
DEFERROR(E_DS_WRITE_DRL,            "Send DRL failed.",                                 -2013);
DEFERROR(E_DS_GET_CONTENT_LIST,     "Get content list failed.",                         -2014);
DEFERROR(E_DS_WRITE_CONTENT_LIST,   "Send content list failed.",                        -2015);
DEFERROR(E_DS_START_GET_CONTENT,    "Initiliaze start get content from disk failed.",   -2016);
DEFERROR(E_DS_START_WRITE_CONTENT,  "Initiliaze start write content to socket failed.", -2017);

/* declare public methods */
PUBLIC int ds_handle_request(int request_socket);

#endif /* _CM_DATA_SERVER_H_ */
