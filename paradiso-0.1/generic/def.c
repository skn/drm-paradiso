/* the following macro triggers the header files to make
   real definitions of variables instead of only declaring them */
#define _DEFINE 1

/* we need the openssl library */
#include <openssl/rsa.h>
#include <openssl/aes.h>
#include <openssl/sha.h>
#include <openssl/engine.h>

/* now we start including all header files so we get all definitions */
#include "generic.h"
#include "socks.h"
#include "semaphores.h"
#include "server.h"
#include "../connection_manager/connection_manager.h"
#include "../logic/interface_server.h"
#include "../logic/data_server.h"
#include "../logic/data_client.h"
#include "../logic/bcast_server.h"
#include "../logic/bcast_client.h"
#include "../security_manager/security_manager.h"
#include "../data_manager/data_manager.h"
