/*
 * server.h - Private header for the server program
 *
 * October 2012
 */

#ifndef SERVER_H
#define SERVER_H

#include "./unpv13e_solaris2.10/lib/unp.h"
#include "./unpv13e_solaris2.10/lib/unpifi.h"

/* Defines */

#define SERVER_INPUT            "server.in"
#define MAX_CONNECTIONS         100         /* Maximum number of interfaces */
#define MAX_CLIENTS             100         /* Maximum number of clients */
#define IFNAME_LEN              16          /* Same as IFI_NAME in unpifi.h */
#define IP_LEN                  16
#define LOCALHOST_IP            "127.0.0.1"
#define FILE_CHUNK_SIZE         (1024 * 1024)
#define MAX_BUFFER_SIZE         (1024 * 1024)

/* Datastructures */

typedef struct cli_info_s {
    char    ip[IP_LEN];
    int     port;
    int     connection_sock;
    int     connection_port;
    int     pid;
    int     valid;
} cli_info_t;

typedef struct conn_info_s {
    char                ifname[IFNAME_LEN];
    int                 sock;
    struct sockaddr_in  ip;
    struct sockaddr_in  netmask;
    struct sockaddr_in  subnet;
} conn_info_t;

typedef struct server_params_s {
    int         port;
    conn_info_t conn[MAX_CONNECTIONS];
    cli_info_t  cli_info[MAX_CLIENTS];
    int         conn_count;
    int         cli_count;
} server_params_t;

#endif /* SERVER_H */
