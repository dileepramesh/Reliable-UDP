/*
 * client.h - Private header for the client program
 *
 * October 2012
 */

#ifndef CLIENT_H
#define CLIENT_H

#include "./unpv13e_solaris2.10/lib/unp.h"
#include "./unpv13e_solaris2.10/lib/unpifi.h"

/* Defines */

#define CLIENT_INPUT            "client.in"
#define IP_LEN                  16
#define MAX_FILENAME_LEN        32
#define MAX_CONNECTIONS         100
#define IFNAME_LEN              16
#define LOCALHOST_IP            "127.0.0.1"
#define FILE_CHUNK_SIZE         (1024 * 1024)
#define MAX_BUFFER_SIZE         (1024 * 1024)

/* Datastructures */

typedef struct iface_info_s {
    char                ifname[IFNAME_LEN];
    struct sockaddr_in  ip;
    struct sockaddr_in  netmask;
    struct sockaddr_in  subnet;
} iface_info_t;

typedef struct client_params_s {
    char            server_ip[IP_LEN];
    char            client_ip[IP_LEN];
    uint16_t        server_port;
    uint16_t        client_port;
    int             server_fd;
    char            file[MAX_FILENAME_LEN];
    iface_info_t    iface[MAX_CONNECTIONS];
    int             iface_count;
    int             server_local;
} client_params_t;

#endif /* CLIENT_H */
