/*
 * server.c
 *
 * This is the main server program which services file transfer requests from
 * different clients. For each new client request, a separate child is
 * spawned. This uses a protocol library that ensures ordered delivery of
 * data.
 *
 * October 2012
 */

/* Includes */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>
#include <pthread.h>
#include <assert.h>
#include "server.h"
#include "rudp.h"

/* Globals */
server_params_t *serv_params;

/*
 * sigchild_handler
 *
 * This will be called when one of the server-child processes die
 */
static void
sigchild_handler (int signo)
{
    int i;
    pid_t pid, del_pid = 0;
    int stat;

    while ((pid = waitpid(-1, &stat, WNOHANG)) > 0) {
        printf("\nsigchild received: child %d terminated (%d)\n", 
               (int)pid, stat);
        if (del_pid == 0) {
            del_pid = pid;
        }
    }

    /* 
     * We go the PID of the child who died. Walk through the cli_info
     * structure array and purge the entry corresponding to this child. Close
     * the associated client socket before purging the entry.
     */
    for (i = 0; i < MAX_CLIENTS; i++) {
        if (!serv_params->cli_info[i].valid) {
            continue;
        }
        if (serv_params->cli_info[i].pid == (int)del_pid ||
            serv_params->cli_info[i].pid == 0) {
            printf("sigchild_handler: purging entry corresponding to "
                   "child %d, client %s (%d)\n", (int)del_pid, 
                   serv_params->cli_info[i].ip,
                   serv_params->cli_info[i].port);
            close(serv_params->cli_info[i].connection_sock);
            bzero(&serv_params->cli_info[i], sizeof(cli_info_t));
            break;
        }
    }
}

/*
 * init_listening_sockets
 *
 * Initialize and bind sockets on all the interfaces present on the server.
 * Also cache the information on IP, Net mask and Subnet associated with each
 * interface in a local array of connection structures.
 */
static int
init_listening_sockets (void)
{
    int sockfd, idx = 0, optval = 1;
    struct ifi_info *ifi;
    struct sockaddr_in *sa, *netmask;
    char ip[IP_LEN], mask[IP_LEN], subnet[IP_LEN];

    printf("\nINTERFACE LIST:\n");

    /* Walk through all the interfaces in the system */
    for (ifi = Get_ifi_info(AF_INET, 1); ifi != NULL; ifi = ifi->ifi_next) {

        /* Create and bind the socket on this interface */
        sockfd = socket(AF_INET, SOCK_DGRAM, 0);
        setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
        sa = (struct sockaddr_in *)ifi->ifi_addr;
        sa->sin_family = AF_INET;
        sa->sin_port = htons(serv_params->port);
        netmask = (struct sockaddr_in *)ifi->ifi_ntmaddr;
        bind(sockfd, (struct sockaddr *)sa, sizeof(struct sockaddr_in));

        /* Store the connection details in our local conn_info structure */
        bzero(&serv_params->conn[idx], sizeof(conn_info_t));
        serv_params->conn[idx].sock = sockfd;
        memcpy(serv_params->conn[idx].ifname, ifi->ifi_name, IFNAME_LEN);
        memcpy(&serv_params->conn[idx].ip, sa, sizeof(struct sockaddr_in));
        memcpy(&serv_params->conn[idx].netmask, netmask, 
               sizeof(struct sockaddr_in));
        serv_params->conn[idx].subnet.sin_addr.s_addr = 
            (serv_params->conn[idx].ip.sin_addr.s_addr & 
             serv_params->conn[idx].netmask.sin_addr.s_addr);

        /* Display it! */
        printf("interface: %s ip: %s mask: %s subnet: %s\n", 
               serv_params->conn[idx].ifname,
               inet_ntop(AF_INET, &(serv_params->conn[idx].ip.sin_addr),
                         ip, IP_LEN),
               inet_ntop(AF_INET, &(serv_params->conn[idx].netmask.sin_addr),
                         mask, IP_LEN),
               inet_ntop(AF_INET, &(serv_params->conn[idx].subnet.sin_addr),
                         subnet, IP_LEN));

        idx++;
    }

    serv_params->conn_count = idx;

    return 0;
}

/*
 * init_connection_socket
 *
 * Initialize a connection socket that the server will use to communicate with
 * a specific client. This is created by the child spawned by the server to
 * handle a particular client.
 */
static int
init_connection_socket (char *server_ip, int client_local, cli_info_t *cli_info)
{
    int sockfd, ret, optval = 1, buf_size;
    struct sockaddr_in cli_addr, serv_addr;
    struct sockaddr_in sock_addr;
    int sock_len;
    char buf[IP_LEN];

    /* Create the socket */
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        printf("init_connection_socket: failed to create socket on the "
               "client (%d)\n", errno);
        return -1;
    }

    /* Set buffer size */
    buf_size = MAX_BUFFER_SIZE;
    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &buf_size, 
                   sizeof(buf_size)) < 0) {
        printf("init_connection_socket: failed to set recv buf (%d)\n", errno);
        return -1;
    }   

    if (setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, &buf_size, 
                   sizeof(buf_size)) < 0) {
        printf("init_connection_socket: failed to set send buf (%d)\n", errno);
        return -1;
    }

    /* Set SO_DONTROUTE if the client is local */
    if (client_local) {
        if (setsockopt(sockfd, SOL_SOCKET, SO_DONTROUTE,
                       &optval, sizeof(optval)) < 0) {
            printf("init_connection_socket: failed to set SO_DONTROUTE (%d)\n",
                   errno);
            return -1;
        }
    }
    cli_info->connection_sock = sockfd;

    /* Bind the socket to the server-ip and an ephemeral port */
    bzero(&serv_addr, sizeof(struct sockaddr_in));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(0);
    inet_pton(AF_INET, server_ip, &serv_addr.sin_addr);

    ret = bind(sockfd, (struct sockaddr *)(&serv_addr),
               sizeof(struct sockaddr_in));
    if (ret < 0) {
        printf("init_connection_socket: bind failed (%d)\n", errno);
        return -1;
    }

    /* Print out the socket information */
    sock_len = sizeof(struct sockaddr);
    bzero(&sock_addr, sizeof(struct sockaddr_in));
    getsockname(sockfd, (struct sockaddr *)&sock_addr, &sock_len);

    printf("Connection socket created and bound to %s port %d\n",
           inet_ntop(AF_INET, &sock_addr.sin_addr, buf, IP_LEN),
           ntohs(sock_addr.sin_port));
    cli_info->connection_port = ntohs(sock_addr.sin_port);

    /* Connect to the client */
    bzero(&cli_addr, sizeof(struct sockaddr_in));
    cli_addr.sin_family = AF_INET;
    cli_addr.sin_port = htons(cli_info->port);
    inet_pton(AF_INET, cli_info->ip, &cli_addr.sin_addr);

    ret = connect(sockfd, (struct sockaddr *)&cli_addr,
                  sizeof(struct sockaddr));
    if (ret != 0) {
        printf("init_connection_socket: failed to connect to client\n");
        return -1;
    }

    /* Print out the client information */
    sock_len = sizeof(struct sockaddr);
    bzero(&sock_addr, sizeof(struct sockaddr_in));
    getpeername(sockfd, (struct sockaddr *)&sock_addr, &sock_len);

    printf("Connection socket connected to client %s port %d\n",
           inet_ntop(AF_INET, &sock_addr.sin_addr, buf, IP_LEN),
           ntohs(sock_addr.sin_port));

    return 0;
}

/*
 * check_client_on_same_network
 *
 * This function checks if the client and server are on the same network.
 * Returns -1 upon error. Returns 1 if both are on the same network.
 */
static int
check_client_on_same_network (conn_info_t *server_conn, char *client_ip)
{
    in_addr_t client_addr;

    bzero(&client_addr, sizeof(struct in_addr));
    inet_pton(AF_INET, client_ip, &client_addr);

    if ((server_conn->netmask.sin_addr.s_addr & client_addr) == 
        (server_conn->subnet.sin_addr.s_addr)) {
        return 1;
    }

    return 0;
}

/*
 * send_file_data
 *
 * This is called once the connection is successfully established with the
 * client. It transfers the given file contents to the client.
 */
static void
send_file_data (int client_fd, char *filename)
{
    int ret, fd, bytes_read;
    char *buf;

    /* Sanity check */
    if (!filename) {
        return;
    }

    buf = (char *)malloc(FILE_CHUNK_SIZE);
    if (!buf) {
        printf("send_file_data: memory failure\n");
        return;
    }

    /* Open the file */
    fd = open(filename, O_RDONLY);
    if (fd < 0) {
        printf("\nsend_file_data: failed to open file %s\n", filename);
        printf("send_file_data: closing file transfer\n\n");

        /* Notify the client */
        rudp_send_ctrl_packet(client_fd, MSG_TYPE_ERROR_INVALID_FILE);
        return;
    }

    printf("Starting file transfer\n\n");

    /* 
     * Read the file contents in chunks of 4K and send it across to the
     * client.
     */
    bzero(buf, FILE_CHUNK_SIZE);
    bytes_read = read(fd, buf, FILE_CHUNK_SIZE);
    while (bytes_read > 0) {
        ret = rudp_send(client_fd, buf, bytes_read);
        if (ret < 0) {
            printf("send_file_data: failed with error %d\n", errno);
            return;
        }

        /* Read the next chunk from the file */
        bzero(buf, FILE_CHUNK_SIZE);
        bytes_read = read(fd, buf, FILE_CHUNK_SIZE);
    }

    /* 
     * All the file contents have been transferred successfully. Close the
     * connection gracefully.
     */
    ret = rudp_close(client_fd);
    if (ret < 0) {
        printf("send_file_data: failed to close the connection (%d)\n", errno);
    }

    /* All done */
    free(buf);
    return;
}

/*
 * handle_client
 *
 * Main routine for the server-child. This is invoked whenever a new client
 * request is received.
 */
static void
handle_client (int cli_sock, struct sockaddr_in *cli_addr, int cli_idx, 
               void *buf)
{
    char client_ip[IP_LEN], server_ip[IP_LEN], send_buf[MAXLINE];
    int i, client_port, server_port, is_local, ret;
    conn_info_t *conn;
    cli_info_t *cli_info = &serv_params->cli_info[cli_idx];

    inet_ntop(AF_INET, &(cli_addr->sin_addr), client_ip, IP_LEN);
    client_port = ntohs(cli_addr->sin_port);

    /*
     * Close all the sockets inherited from the parent except for the socket
     * on which the connection was received.
     */
    for (i = 0; i < serv_params->conn_count; i++) {
        if (serv_params->conn[i].sock == cli_sock) {
            conn = &serv_params->conn[i];
            continue;
        }
        close(serv_params->conn[i].sock);
    }

    /* 
     * Check whether the client and server are on the same host / network. If
     * so, we have to set the MSG_DONTROUTE flag.
     */
    is_local = 0;
    inet_ntop(AF_INET, &(conn->ip.sin_addr), server_ip, IP_LEN);
    server_port = serv_params->port;
    if (strncmp(server_ip, LOCALHOST_IP, IP_LEN) == 0) {
        is_local = 1;
        printf("Server and Client are on the same host\n");
    } else {
        is_local = check_client_on_same_network(conn, client_ip);

        if (is_local) {
            printf("Server and Client are on the same network (Local)\n");
        } else {
            printf("Server and Client are on different networks (Non-Local)\n");
        }
    }

    printf("Selected Server: %s (%d)\n", server_ip, server_port);
    printf("Selected Client: %s (%d)\n\n", client_ip, client_port);

    printf("Filename received from client for transfer: %s\n\n", (char *)buf);

    /* Create a new connection socket to communicate with the client */
    ret = init_connection_socket(server_ip, is_local, cli_info);
    if (ret != 0) {
        printf("handle_client: failed to initialize connection socket\n");
        return;
    }

    /* Send the port associated with the connection socket to the client */
    sprintf(send_buf, "%d", cli_info->connection_port);
    ret = rudp_srv_conn_send(conn->sock, cli_info->connection_sock, cli_addr,
                             (void *)send_buf, MAXLINE);
    if (ret < 0) {
        printf("handle_client: failed to send connection socket port to "
               "client\n");
        return;
    }

    printf("Connection re-established with the client\n");

    /* Now send the file contents to the client */
    send_file_data(cli_info->connection_sock, buf);

    /* All done */
    exit(0);
}

/*
 * is_new_client_request
 *
 * This checks whether the given client is connecting with us for the first
 * time or if it's a duplicate request. If it's a new request, we cache the
 * request. We get duplicate requests when the connection port information we
 * sent to the client is lost.
 */
static int
is_new_client_request (struct sockaddr_in *cli_addr, int *cli_idx)
{
    char cli_ip[IP_LEN];
    int i, idx, cli_port;

    inet_ntop(AF_INET, &(cli_addr->sin_addr), cli_ip, IP_LEN);
    cli_port = ntohs(cli_addr->sin_port);
    idx = MAX_CLIENTS;
    
    for (i = 0; i < MAX_CLIENTS; i++) {
        /* Skip if the entry is invalid */
        if (!serv_params->cli_info[i].valid) {
            if (idx == MAX_CLIENTS) {
                idx = i;
            }
            continue;
        }

        /* Check if it's a duplicate request */
        if (strncmp(serv_params->cli_info[i].ip, cli_ip, IP_LEN) == 0 &&
            serv_params->cli_info[i].port == cli_port) {
            printf("is_new_client_request: duplicate client request %s(%d). "
                   "ignoring\n", cli_ip, cli_port);
            return 0;
        }
    }

    if (idx == MAX_CLIENTS) {
        printf("cannot process new request as number of clients exceed "
               "maximum\n");
        return 0;
    }

    /* Cache the request. PID will be updated after forking the child. */
    strncpy(serv_params->cli_info[idx].ip, cli_ip, IP_LEN);
    serv_params->cli_info[idx].port = cli_port;
    serv_params->cli_info[idx].valid = 1;
    *cli_idx = idx;
    serv_params->cli_count += 1;

    printf("Received new connection request from client %s (%d)\n\n", 
           cli_ip, cli_port);

    return 1;
}

/*
 * conn_listen
 *
 * This is the main loop for the server wherein it listens for incoming
 * connections using select.
 */
static void
conn_listen (void)
{
    int i, max_fd, bytes_read, ret, pid, cli_idx;
    fd_set fdset, origset;
    char buf[10000];
    struct sockaddr_in cli_addr;
    int len = sizeof(struct sockaddr);

    printf("\nWaiting for incoming connections...\n");

    /* Setup parameters for the select call and invoke it */
    FD_ZERO(&fdset);
    max_fd = -1;
    for (i = 0; i < serv_params->conn_count; i++) {
        FD_SET(serv_params->conn[i].sock, &fdset);
        if (serv_params->conn[i].sock > max_fd) {
            max_fd = serv_params->conn[i].sock;
        }
    }

    origset = fdset;

    /* Main Loop */
    while (1) {

        fdset = origset;
        ret = select(max_fd + 1, &fdset, NULL, NULL, NULL);
        if (ret < 0) {
            if (errno == EINTR) {
                continue;
            } else {
                /* Should never happen! */
                assert(0);
            }
        }

        /* See which socket the request arrived on and read from it */
        for (i = 0; i < serv_params->conn_count; i++) {
            if (FD_ISSET(serv_params->conn[i].sock, &fdset)) {
                /* See who we got the message from */
                bzero(&cli_addr, sizeof(struct sockaddr_in));
                bytes_read = rudp_srv_conn_recv(serv_params->conn[i].sock, 
                                                buf, sizeof(buf), 
                                                (struct sockaddr *)&cli_addr, 
                                                &len);

                /*
                 * Check if we have already received a message from this guy.
                 * If so, we need to ignore the message. If it's a new
                 * request, then cache it to avoid duplicates later on.
                 */
                ret = is_new_client_request(&cli_addr, &cli_idx);
                if (ret) {
                    /* It's a new request. Spawn a child to handle it */
                    pid = fork();
                    if (pid == 0) {
                        /* Call the child routine to handle this request */
                        handle_client(serv_params->conn[i].sock, &cli_addr, 
                                      cli_idx, buf);
                    } else {
                        /* Store the child's PID in our table */
                        serv_params->cli_info[cli_idx].pid = pid;
                    }
                }
            }
        }
    }
}

/*
 * read_server_params
 *
 * Read the input parameters for the server from the file server.in
 */
static int
read_server_params (rudp_srv_state_t *rudp_srv_state)
{
    int fd, val, lineno = 1;
    char buf[MAXLINE];

    /* Open the input file */
    fd = open(SERVER_INPUT, O_RDONLY);
    if (!fd) {
        return -1;
    }

    /* Read the parameters one line at a time */
    bzero(serv_params, sizeof(server_params_t));
    bzero(rudp_srv_state, sizeof(rudp_srv_state_t));
    bzero(buf, MAXLINE);
    while (readline(fd, buf, MAXLINE)) {
        val = atoi(buf);
        if (val == 0) {
            return -1;
        }

        if (lineno == 1) {
            serv_params->port = val;
        } else if (lineno == 2) {
            rudp_srv_state->max_cwnd_size = val;
        }
        lineno++;
        bzero(buf, MAXLINE);
    }

    printf("\nSERVER PARAMS:\n");
    printf("port: %d\n", serv_params->port);
    printf("sending window size: %d\n", rudp_srv_state->max_cwnd_size);

    return 0;
}

/* Main entry point */
int
main (int argc, char *argv[])
{
    int ret;
    rudp_srv_state_t rudp_srv_state;

    /* Sanity check */
    if (argc != 1) {
        printf("usage: ./server\n");
        return -1;
    }

    /* Register for SIGCHLD */
    signal(SIGCHLD, sigchild_handler);

    /* Initialize the structure for holding server parameters */
    serv_params = (server_params_t *)malloc(sizeof(server_params_t));
    if (!serv_params) {
        printf("main: failed to initialize server parameters\n");
        return -1;
    }

    /* Read the server parameters from server.in */
    ret = read_server_params(&rudp_srv_state);
    if (ret != 0) {
        printf("main: failed to read server parameters from server.in\n");
        return -1;
    }

    /* Initialize the RUDP library */
    ret = rudp_srv_init(&rudp_srv_state);
    if (ret != 0) {
        printf("main: failed to initialize the RUDP library\n");
        return -1;
    }

    /* Setup connections on all the interfaces */
    init_listening_sockets();

    /* Monitor the created sockets using select */
    conn_listen();

    return 0;
}

/* End of File */
