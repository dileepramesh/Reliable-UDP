/*
 * client.c
 *
 * This is the client program which requests file transfer from the
 * server. It uses the RUDP library to get reliable data transfer.
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
#include "client.h"
#include "rudp.h"

/* Globals */
client_params_t *cli_params;
pthread_t rudp_thread;
pthread_t consumer_thread;

/*
 * client_conn_init
 *
 * Create a socket to communicate with the server
 */
static int
client_conn_init (int server_local)
{
    int sockfd, ret, optval = 1, buf_size;
    struct sockaddr_in cli_addr, serv_addr;
    struct sockaddr_in sock_addr;
    int sock_len;
    char buf[IP_LEN];

    /* Create the socket */
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        printf("client_conn_init: failed to create socket on the client (%d)\n",
               errno);
        return -1;
    }

    /* Set buffer size */
    buf_size = (1024 * 1024);
    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &buf_size, 
                   sizeof(buf_size)) < 0) {
        printf("client_conn_init: failed to set recv buf (%d)\n", errno);
        return -1;
    }

    if (setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, &buf_size, 
                   sizeof(buf_size)) < 0) {
        printf("client_conn_init: failed to set send buf (%d)\n", errno);
        return -1;
    }

    /* Set SO_DONTROUTE if the server is local */
    if (server_local) {
        if (setsockopt(sockfd, SOL_SOCKET, SO_DONTROUTE, 
                       &optval, sizeof(optval)) < 0) {
            printf("client_conn_init: failed to set SO_DONTROUTE (%d)\n", 
                   errno);
            return -1;
        }
    }

    /* Bind the socket to the client-ip and an ephemeral port */
    bzero(&cli_addr, sizeof(struct sockaddr_in));
    cli_addr.sin_family = AF_INET;
    cli_addr.sin_port = htons(0);
    if (server_local) {
        inet_pton(AF_INET, cli_params->client_ip, &cli_addr.sin_addr);
    }
    
    ret = bind(sockfd, (struct sockaddr *)(&cli_addr), 
               sizeof(struct sockaddr_in));
    if (ret < 0) {
        printf("client_conn_init: bind failed (%d)\n", errno);
        return -1;
    }

    cli_params->server_fd = sockfd;

    /* Print out the client information */
    sock_len = sizeof(struct sockaddr);
    bzero(&sock_addr, sizeof(struct sockaddr_in));
    getsockname(sockfd, (struct sockaddr *)&sock_addr, &sock_len);

    printf("\nClient socket bound to %s port %d\n", 
           inet_ntop(AF_INET, &sock_addr.sin_addr, buf, IP_LEN), 
           ntohs(sock_addr.sin_port));
    cli_params->client_port = ntohs(sock_addr.sin_port);

    /* Connect to the server */
    bzero(&serv_addr, sizeof(struct sockaddr_in));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(cli_params->server_port);
    inet_pton(AF_INET, cli_params->server_ip, &serv_addr.sin_addr);

    ret = connect(sockfd, (struct sockaddr *)&serv_addr, 
                  sizeof(struct sockaddr));
    if (ret != 0) {
        printf("client_conn_init: failed to connect to server\n");
        return -1;
    }

    /* Print out the server information */
    sock_len = sizeof(struct sockaddr);
    bzero(&sock_addr, sizeof(struct sockaddr_in));
    getpeername(sockfd, (struct sockaddr *)&sock_addr, &sock_len);

    printf("Client socket connected to Server %s port %d\n", 
           inet_ntop(AF_INET, &sock_addr.sin_addr, buf, IP_LEN), 
           ntohs(sock_addr.sin_port));

    return 0;
}

/*
 * reconnect_to_server
 *
 * This function is registered with the RUDP library and is called when the
 * ephimeral port is received from the server. This port will be used for the
 * actual file transfer. Here we reconnect the existing socket with the new
 * port. 
 */
static int
reconnect_to_server (int old_fd, void *new_port, void *addr)
{
    int port, ret;
    struct sockaddr_in *sa = (struct sockaddr_in *)addr;

    /* Store the updated port received from the server */
    port = atoi(new_port);
    cli_params->server_port = port;

    /* Connect to the server */
    bzero(sa, sizeof(struct sockaddr_in));
    sa->sin_family = AF_INET;
    sa->sin_port = htons(cli_params->server_port);
    inet_pton(AF_INET, cli_params->server_ip, &sa->sin_addr);

    ret = connect(old_fd, (struct sockaddr *)sa, sizeof(struct sockaddr));
    if (ret < 0) {
        printf("reconnect_to_server: failed to connect to server (%d)\n",
               errno);
        return -1;
    }

    return 0;
}

/*
 * get_subnet
 *
 * Returns the subnet mask of the given IP. Doesn't check the validity of the
 * address, i.e, only higher order bits have to be set.
 */
static int
get_subnet (in_addr_t addr)
{
    int count = 0;

    /* Return the number of set bits in the address */
    while (addr) {
        addr = addr & (addr - 1);
        count++;
    }

    return count;
}

/*
 * check_server_on_same_network
 *
 * This function checks if the client and server are on the same network.
 * Returns -1 upon error. If they are on the same network, then client
 * parameter will be filled with the corresponding IP.
 */
static int
check_server_on_same_network (char *client)
{
    int i, max_subnet, cur_subnet, is_local;
    char ip[IP_LEN];
    in_addr_t server_addr;

    /* Get the server's socket address from it's IP */
    bzero(&server_addr, sizeof(struct in_addr));
    inet_pton(AF_INET, cli_params->server_ip, &server_addr);
    max_subnet = -1;
    is_local = 0;

    /* Check if any of our IP is on a matching subnet */
    for (i = 0; i < cli_params->iface_count; i++) {
        if ((cli_params->iface[i].netmask.sin_addr.s_addr & server_addr) ==
            cli_params->iface[i].subnet.sin_addr.s_addr) {
            cur_subnet = get_subnet(cli_params->iface[i].netmask.sin_addr.s_addr);
            if (cur_subnet > max_subnet) {
                max_subnet = cur_subnet;
                strncpy(client,
                        inet_ntop(AF_INET, &(cli_params->iface[i].ip.sin_addr),
                                  ip, IP_LEN),
                        IP_LEN);
                is_local = 1;
            }
        }
    }

    return is_local;
}

/*
 * check_server_on_same_host
 *
 * This function returns true if the client and server are on the same host.
 * False otherwise. It returns -1 upon error.
 */
static int
check_server_on_same_host (void)
{
    struct sockaddr_in addr;
    int i;

    /* First check if server-ip is the localhost IP */
    if (strcmp(cli_params->server_ip, LOCALHOST_IP) == 0) {
        return 1;
    }

    /* Get the server's address from it's IP */
    bzero(&addr, sizeof(struct in_addr));
    inet_pton(AF_INET, cli_params->server_ip, &addr.sin_addr);

    /* 
     * Run through the interface list and find if one of the interface 
     * has server-ip. If so, both are on the same host.
     */
    for (i = 0; i < cli_params->iface_count; i++) {
        if (addr.sin_addr.s_addr == cli_params->iface[i].ip.sin_addr.s_addr) {
            return 1;
        }
    }

    return 0;
}

/*
 * check_server_status
 *
 * This function checks if the server resides on the same host / network as
 * that of the client. It sets the client and server IP accordingly. Returns
 * -1 upon failure.
 */
static int
check_server_status (void)
{
    int same_host, same_network, is_local;
    char client_ip[IP_LEN], ip[IP_LEN];

    /*
     * Determine whether the server is on the same host. If so, we have to use
     * loopback address for both client and server.
     */
    same_host = check_server_on_same_host();
    if (same_host < 0) {
        return -1;
    }

    if (same_host) {
        /* Use the loopback address */
        bzero(cli_params->server_ip, IP_LEN);
        bzero(cli_params->client_ip, IP_LEN);
        strncpy(cli_params->server_ip, LOCALHOST_IP, IP_LEN);
        strncpy(cli_params->client_ip, LOCALHOST_IP, IP_LEN);
        is_local = 1;
    } else {
        /* Check whether they are on the same network atleast */
        same_network = check_server_on_same_network(client_ip);
        if (same_network < 0) {
            return -1;
        }

        if (same_network) {
            bzero(cli_params->client_ip, IP_LEN);
            strncpy(cli_params->client_ip, client_ip, IP_LEN);
            is_local = 1;
        } else {
            /*
             * Server and Client are on different networks. Pick the client 
             * address arbitrarily.
             */
            bzero(cli_params->client_ip, IP_LEN);
            strncpy(cli_params->client_ip,
                    inet_ntop(AF_INET, &(cli_params->iface[0].ip.sin_addr),
                              ip, IP_LEN),
                    IP_LEN);
            is_local = 0;
        }
    }

    return is_local;
}

/*
 * get_interface_list
 *
 * This function first scans the list of all the interfaces on the client and
 * stores it's associated IP and Mask.
 */
static int
get_interface_list (void)
{
    int idx = 0;
    struct ifi_info *ifi, *ifihead;
    struct sockaddr_in *sa, *netmask;
    char ip[IP_LEN], mask[IP_LEN], subnet[IP_LEN];

    printf("\nINTERFACE LIST:\n");

    /* Walk through all the interfaces in the system */
    for (ifihead = ifi = Get_ifi_info(AF_INET, 1); ifi != NULL; 
         ifi = ifi->ifi_next) {

        /* Store the connection details in our local conn_info structure */
        sa = (struct sockaddr_in *)ifi->ifi_addr;
        netmask = (struct sockaddr_in *)ifi->ifi_ntmaddr;
        bzero(&cli_params->iface[idx], sizeof(iface_info_t));
        memcpy(cli_params->iface[idx].ifname, ifi->ifi_name, IFNAME_LEN);
        memcpy(&cli_params->iface[idx].ip, sa, sizeof(struct sockaddr_in));
        memcpy(&cli_params->iface[idx].netmask, netmask, 
               sizeof(struct sockaddr_in));
        cli_params->iface[idx].subnet.sin_addr.s_addr = 
            (cli_params->iface[idx].ip.sin_addr.s_addr & 
             cli_params->iface[idx].netmask.sin_addr.s_addr);

        /* Display it! */
        printf("interface: %s ip: %s mask: %s subnet: %s\n", 
               cli_params->iface[idx].ifname,
               inet_ntop(AF_INET, &(cli_params->iface[idx].ip.sin_addr), 
                         ip, IP_LEN), 
               inet_ntop(AF_INET, &(cli_params->iface[idx].netmask.sin_addr), 
                         mask, IP_LEN), 
               inet_ntop(AF_INET, &(cli_params->iface[idx].subnet.sin_addr), 
                         subnet, IP_LEN));

        idx++;
    }

    cli_params->iface_count = idx;

    return 0;
}

/*
 * read_client_params
 *
 * Read the input parameters for the client from the file client.in
 */
static int
read_client_params (rudp_cli_state_t *rudp_cli_state)
{
    int fd, lineno = 1;
    char buf[MAXLINE];
    struct hostent *hostent;

    /* Open the input file */
    fd = open(CLIENT_INPUT, O_RDONLY);
    if (!fd) {
        return -1;
    }

    /* Read the client parameters one line at a time */
    bzero(cli_params, sizeof(client_params_t));
    bzero(rudp_cli_state, sizeof(rudp_cli_state_t));
    bzero(buf, MAXLINE);
    while (readline(fd, buf, MAXLINE)) {
        switch (lineno) {
            case 1:
                strncpy(cli_params->server_ip, buf, IP_LEN);
                cli_params->server_ip[strlen(buf) - 1] = 0;
                break;
            case 2:
                cli_params->server_port = atoi(buf);
                if (cli_params->server_port == 0) {
                    return -1;
                }
                break;
            case 3:
                strncpy(cli_params->file, buf, MAX_FILENAME_LEN);
                cli_params->file[strlen(buf) - 1] = 0;
                break;
            case 4:
                rudp_cli_state->advw_size = atoi(buf);
                if (rudp_cli_state->advw_size == 0) {
                    return -1;
                }
                break;
            case 5:
                rudp_cli_state->random_seed = atoi(buf);
                if (rudp_cli_state->random_seed == 0) {
                    return -1;
                }
                break;
            case 6:
                rudp_cli_state->data_loss_prob = atof(buf);
                break;
            case 7:
                rudp_cli_state->recv_rate = atoi(buf);
                if (rudp_cli_state->recv_rate == 0) {
                    return -1;
                }
                break;
        }
        lineno++;
        bzero(buf, MAXLINE);
    }

    printf("CLIENT PARAMS:\n");
    printf("server ip: %s\n", cli_params->server_ip);
    printf("server port: %d\n", cli_params->server_port);
    printf("filename: %s\n", cli_params->file);
    printf("advertised window: %d\n", rudp_cli_state->advw_size);
    printf("seed value: %d\n", rudp_cli_state->random_seed);
    printf("data loss probability: %f\n", rudp_cli_state->data_loss_prob);
    printf("receive rate (ms): %d\n", rudp_cli_state->recv_rate);

    /* Verify that the server address is sane */
    hostent = gethostbyname(cli_params->server_ip);
    if (!hostent) {
        printf("\nread_client_params: invalid server address\n");
        return -1;
    }

    return 0;
}

/*
 * process_rudp_thread
 *
 * Start routine for the RUDP thread. This thread reads dataa from the server
 * and populates the receive window.
 */
static void *
process_rudp_thread (void *arg)
{
    struct sockaddr_in server_addr;
    int len;

    /* Get the server address */
    len = sizeof(struct sockaddr_in);
    bzero(&server_addr, sizeof(struct sockaddr_in));
    getpeername(cli_params->server_fd, (struct sockaddr *)&server_addr, &len);

    /* 
     * Just call the library function. This function will return only after
     * all the data has been received from the server and we have come out 
     * of the TIME_WAIT state.
     */
    rudp_recv(cli_params->server_fd, (struct sockaddr *)&server_addr, &len);

    /* 
     * We terminate this thread when the server sends us a FIN. So, nothing
     * to do here.
     */
    return NULL;
}

/*
 * process_consumer_thread
 *
 * Start routine for the consumer thread. This thread consumes data from the
 * receive window and prints the content to standard output.
 */
static void *
process_consumer_thread (void *arg)
{
    int total_bytes_read, bytes_read, ivl;
    char buf[FILE_CHUNK_SIZE];
    FILE *fp;

    /* Create a file for writing the output */
    fp = fopen("output_file.txt", "w");

    while (!rudp_cli_transfer_complete()) {

        /* Read the available chunk of data */
        bzero(buf, sizeof(buf));
        bytes_read = rudp_read(buf);

        /* Print the file contents */
        if (bytes_read > 0) {
            /* 
             * Dump the output to a file rather than stdout. It's much
             * cleaner!
             */
            fprintf(fp, "%s", buf);
            total_bytes_read += bytes_read;
        }

        /* 
         * Sleep for some random time before the next read. This will simulate
         * flow-control by filling up the receive window.
         */
        ivl = rudp_cli_get_sleep_interval();
        usleep(ivl);
    }

    printf("\nConsumer thread terminating\n");
    printf("File transfer complete. Total bytes read: %d\n", 
           total_bytes_read);
    printf("Received file contents have been saved to output_file.txt\n");

    /* RUDP thread would have exited by now. So, we too can disappear! */
    fclose(fp);
    exit(0);
}

/* Main entry point */
int
main (int argc, char *argv[])
{
    int ret, is_local, sock_len;
    rudp_cli_state_t rudp_cli_state;
    char buf[MAXLINE];
    struct sockaddr_in server_addr, sock_addr;

    /* Sanity check */
    if (argc != 1) {
        printf("usage: ./client\n");
        return -1;
    }

    /* Initialize the structure for holding client parameters */
    cli_params = (client_params_t *)malloc(sizeof(client_params_t));
    if (!cli_params) {
        printf("main: failed to initialize client parameters\n");
        return -1;
    }

    /* Read the client parameters from client.in */
    ret = read_client_params(&rudp_cli_state);
    if (ret != 0) {
        printf("main: failed to read client parameters from client.in\n");
        return -1;
    }

    /* Initialize the RUDP library */
    ret = rudp_cli_init(&rudp_cli_state);
    if (ret != 0) {
        printf("main: failed to initialize the RUDP library\n");
        return -1;
    }

    /* Get the list of interfaces on the system and cache it */
    ret = get_interface_list();
    if (ret != 0) {
        printf("main: failed to get interface list\n");
        return -1;
    }

    is_local = check_server_status();
    if (is_local < 0) {
        printf("main: failed to check status of server\n");
        return -1;
    }

    if (is_local == 1) {
        printf("\nServer and Client are on the same network (Local)\n");
    } else {
        printf("\nServer and Client are not on the same network (Non-Local)\n");
    }
    cli_params->server_local = is_local;

    /* Initialize the connection with server */
    ret = client_conn_init(is_local);
    if (ret != 0) {
        printf("main: failed to initialize connection wth server\n");
        return -1;
    }

    printf("Selected Server: %s (%d)\n", 
           cli_params->server_ip, cli_params->server_port);
    printf("Selected Client: %s (%d)\n", 
           cli_params->client_ip, cli_params->client_port);

    bzero(&server_addr, sizeof(struct sockaddr_in));
    inet_pton(AF_INET, cli_params->server_ip, &server_addr.sin_addr);
    server_addr.sin_port = htons(cli_params->server_port);

    /* Send the filename to be transferred to the server */
    ret = rudp_cli_conn_send(cli_params->server_fd, &server_addr, 
                             cli_params->file, MAX_FILENAME_LEN,
                             buf, MAXLINE, reconnect_to_server);
    if (ret < 0) {
        printf("main: failed to send filename to server\n");
        return -1;
    }

    /* Store the new server port */
    cli_params->server_port = atoi(buf);

    /* Print the new server information post reconnect */
    sock_len = sizeof(struct sockaddr);
    bzero(&sock_addr, sizeof(struct sockaddr_in));
    getpeername(cli_params->server_fd, (struct sockaddr *)&sock_addr, 
                &sock_len);

    printf("\nSocket reconnected to client %s port %d\n",
           inet_ntop(AF_INET, &sock_addr.sin_addr, buf, IP_LEN),
           ntohs(sock_addr.sin_port));

    printf("\nInitiated File transfer with the Server\n\n");

    /* 
     * Create 2 threads, one for reading data from the server and populating
     * the receive buffer, another for consuming the data and printing to
     * stdout.
     */
    pthread_create(&rudp_thread, NULL, process_rudp_thread, NULL);
    pthread_create(&consumer_thread, NULL, process_consumer_thread, NULL);

    /* Wait till they terminate */
    pthread_join(rudp_thread, NULL);
    pthread_join(consumer_thread, NULL);

    return 0;
}

/* End of File */
