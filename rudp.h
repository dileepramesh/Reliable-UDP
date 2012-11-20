/*
 * rudp.h - Private header for the protocol layer
 *
 * October 2012
 */

#ifndef RUDP_H
#define RUDP_H

#include "./unpv13e_solaris2.10/lib/unp.h"
#include "./unpv13e_solaris2.10/lib/unprtt.h"

/* Defines */

#define RUDP_PAYLOAD_SIZE               512
#define RUDP_TIME_WAIT_INTERVAL         5
#define RUDP_PERSIST_TIMER_INTERVAL     5
#define RUDP_CLIENT_TIMEOUT             60
#define RUDP_DEFAULT_SSTHRESH           65535

#define CONGESTION_STATE_SLOW_START     0
#define CONGESTION_STATE_AVOIDANCE      1

#define MSG_TYPE_FILENAME               1
#define MSG_TYPE_CONNECTION_PORT        2
#define MSG_TYPE_FILE_DATA              3
#define MSG_TYPE_ACKNOWLEDGEMENT        4
#define MSG_TYPE_FIN                    5
#define MSG_TYPE_WINDOW_PROBE           6
#define MSG_TYPE_ERROR_INVALID_FILE     7

/* Datastructures */

typedef struct rudp_payload_s {
    uint8_t     *data;
    uint8_t     valid;
    uint16_t    data_size;
} rudp_payload_t;

typedef struct rudp_srv_state_s {
    uint32_t        cwnd_size;
    uint32_t        max_cwnd_size;
    uint32_t        advw_size;
    uint32_t        cwnd_free;
    uint32_t        ss_thresh;
    uint32_t        cwnd_start;
    uint32_t        cwnd_end;
    uint32_t        expected_ack;
    uint32_t        num_acks;
    uint32_t        rudp_state;
    uint32_t        num_dup_acks;
    uint32_t        last_dup_ack;
    rudp_payload_t  *cwnd;
} rudp_srv_state_t;

typedef struct rudp_cli_state_s {
    uint32_t    advw_size;
    uint32_t    advw_start;
    uint32_t    advw_end;
    uint32_t    advw_free;
    uint32_t    expected_seq;
    int         random_seed;
    double      data_loss_prob;
    int         recv_rate;
    uint8_t     fin_received;
    rudp_payload_t  *advw;
    pthread_mutex_t advw_lock;
} rudp_cli_state_t;

/* Function prototypes */

int rudp_srv_init (rudp_srv_state_t *state);
int rudp_srv_destroy (void);
int rudp_srv_conn_send (int fd1, int fd2, struct sockaddr_in *peer_addr, 
                        void *data, int size);
int rudp_srv_conn_recv (int fd, void *buf, int size, 
                        struct sockaddr *src_addr, 
                        int *src_len);
int rudp_send (int fd, void *buf, int size);
int rudp_close (int fd);
int rudp_send_ctrl_packet (int fd, int msg_type);

int rudp_cli_init (rudp_cli_state_t *state);
int rudp_cli_destroy (void);
int rudp_cli_conn_send (int fd, struct sockaddr_in *peer_addr, 
                        void *data, int size, void *recv_data, int recv_size,
                        int (*reconnect_fn)(int, void *, void *));
int rudp_cli_get_sleep_interval (void);
int rudp_cli_transfer_complete (void);
int rudp_read (char *buf);
int rudp_recv (int fd, struct sockaddr *src_addr, int *src_len);

#endif /* RUDP_H */
