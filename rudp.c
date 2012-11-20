/*
 * rudp.c
 *
 * This implements a reliability layer on top of UDP. Both the server and
 * client programs use this protocol layer to achieve file transfers reliably.
 *
 * October 2012
 */

/* Includes */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>
#include <pthread.h>
#include <math.h>
#include <assert.h>
#include <setjmp.h>
#include <sys/time.h>
#include "rudp.h"

/* Globals */
rudp_srv_state_t *srv_state;
rudp_cli_state_t *cli_state;
static struct rtt_info rttinfo;
static int rttinit = 0;
static struct msghdr msgsend, msgrecv;
static sigjmp_buf jmpbuf;

/* Header prepended to each UDP datagram - For reliability */
static struct hdr {
    uint32_t msg_type;
    uint32_t seq;
    uint32_t ts;
    uint32_t window_size;
} sendhdr, recvhdr;

/* Defines */
#define FILE_PAYLOAD_SIZE       (RUDP_PAYLOAD_SIZE - sizeof(struct hdr))
#define GET_MIN(A, B) ((A) < (B) ? (A) : (B))

/****************************************************************************/
/*           Common routines related to both Server and Client              */
/****************************************************************************/

/*
 * sigalarm_handler
 *
 * Handler for SIGALRM. We just set the jmpbuf here inorder to avoid race
 * conditions.
 */
static void 
sigalarm_handler (int signo)
{
    siglongjmp(jmpbuf, 1);
}

/*
 * rudp_start_timer
 *
 * Start a timer with the specified interval
 */
static void
rudp_start_timer (uint32_t ivl)
{
    struct itimerval timer;

    timer.it_interval.tv_sec = 0;
    timer.it_interval.tv_usec = 0;
    timer.it_value.tv_sec = (ivl / USEC_IN_SEC);
    timer.it_value.tv_usec = (ivl % USEC_IN_SEC);
    setitimer(ITIMER_REAL, &timer, 0);
}

/*
 * rudp_stop_timer
 *
 * Stop a currently running timer
 */
static void
rudp_stop_timer (void)
{
    struct itimerval timer;

    timer.it_interval.tv_sec = 0;
    timer.it_interval.tv_usec = 0;
    timer.it_value.tv_sec = 0;
    timer.it_value.tv_usec = 0;
    setitimer(ITIMER_REAL, &timer, 0);
}

/****************************************************************************/
/*                       Server related routines                            */
/****************************************************************************/

/*
 * rudp_srv_init
 *
 * Initializes the RUDP layer for the server
 */
int
rudp_srv_init (rudp_srv_state_t *state)
{
    int i;

    /* Initialize the parameters based on what is sent by the server */
    srv_state = (rudp_srv_state_t *)malloc(sizeof(rudp_srv_state_t));
    if (!srv_state) {
        return -1;
    }

    bzero(srv_state, sizeof(rudp_srv_state_t));

    /* Initialize the state parameters */
    srv_state->max_cwnd_size = state->max_cwnd_size;
    srv_state->cwnd_size = 1; /* CW starts with size 1 in slow start phase */
    srv_state->cwnd_free = srv_state->cwnd_size;
    srv_state->ss_thresh = RUDP_DEFAULT_SSTHRESH;
    srv_state->cwnd_start = 0;
    srv_state->cwnd_end = 0;
    srv_state->expected_ack = 1; /* First packet sent has sequence number 0 */
    srv_state->num_acks = 0;
    srv_state->num_dup_acks = 0;
    srv_state->last_dup_ack = 0;
    srv_state->rudp_state = CONGESTION_STATE_SLOW_START;

    /* Initialize the congestion window */
    srv_state->cwnd = 
        (rudp_payload_t *)malloc(srv_state->max_cwnd_size * 
                                 sizeof(rudp_payload_t));
    if (!srv_state->cwnd) {
        return -1;
    }
    bzero(srv_state->cwnd, srv_state->max_cwnd_size * sizeof(rudp_payload_t));

    for (i = 0; i < srv_state->max_cwnd_size; i++) {
        srv_state->cwnd[i].data = (char *)malloc(RUDP_PAYLOAD_SIZE);
        if (!srv_state->cwnd[i].data) {
            return -1;
        }
        bzero(srv_state->cwnd[i].data, RUDP_PAYLOAD_SIZE);
    }

    /* Register for SIGALRM to handle timeouts */
    signal(SIGALRM, sigalarm_handler);

    return 0;
}

/*
 * rudp_srv_destroy
 *
 * Cleans up the resources allocated to the RUDP layer on the server
 */
int
rudp_srv_destroy (void)
{
    int i;

    /* Free the allocated resources */
    if (srv_state) {
        if (srv_state->cwnd) {
            for (i = 0; i < srv_state->max_cwnd_size; i++) {
                if (srv_state->cwnd[i].data) {
                    free(srv_state->cwnd[i].data);
                }
            }
        }
        free(srv_state->cwnd);
        free(srv_state);
    }

    return 0;
}

/*
 * rudp_srv_conn_send
 *
 * This is used by the server during the initial connection setup phase.
 * The server uses this to send the ephimeral port to client and to receive
 * the acknowledgement for that.
 */
int
rudp_srv_conn_send (int fd1, int fd2, struct sockaddr_in *peer_addr, 
                    void *data, int size)
{
    int n, timeout = 0, len = sizeof(struct sockaddr);
    struct iovec iovsend[2], iovrecv[1];

    /* Initialize the RTT library if we are coming here for the first time */
    if (rttinit == 0) {
        rtt_init(&rttinfo);
        rttinit = 1;
        rtt_d_flag = 1;
    }

    bzero(&msgsend, sizeof(struct msghdr));
    bzero(&msgrecv, sizeof(struct msghdr));

    /* Send the connection port to the client */
    sendhdr.msg_type = htonl(MSG_TYPE_CONNECTION_PORT);
    msgsend.msg_name = peer_addr;
    msgsend.msg_namelen = len;
    msgsend.msg_iov = iovsend;
    msgsend.msg_iovlen = 2;

    iovsend[0].iov_base = (void *)&sendhdr;
    iovsend[0].iov_len = sizeof(struct hdr);
    iovsend[1].iov_base = data;
    iovsend[1].iov_len = size;

    /* Initialize the receive parameters for getting the acknowledgement */
    msgrecv.msg_name = peer_addr;
    msgrecv.msg_namelen = len;
    msgrecv.msg_iov = iovrecv;
    msgrecv.msg_iovlen = 1;

    iovrecv[0].iov_base = (void *)&recvhdr;
    iovrecv[0].iov_len = sizeof(struct hdr);

    /* Initialize the retransmission count to 0 */
    rtt_newpack(&rttinfo);

    printf("\nSending connection port to client\n");

    /* Send it till we exceed the number of retries */
send_again:

    /* 
     * Send it out on both connection and listening sockets in case of a
     * timeout 
     */
    sendhdr.ts = htonl(rtt_ts(&rttinfo));
    msgsend.msg_name = peer_addr;
    msgsend.msg_namelen = len;
    sendmsg(fd1, &msgsend, 0);
    if (timeout == 1) {
        /* Recepient should be NULL if socket is connected */
        msgsend.msg_name = NULL;
        msgsend.msg_namelen = 0;
        sendmsg(fd2, &msgsend, 0);
    }

    /* Start the timer */
    rudp_start_timer(rtt_start(&rttinfo));

    if (sigsetjmp(jmpbuf, 1) != 0) {
        if (rtt_timeout(&rttinfo) < 0) {
            printf("rudp_serv_conn_send: no response from peer. giving up.\n");
            rttinit = 0;
            errno = ETIMEDOUT;
            return -1;
        }
        printf("rudp_serv_conn_send: request timed out. retransmitting..\n");
        timeout = 1;
        goto send_again;
    }

    /* We will receive the acknowledgement on the connection socket */
    do {
        n = recvmsg(fd2, &msgrecv, 0);
    } while (ntohl(recvhdr.msg_type) != MSG_TYPE_ACKNOWLEDGEMENT);

    /* Store the window size advertised by the client */
    srv_state->advw_size = ntohl(recvhdr.window_size);
    srv_state->ss_thresh = srv_state->advw_size;

    /* Stop the timer */
    rudp_stop_timer();

    /* Calculate & store new RTT estimator values */
    rtt_stop(&rttinfo, rtt_ts(&rttinfo) - ntohl(recvhdr.ts));

    /* Return the actual number of bytes read */
    return (n - sizeof(struct hdr));
}

/*
 * rudp_srv_conn_recv
 *
 * This is called during the initial connection setup phase. This is called by
 * the server to receive the filename from the client.
 */
int
rudp_srv_conn_recv (int fd, void *buf, int size, struct sockaddr *src_addr, 
                    int *src_len)
{
    int bytes_read;
    struct iovec iovrecv[2];

    /* Initialize the RTT library if we are coming here for the first time */
    if (rttinit == 0) {
        rtt_init(&rttinfo);
        rttinit = 1;
        rtt_d_flag = 1;
    }

    bzero(&msgrecv, sizeof(struct msghdr));

    /* Initialize the receive buffer */
    msgrecv.msg_name = src_addr;
    msgrecv.msg_namelen = *src_len;
    msgrecv.msg_iov = iovrecv;
    msgrecv.msg_iovlen = 2;

    iovrecv[0].iov_base = (void *)&recvhdr;
    iovrecv[0].iov_len = sizeof(struct hdr);
    iovrecv[1].iov_base = buf;
    iovrecv[1].iov_len = size;

    /* Block till we get a response */
    do {
        bytes_read = recvmsg(fd, &msgrecv, 0);
    } while (ntohl(recvhdr.msg_type) != MSG_TYPE_FILENAME);

    /* Return the actual number of bytes read to the caller */
    return (bytes_read - sizeof(struct hdr) - *src_len);
}

/*
 * rudp_send_ctrl_packet
 *
 * This function is called when we want to send control messages to the
 * receiver, like window probes, fin or some error.
 */
int
rudp_send_ctrl_packet (int fd, int msg_type)
{
    struct iovec iovsend[1];

    sendhdr.msg_type = htonl(msg_type);
    msgsend.msg_name = NULL;
    msgsend.msg_namelen = 0;
    msgsend.msg_iov = iovsend;
    msgsend.msg_iovlen = 1;

    iovsend[0].iov_base = (void *)&sendhdr;
    iovsend[0].iov_len = sizeof(struct hdr);

    sendmsg(fd, &msgsend, 0);

    return 0;
}

/*
 * rudp_send_data_packet
 *
 * Form a packet from the given parameters and send it to the peer
 */
static int
rudp_send_data_packet (int fd, struct hdr *packet_hdr, char *buffer, int len,
                       int retransmit)
{
     struct iovec iovsend[2];
     int ret = 0;
     
     if (retransmit == 0) {
        printf("sending packet with seq %d\n", ntohl(packet_hdr->seq));
     } else {
        printf("resending packet with seq %d\n", ntohl(packet_hdr->seq));
     }

     bzero(&msgsend, sizeof(struct msghdr));
     msgsend.msg_name = NULL;
     msgsend.msg_namelen = 0;
     msgsend.msg_iov = iovsend;
     msgsend.msg_iovlen = 2;
    
     iovsend[0].iov_base = (void *)packet_hdr;
     iovsend[0].iov_len = sizeof(struct hdr);
     iovsend[1].iov_base = (void *)buffer;
     iovsend[1].iov_len = len - sizeof(struct hdr);

     ret = sendmsg(fd, &msgsend, 0);
     if (ret < 0 ) {
         perror("rudp_send_data_packet: sendmsg failed : ");
         return ret;
     }

     return len;
}

/*
 * add_packet_to_cwnd
 *
 * Form the packet from the given parameters and add it to the congestion
 * window
 */
static int 
add_packet_to_cwnd (struct hdr *packet_hdr, char * buffer, int len)
{
    char *ptr = NULL;

    /* Sanity check */
    assert(srv_state->cwnd[srv_state->cwnd_end].valid == 0);

    /* New packet always goes to where cwnd_end is pointing */
    srv_state->cwnd[srv_state->cwnd_end].valid = 1;
    srv_state->cwnd[srv_state->cwnd_end].data_size = len;

    ptr = (char*)srv_state->cwnd[srv_state->cwnd_end].data;
    memcpy(ptr, packet_hdr, sizeof(struct hdr));
    memcpy(ptr + sizeof(struct hdr), buffer, len - sizeof(struct hdr));

    srv_state->cwnd_free--;
    srv_state->cwnd_end = (srv_state->cwnd_end + 1) % srv_state->cwnd_size;

    return 0;
}

/*
 * find_packet_count
 *
 * Determine the number of packets that can be sent based on the congestion
 * window and advertised window state.
 */
static inline int 
find_packet_count (void)
{
    int num = GET_MIN(srv_state->advw_size, srv_state->cwnd_free);
    return num;
}

/*
 * update_cwnd_after_timeout
 *
 * This is called when a sent packet is lost or the corresponding
 * acknowledgement is lost. Here, we shrink the congestion window to the new
 * size passed and update the window parameters accordingly.
 */
static void
update_cwnd_after_timeout (int new_cwnd_size, int new_ss_thresh, 
                           int new_state, int *buffer_ptr, 
                           int *bytes_remaining,
                           int *seq, int *pending_acks)
{
    int i, idx, bytes, start, old_window_size, valid;
    rudp_payload_t *new_cwnd;

    /* Allocate a new window copy */
    new_cwnd = (rudp_payload_t *)malloc(srv_state->max_cwnd_size *
                                 sizeof(rudp_payload_t));
    if (!new_cwnd) {
        printf("update_cwnd_after_timeout: no memory\n");
        assert(0);
    }
    bzero(new_cwnd, srv_state->max_cwnd_size * sizeof(rudp_payload_t));

    for (i = 0; i < srv_state->max_cwnd_size; i++) {
        new_cwnd[i].data = (char *)malloc(RUDP_PAYLOAD_SIZE);
        if (!new_cwnd[i].data) {
            printf("update_cwnd_after_timeout: no memory\n");
            assert(0);
        }
        bzero(new_cwnd[i].data, RUDP_PAYLOAD_SIZE);
    }

    /* Copy relevant packets from the old copy */
    idx = srv_state->cwnd_start;
    valid = 0;
    for (i = 0; i < new_cwnd_size; i++) {
        if (srv_state->cwnd[idx].valid == 0) {
            break;
        }

        new_cwnd[i].valid = srv_state->cwnd[idx].valid;
        new_cwnd[i].data_size = srv_state->cwnd[idx].data_size;
        memcpy(new_cwnd[i].data, srv_state->cwnd[idx].data, 
               RUDP_PAYLOAD_SIZE);
        idx = (idx + 1) % srv_state->cwnd_size;
        valid++;
    }
    start = srv_state->cwnd_start;
    *seq = ntohl(((struct hdr *)(srv_state->cwnd[start].data))->seq) + valid;
    srv_state->cwnd_free = new_cwnd_size - valid;

    /*
     * Compute how many data bytes we have to copy back from the buffer
     * again and update the buffer pointer accordingly.
     */
    bytes = 0;
    while (srv_state->cwnd[idx].valid) {
        bytes += (srv_state->cwnd[idx].data_size - sizeof(struct hdr));
        idx = (idx + 1) % srv_state->cwnd_size;
        if (idx == srv_state->cwnd_start) {
            break;
        }
    }
    *buffer_ptr -= bytes;
    *bytes_remaining += bytes;

    /* Free the old window and replace it with the new one */
    for (i = 0; i < srv_state->max_cwnd_size; i++) {
        if (srv_state->cwnd[i].data) {
            free(srv_state->cwnd[i].data);
        }
    }
    free(srv_state->cwnd);
    srv_state->cwnd = new_cwnd;

    /* Update the window parameters */
    old_window_size = srv_state->cwnd_size;
    srv_state->ss_thresh = new_ss_thresh;
    srv_state->cwnd_size = new_cwnd_size;
    srv_state->cwnd_start = 0;
    srv_state->cwnd_end = 0;
    srv_state->num_acks = 0;
    srv_state->num_dup_acks = 0;
    srv_state->rudp_state = new_state;

    /*
     * Update pending acks count. TODO see if we can update it intelligently
     * instead of walking the whole window.
     */
    idx = 0;
    *pending_acks = 0;
    for (i = 0; i < srv_state->cwnd_size; i++) {
        if (srv_state->cwnd[i].valid == 0) {
            idx = i;
            break;
        }
        *pending_acks = *pending_acks + 1;
    }
    srv_state->cwnd_end = idx;

    /* Debug */
    if (new_state == CONGESTION_STATE_SLOW_START) {
        printf("ENTERED SLOW START PHASE\n");
    } else {
        printf("ENTERED CONGESTION AVOIDANCE PHASE\n");
    }
    printf("shrinking congestion window from %d to %d. new ss_thresh: %d\n", 
           old_window_size, srv_state->cwnd_size, srv_state->ss_thresh);
}

/*
 * update_cwnd_after_valid_ack
 *
 * This is called to update the congestion window parameters whenever we
 * receive a valid ack.
 */
static void
update_cwnd_after_valid_ack (void)
{
    int i, src_idx, dest_idx;
    rudp_payload_t *new_cwnd;

    /* Allocate a new copy of the congestion window */
    new_cwnd = (rudp_payload_t *)malloc(srv_state->max_cwnd_size *
                                 sizeof(rudp_payload_t));
    if (!new_cwnd) {
        printf("update_cwnd_after_valid_ack: no memory\n");
        assert(0);
    }
    bzero(new_cwnd, srv_state->max_cwnd_size * sizeof(rudp_payload_t));

    for (i = 0; i < srv_state->max_cwnd_size; i++) {
        new_cwnd[i].data = (char *)malloc(RUDP_PAYLOAD_SIZE);
        if (!new_cwnd[i].data) {
            printf("update_cwnd_after_valid_ack: no memory\n");
            assert(0);
        }
        new_cwnd[i].valid = 0;
        bzero(new_cwnd[i].data, RUDP_PAYLOAD_SIZE);
    }

    /* Copy relevant packets from old to new copy */
    src_idx = srv_state->cwnd_start;
    dest_idx = 0;

    while (srv_state->cwnd[src_idx].valid) {
        new_cwnd[dest_idx].valid = srv_state->cwnd[src_idx].valid;
        new_cwnd[dest_idx].data_size = srv_state->cwnd[src_idx].data_size;
        memcpy(new_cwnd[dest_idx].data, srv_state->cwnd[src_idx].data,
               RUDP_PAYLOAD_SIZE);
        src_idx = (src_idx + 1) % srv_state->cwnd_size;
        dest_idx = (dest_idx + 1) % srv_state->cwnd_size;
    }

    /* Free the old copy and replace it with the new one */
    for (i = 0; i < srv_state->max_cwnd_size; i++) {
        if (srv_state->cwnd[i].data) {
            free(srv_state->cwnd[i].data);
        }
    }
    free(srv_state->cwnd);
    srv_state->cwnd = new_cwnd;

    /* Update the free window slots and update the window parameters */
    srv_state->cwnd_free = 0;
    for (i = 0; i < srv_state->cwnd_size; i++) {
        if (srv_state->cwnd[i].valid == 0) {
            srv_state->cwnd_free++;
        }
    }

    srv_state->cwnd_start = 0;
    srv_state->cwnd_end = dest_idx;
}

/*
 * update_cwnd_size_after_valid_ack
 *
 * This routine updates the size of the congestion window based on the number
 * of acknowledgements received.
 */
static void
update_cwnd_size_after_valid_ack (uint32_t num_rcvd_acks)
{
    if (srv_state->rudp_state == CONGESTION_STATE_SLOW_START) {
        if (srv_state->cwnd_size < srv_state->max_cwnd_size) {
            srv_state->cwnd_size += num_rcvd_acks;
            if (srv_state->cwnd_size > srv_state->max_cwnd_size) {
                srv_state->cwnd_size = srv_state->max_cwnd_size;
            }
        }
    } else {
        if (srv_state->num_acks >= srv_state->cwnd_size) {
            if (srv_state->cwnd_size < srv_state->max_cwnd_size) {
                srv_state->cwnd_size += num_rcvd_acks;
                if (srv_state->cwnd_size > srv_state->max_cwnd_size) {
                    srv_state->cwnd_size = srv_state->max_cwnd_size;
                }
            }
            srv_state->num_acks = 0;
        }
    }

    if (srv_state->rudp_state == CONGESTION_STATE_SLOW_START &&
        srv_state->cwnd_size > srv_state->ss_thresh) {
        printf("ENTERED CONGESTION AVOIDANCE\n");
        srv_state->rudp_state = CONGESTION_STATE_AVOIDANCE;
    }
}

/*
 * print_cwnd
 *
 * Print the congestion window 
 */
static void
print_cwnd (void)
{
    int i;

    printf("start %d end %d size %d\n", 
           srv_state->cwnd_start, srv_state->cwnd_end, srv_state->cwnd_size);

    for (i = 0; i < srv_state->cwnd_size; i++) {
        printf("%d ", ntohl(((struct hdr *)(srv_state->cwnd[i].data))->seq));
    }
    printf("\n");
}

/*
 * rudp_handle_ack
 *
 * This is called when we receive acks for multiple packets. This can happen
 * during network congestion when packets arrive out of order. Depending on
 * what state our congestion window is in and how many acks are received, we
 * need to update our window state carefully.
 */
static void
rudp_handle_ack (uint32_t received_ack, uint32_t num_acks,
                            int *pending_acks)
{
    int i, idx;
    uint32_t start, end, free, size, exp_ack, start_seq, last_seq;

    start =  srv_state->cwnd_start;
    end = srv_state->cwnd_end;
    free = srv_state->cwnd_free;
    size = srv_state->cwnd_size;
    exp_ack = srv_state->expected_ack;

    if (end == 0) {
        end = size - 1;
    } else {
        end--;
    }
    last_seq = ntohl(((struct hdr *)(srv_state->cwnd[end].data))->seq);
    start_seq = ntohl(((struct hdr *)(srv_state->cwnd[start].data))->seq);

    /* Case 1: We have received a single ack */
    if (num_acks == 1) {
        srv_state->cwnd[srv_state->cwnd_start].valid = 0;
        srv_state->cwnd_free++;
        srv_state->num_acks++;
        srv_state->cwnd_start = 
            (srv_state->cwnd_start + 1) % srv_state->cwnd_size;
        *pending_acks = *pending_acks - 1;
        srv_state->expected_ack += 1;
        return;
    }

    /* Case 2: All the acked packets are in the congestion window */
    if ((start_seq + num_acks) <= (last_seq + 1)) {
        printf("cum_ack: case 1\n");
        for (i = 0; i < num_acks; i++) {
            srv_state->cwnd[srv_state->cwnd_start].valid = 0;
            srv_state->cwnd_free++;
            srv_state->num_acks++;
            srv_state->cwnd_start = 
                (srv_state->cwnd_start + 1) % srv_state->cwnd_size;
            *pending_acks = *pending_acks - 1;
            srv_state->expected_ack += 1;
        }

        return;
    }

    /* 
     * Case 3: The packet corresponding to the received ack is not in the
     * congestion window. This can happen during congestion when we have
     * shrunk the congestion window. In this case, all the packets in our
     * congestion window has been acked.
     */
    if (received_ack >= (last_seq + 1)) {
        printf("cum_ack: case 2\n");
        idx = start;
        while (1) {
            if (srv_state->cwnd[idx].valid == 0) {
                break;
            }
            srv_state->cwnd[idx].valid = 0;
            srv_state->cwnd_free++;
            srv_state->num_acks++;
            *pending_acks = *pending_acks - 1;
            srv_state->expected_ack += 1;
            idx = (idx + 1) % srv_state->cwnd_size;
        }

        return;
    }
}

/*
 * retransmit_first_unacked_packet
 *
 * This routine retransmits the packet pointed to by cwnd_start. This is
 * invoked in case of a timeout or fast retransmit.
 */
static void
retransmit_first_unacked_packet (int fd)
{
    rudp_payload_t *payload;

    payload = &srv_state->cwnd[srv_state->cwnd_start];
    rudp_send_data_packet(fd, (struct hdr *)payload->data,
                          (void *)(payload->data + sizeof(struct hdr)),
                          payload->data_size, 1);
}

/*
 * retransmit_unacked_packets
 *
 * This function takes the start and end indices of the congestion window and
 * retransmits all the packets in that range. This is invoked when we are
 * coming out of the persist mode.
 */
static void
retransmit_unacked_packets (int fd, uint32_t recv_win_size)
{
    int i, idx;
    uint32_t start, end, start_seq, end_seq, num_packets;
    rudp_payload_t *payload;

    start = srv_state->cwnd_start;
    end = srv_state->cwnd_end; /* end points to the first free slot */
    if (end == 0) {
        end = srv_state->cwnd_size - 1;
    } else {
        end -= 1;
    }

    start_seq = ntohl(((struct hdr *)(srv_state->cwnd[start].data))->seq);
    end_seq = ntohl(((struct hdr *)(srv_state->cwnd[end].data))->seq);

    num_packets = end_seq - start_seq + 1;
    num_packets = GET_MIN(num_packets, recv_win_size);

    idx = srv_state->cwnd_start;
    for (i = 0; i < num_packets; i++) {
        assert(srv_state->cwnd[idx].valid == 1);
        payload = &srv_state->cwnd[idx];
        rudp_send_data_packet(fd, (struct hdr *)payload->data,
                              (void *)(payload->data + sizeof(struct hdr)),
                              payload->data_size, 1);
        idx = (idx + 1) % srv_state->cwnd_size;
    }
}

/*
 * rudp_send
 *
 * This functions sends a chunk of data to the remote end reliably by
 * implementing TCP like flow-control and congestion-control techniques. We
 * return from this function only when we have successfully transmitted all
 * the 'size' bytes of the passed buffer.
 */
int
rudp_send (int fd, void *filebuf, int size)
{
    static int current_sequence_number;
    int bytes_remaining = size;
    struct hdr packet_hdr;
    uint8_t timeout, retransmit, persist_mode, num_extra_free;
    uint32_t num_packets = 0;
    char buffer[FILE_PAYLOAD_SIZE];
    struct iovec iovrecv[1];
    int i, j, n, ret, len, offset = 0;
    int num_slots, num_rcvd_acks, ss_thresh, idx, pending_acks = 0;

    /* 
     * Keep sending in chunks of RUDP_PAYLOAD_SIZE bytes till we finish
     * sending everything reliably.
     */
    while (bytes_remaining || pending_acks) {
        
        /* Reset state parameters */
        timeout = 0;
        retransmit = 0;
        persist_mode = 0;

        /* Figure out how many packets to send */
        num_packets = find_packet_count();

        /* Do we have enough data to send num_packets ? */
        num_slots = (int)ceil((double)bytes_remaining / FILE_PAYLOAD_SIZE);
        num_packets = GET_MIN(num_packets, num_slots);
        printf("num_packets: %d cwnd_free %d slots %d\n", 
               num_packets, srv_state->cwnd_free, num_slots);

        /* Initialize the retransmission count to 0 */
        rtt_newpack(&rttinfo);

        /* Send all the packets */
        for (i = 0; i < num_packets; i++) {

            /* Construct the header */
            packet_hdr.msg_type = htonl(MSG_TYPE_FILE_DATA);
            packet_hdr.ts = htonl(rtt_ts(&rttinfo));
            packet_hdr.seq = htonl(current_sequence_number);
            current_sequence_number++;
            packet_hdr.window_size = htons(0);

            /*
             * Copy appropriate number of bytes from user buffer to send
             * buffer 
             */
            len = (bytes_remaining >= FILE_PAYLOAD_SIZE) ? FILE_PAYLOAD_SIZE : 
                   bytes_remaining;
            memcpy(buffer, filebuf + offset, len); 
            offset += len;
            bytes_remaining -= len;
            pending_acks++;

            /* 
             * Now add this packet to cwnd.
             * Note : this function should not return error.
             */
            ret = add_packet_to_cwnd(&packet_hdr, buffer, 
                                     len + sizeof(struct hdr));
            assert(ret == 0);

            /* Now send the packet */
            rudp_send_data_packet(fd, &packet_hdr, buffer, 
                                  len + sizeof(struct hdr), 0);
        }

        /* 
         * If we don't have anything to send and we have pending
         * acknowledgements, just retransmit the first unacknowledged packet
         * instead of waiting for the timeout and shrinking the congestion
         * window. Not doing this optimization for now.
         */

send_again:

        /* Did we timeout */
        if (timeout == 1) {
            /* Are we in persist mode */
            if (persist_mode) {
                /* Send a probe message */
                printf("rudp_send: sending window probe message\n");
                rudp_send_ctrl_packet(fd, MSG_TYPE_WINDOW_PROBE);
            } else {
                /* Retransmit the last packet sent */
                retransmit_first_unacked_packet(fd);

                /* 
                 * We have to reduce congestion window to ss_thresh. Compute
                 * the new ss_thresh. Also update the window parameters and
                 * buffer pointer.
                 */
                if (srv_state->cwnd_size > 1) {
                    ss_thresh = srv_state->cwnd_size / 2;
                    update_cwnd_after_timeout(1, ss_thresh, 
                                              CONGESTION_STATE_SLOW_START,
                                              &offset, &bytes_remaining,
                                              &current_sequence_number, 
                                              &pending_acks);
                }
                //print_cwnd();
                retransmit = 1;
            }

            timeout = 0;
        }

        /* Start the timer */
        if (persist_mode) {
            rudp_start_timer(RUDP_PERSIST_TIMER_INTERVAL * USEC_IN_SEC);
        } else {
            rudp_start_timer(rtt_start(&rttinfo));
        }

        if (sigsetjmp(jmpbuf, 1) != 0) {
            if (rtt_timeout(&rttinfo) < 0) {
                printf("rudp_send: no response from peer. giving up.\n");
                rttinit = 0;
                errno = ETIMEDOUT;
                return -1;
            }
            printf("rudp_send: request timed out. retransmitting..\n");
            timeout = 1;
            goto send_again;
        }

        /* Initialize the receive parameters for getting the acknowledgement */
        msgrecv.msg_name = NULL;
        msgrecv.msg_namelen = 0;
        msgrecv.msg_iov = iovrecv;
        msgrecv.msg_iovlen = 1;
        iovrecv[0].iov_base = (void *)&recvhdr;
        iovrecv[0].iov_len = sizeof(struct hdr);

        /* Block till we get a response */
        n = recvmsg(fd, &msgrecv, 0);

        /* Check for duplicate acknowledgements */
        if (ntohl(recvhdr.seq) < srv_state->expected_ack) {
            if (persist_mode == 0) {

                srv_state->num_dup_acks++;
                if (srv_state->num_dup_acks == 3) {

                    /* Stop the timer */
                    rudp_stop_timer();

                    srv_state->num_dup_acks = 0;

                    if (srv_state->last_dup_ack != ntohl(recvhdr.seq)) {

                        printf("rudp_send: received dup ack %d (%d) window %d. "
                               "retransmitting\n", ntohl(recvhdr.seq), 
                               srv_state->expected_ack, 
                               ntohl(recvhdr.window_size));
                        //print_cwnd();

                        /* Fast retransmit: Retransmit the last packet sent */
                        retransmit_first_unacked_packet(fd);
                        retransmit = 1;
                        srv_state->num_dup_acks = 0;
                        srv_state->last_dup_ack = ntohl(recvhdr.seq);

                        /*
                         * We have to reduce congestion window to ss_thresh.
                         * Compute the new ss_thresh. Also update the window
                         * parameters and buffer pointer.
                         */
                        if (srv_state->cwnd_size > 1) {
                            ss_thresh = srv_state->cwnd_size / 2;
                            update_cwnd_after_timeout(ss_thresh, ss_thresh,
                                                      CONGESTION_STATE_AVOIDANCE,
                                                      &offset, &bytes_remaining,
                                                      &current_sequence_number, 
                                                      &pending_acks);
                        }
                        //print_cwnd();
                        retransmit = 1;
                    }
                }

                goto send_again;

            } else {
                /* We are in persist mode. Has the window opened up? */
                if (ntohl(recvhdr.window_size) > 0) {
                    printf("rudp_send: coming out of persist mode. "
                           "new win: %d\n", ntohl(recvhdr.window_size));
                    srv_state->advw_size = ntohl(recvhdr.window_size);
                    persist_mode = 0;
                    if (pending_acks == 0) {
                        rudp_stop_timer();
                        rtt_stop(&rttinfo, 
                                 rtt_ts(&rttinfo) - ntohl(recvhdr.ts));
                        continue;
                    } else {
                        retransmit_unacked_packets(fd, 
                                                   ntohl(recvhdr.window_size));
                        goto send_again;
                    }
                } else {
                    persist_mode = 1;
                    goto send_again;
                }
            }
        }

        /* Stop the timer */
        rudp_stop_timer();

        /*
         * We got a valid acknowledgement. Update the window parameters. Be
         * sure to block SIGALRM so that we don't end up in an inconsistent
         * state.
         */
        printf("rudp_send: received valid ack %d expected %d win %d "
               "pending %d\n", ntohl(recvhdr.seq), srv_state->expected_ack,
               ntohl(recvhdr.window_size), pending_acks);

        /*
         * Handle the acknowledgement. We have 3 cases here:
         * 1. We receive only one expected ack
         * 2. We receive a cumulative ack for a set of packets in the cwnd
         * 3. We receive a cumulative ack for a packet that is not there in
         *    our cwnd (Happens if we have shrunk our congestion window)
         */
        num_rcvd_acks = ntohl(recvhdr.seq) - srv_state->expected_ack + 1;
        rudp_handle_ack(ntohl(recvhdr.seq), num_rcvd_acks, 
                                   &pending_acks);
        srv_state->advw_size = ntohl(recvhdr.window_size);

        /* 
         * Update the congestion window size based on the congestion state.
         * Also update the free slots in the window.
         */
        update_cwnd_size_after_valid_ack(num_rcvd_acks);

        /* Update the congestion window parameters */
        update_cwnd_after_valid_ack();

        /* Is the receiver full? If so, we have to trigger persist timer */
        if (srv_state->advw_size == 0) {
            printf("rudp_send: entering persist mode. receive window full\n");
            persist_mode = 1;
            //print_cwnd();
            goto send_again;
        }

        /* Update RTT if we have not retransmitted the last packet */
        if (!retransmit) {
            rtt_stop(&rttinfo, rtt_ts(&rttinfo) - ntohl(recvhdr.ts));
        }
    }

    return 0;
}

/*
 * rudp_close
 *
 * This function terminates the given connection. It sends a FIN packet to the
 * peer and waits for an acknowledgement. It retransmits the FIN a fixed
 * number of times till it receives an ack.
 */
int
rudp_close (int fd)
{
    int bytes_read;
    struct iovec iovrecv[1];

send_again:

    rudp_send_ctrl_packet(fd, MSG_TYPE_FIN);

    /* Start a timer */
    rudp_start_timer(RUDP_TIME_WAIT_INTERVAL * USEC_IN_SEC);

    /* Handle timeout */
    if (sigsetjmp(jmpbuf, 1) != 0) {
        printf("rudp_close: failed to receive ack for fin. retransmitting.\n");
        goto send_again;
    }

    /* Block on receive as server may retransmit the last packet or FIN */
    msgrecv.msg_name = NULL;
    msgrecv.msg_namelen = 0;
    msgrecv.msg_iov = iovrecv;
    msgrecv.msg_iovlen = 1;

    iovrecv[0].iov_base = (void *)&recvhdr;
    iovrecv[0].iov_len = sizeof(struct hdr);

    bytes_read = recvmsg(fd, &msgrecv, 0);

    /* Stop the timer */
    rudp_stop_timer();

    printf("rudp_close: received ack for FIN message\n");

    close(fd);

    return 0;
}

/****************************************************************************/
/*                       Client related routines                            */
/****************************************************************************/

/*
 * rudp_cli_init
 *
 * Initializes the RUDP layer for the client
 */
int
rudp_cli_init (rudp_cli_state_t *state)
{
    int i;

    /* Initialize the parameters based on what is sent by the client */
    cli_state = (rudp_cli_state_t *)malloc(sizeof(rudp_cli_state_t));
    if (!cli_state) {
        return -1;
    }

    /* Store the parameters specified in client.in file */
    bzero(cli_state, sizeof(rudp_cli_state_t));
    cli_state->advw_size = state->advw_size;
    cli_state->random_seed  = state->random_seed;
    cli_state->data_loss_prob = state->data_loss_prob;
    cli_state->recv_rate = state->recv_rate;

    /* Initialize the receive window parameters */
    cli_state->advw_start = 0;
    cli_state->advw_end = 0;
    cli_state->expected_seq = 0;
    cli_state->advw_free = cli_state->advw_size;
    pthread_mutex_init(&cli_state->advw_lock, NULL);

    /* Allocate and initialize the receive window */
    cli_state->advw = 
       (rudp_payload_t *)malloc(cli_state->advw_size * sizeof(rudp_payload_t));
    if (!cli_state->advw) {
        return -1;
    }
    bzero(cli_state->advw, cli_state->advw_size * sizeof(rudp_payload_t));

    for (i = 0; i < cli_state->advw_size; i++) {
        cli_state->advw[i].data = (char *)malloc(RUDP_PAYLOAD_SIZE);
        if (!cli_state->advw[i].data) {
            return -1;
        }
        bzero(cli_state->advw[i].data, RUDP_PAYLOAD_SIZE);
    }

    /* Initialize the random seed */
    srand(cli_state->random_seed);

    /* Register for SIGALRM */
    signal(SIGALRM, sigalarm_handler);

    return 0;
}

/*
 * rudp_cli_destroy
 *
 * Cleans up the resources allocated to the RUDP layer on the client
 */
int
rudp_cli_destroy (void)
{
    int i;

    /* Free the allocated resources */
    if (cli_state) {
        if (cli_state->advw) {
            for (i = 0; i < cli_state->advw_size; i++) {
                if (cli_state->advw[i].data) {
                    free(cli_state->advw[i].data);
                }
            }
        }
        free(cli_state->advw);
        free(cli_state);
    }

    return 0;
}

/*
 * rudp_send_ack
 *
 * This function constructs an acknowledgement from the given parameters and
 * sends it across to the server.
 */
static void
rudp_send_ack (int fd, uint32_t seq, uint32_t window_size)
{
    struct iovec iovsend[1];

    printf("rudp_send_ack: sending ack %d window %d\n", seq, window_size);

    bzero(&msgsend, sizeof(struct msghdr));
    msgsend.msg_name = NULL; /* No need to specify recepient as socket is */
    msgsend.msg_namelen = 0; /* already connected.                        */
    msgsend.msg_iov = iovsend;
    msgsend.msg_iovlen = 1;

    sendhdr.msg_type = htonl(MSG_TYPE_ACKNOWLEDGEMENT);
    sendhdr.seq = htonl(seq);
    sendhdr.window_size = htonl(window_size);

    iovsend[0].iov_base = (void *)&sendhdr;
    iovsend[0].iov_len = sizeof(struct hdr);

    if (sendmsg(fd, &msgsend, 0) < 0) {
        perror("rudp_send_ack: cannot send ack: ");
    }
}

/*
 * rudp_cli_conn_send
 *
 * This is used during the initial connection setup phase. The client
 * calls this to send the filename and receive the ephimeral port from
 * the server. It then sends an acknowledgement to the server.
 */
int
rudp_cli_conn_send (int fd, struct sockaddr_in *peer_addr, void *data,
                    int size, void *recv_data, int recv_size,
                    int (*reconnect_fn)(int, void *, void *))
{
    int ret, n, len = sizeof(struct sockaddr);
    struct iovec iovsend[2], iovrecv[2];
    struct sockaddr_in serv_addr;

    /* Initialize the RTT library if we are coming here for the first time */
    if (rttinit == 0) {
        rtt_init(&rttinfo);
        rttinit = 1;
        rtt_d_flag = 1;
    }

    bzero(&msgsend, sizeof(struct msghdr));
    bzero(&msgrecv, sizeof(struct msghdr));

    /* Send the filename to the server */
    sendhdr.msg_type = htonl(MSG_TYPE_FILENAME);
    msgsend.msg_name = NULL; /* No need to specify recepient as socket is */
    msgsend.msg_namelen = 0; /* already connected.                        */
    msgsend.msg_iov = iovsend;
    msgsend.msg_iovlen = 2;

    iovsend[0].iov_base = (void *)&sendhdr;
    iovsend[0].iov_len = sizeof(struct hdr);
    iovsend[1].iov_base = data;
    iovsend[1].iov_len = size;

    /* Initialize the receive buffer for getting the connection port */
    msgrecv.msg_name = peer_addr;
    msgrecv.msg_namelen = len;
    msgrecv.msg_iov = iovrecv;
    msgrecv.msg_iovlen = 2;

    iovrecv[0].iov_base = (void *)&recvhdr;
    iovrecv[0].iov_len = sizeof(struct hdr);
    iovrecv[1].iov_base = recv_data;
    iovrecv[1].iov_len = recv_size;

    /* Initialize the retransmission count to 0 */
    rtt_newpack(&rttinfo);

    printf("\nSending filename %s to server\n", (char *)data);

    /* Send it till we exceed the number of retries */
send_again:

    sendhdr.ts = htonl(rtt_ts(&rttinfo));
    sendmsg(fd, &msgsend, 0);

    /* Start the timer */
    rudp_start_timer(rtt_start(&rttinfo));

    if (sigsetjmp(jmpbuf, 1) != 0) {
        if (rtt_timeout(&rttinfo) < 0) {
            printf("rudp_cli_conn_send: no response from peer. giving up.\n");
            rttinit = 0;
            errno = ETIMEDOUT;
            return -1;
        }
        printf("rudp_cli_conn_send: request timed out. retransmitting..\n");
        goto send_again;
    }

    /* Block till we get a response */
    do {
        n = recvmsg(fd, &msgrecv, 0);
    } while (ntohl(recvhdr.msg_type) != MSG_TYPE_CONNECTION_PORT);

    /* Stop the timer */
    rudp_stop_timer();

    /* Calculate & store new RTT estimator values */
    rtt_stop(&rttinfo, rtt_ts(&rttinfo) - ntohl(recvhdr.ts));

    /* 
     * We got the new ephimeral port from the server in recv_data. Reconnect
     * to the server on this new port.
     */
    ret = reconnect_fn(fd, recv_data, &serv_addr);
    if (ret < 0) {
        printf("rudp_cli_conn_send: issue in re-connecting client socket to "
               "new port\n");
        return -1;
    }

    bzero(&msgsend, sizeof(struct msghdr));

    /* Now send the acknowledgement to the server */
    printf("rudp_cli_conn_send: reconnection successful. sending "
           "acknowledgement to server\n");

    sendhdr.msg_type = htonl(MSG_TYPE_ACKNOWLEDGEMENT);
    sendhdr.window_size = htonl(cli_state->advw_size);

    msgsend.msg_name = NULL; /* No need to specify recepient as socket is */
    msgsend.msg_namelen = 0; /* already connected.                        */
    msgsend.msg_iov = iovsend;
    msgsend.msg_iovlen = 1;

    iovsend[0].iov_base = (void *)&sendhdr;
    iovsend[0].iov_len = sizeof(struct hdr);

    sendmsg(fd, &msgsend, 0);

    return (n - sizeof(struct hdr));
}

/*
 * rudp_cli_drop_packet
 *
 * This function determines whether the rudp thread should drop the received
 * packet or not. This is used to simulate congestion control. It returns 1 if
 * packet needs to be dropped, 0 otherwise.
 */
static int
rudp_cli_drop_packet (void)
{
    double val;
    int rand_val, ivl;

    rand_val = random();
    val = (double)(rand_val % 100) / 100;

    if (val < cli_state->data_loss_prob) {
        return 1;
    } else {
        return 0;
    }
}

/*
 * rudp_cli_get_sleep_interval
 *
 * This function is called whenever the consumer thread reads a set of packets
 * from the receive buffer. It returns the number of seconds the thread has to
 * sleep before reading the receive buffer again.
 */
int
rudp_cli_get_sleep_interval (void)
{
    double val;
    int rand_val, ivl;

    rand_val = random();
    val = (double)(rand_val % 100) / 100;
    if (val == 0) {
        /* Log 0 is not defined! */
        val += 0.50;
    }

    ivl = (int)(((-1) * cli_state->recv_rate * log(val)) * 1000);

    return ivl;
}

/*
 * rudp_cli_get_pending_packets_count
 *
 * Returns the number of unread packets in the receiver's advertised window
 */
static int
rudp_cli_get_pending_packets_count (void)
{
    int i, count = 0;

    for (i = cli_state->advw_start; i != cli_state->advw_end;) {
        count++;
        i = (i + 1) % cli_state->advw_size;
    }

    return count;
}

/*
 * rudp_cli_transfer_complete
 *
 * This functions true if the server has sent us a FIN and consumer thread has
 * processed all the data. Consumer thread calls this to figure out when to 
 * terminate.
 */
int
rudp_cli_transfer_complete (void)
{
    int pending_packets = rudp_cli_get_pending_packets_count();

    return (cli_state->fin_received && 
            (cli_state->advw_start == cli_state->advw_end));
}

/*
 * rudp_read
 *
 * Read outstanding packets from the receive buffer. This is called by the
 * consumer thread.
 */
int
rudp_read (char *buf)
{
    int i, slot, bytes_to_read, num_packets;
    uint8_t *p;
    rudp_payload_t *payload;

    /* Sanity check */
    if (!buf) {
        return 0;
    }

    /* Return if there is nothing to read */
    if (cli_state->advw[cli_state->advw_start].valid == 0) {
        return 0;
    }

    pthread_mutex_lock(&cli_state->advw_lock);

    bytes_to_read = 0;

    /* Figure out how much buffer size we need */
    slot = cli_state->advw_start;
    if (cli_state->advw_end > cli_state->advw_start) {
        num_packets = cli_state->advw_end - cli_state->advw_start;
    } else {
        num_packets = cli_state->advw_size - 
                      (cli_state->advw_start - cli_state->advw_end);
    }
    for (i = 0; i < num_packets; i++) {
        bytes_to_read += (cli_state->advw[slot].data_size - sizeof(struct hdr));
        slot = (slot + 1) % cli_state->advw_size;
    }

    if (bytes_to_read == 0) {
        return 0;
    }

    buf[bytes_to_read] = 0;

    /*
     * Copy all the packets that we have in the receive buffer. Take care to
     * start copying after the header.
     */
    slot = cli_state->advw_start;
    for (i = 0; i < num_packets; i++) {
        assert(cli_state->advw[slot].valid == 1);
        payload = &cli_state->advw[slot];
        p = (uint8_t *)payload->data;
        memcpy(buf, p + sizeof(struct hdr), 
               payload->data_size - sizeof(struct hdr));
        buf += (payload->data_size - sizeof(struct hdr));
        cli_state->advw_free++;
        cli_state->advw[slot].valid = 0;
        slot = (slot + 1) % cli_state->advw_size;
    }

    cli_state->advw_start = slot;

    pthread_mutex_unlock(&cli_state->advw_lock);
 
    return bytes_to_read;
}

/*
 * rudp_process_probe
 *
 * Process a window probe message from the server
 */
static void
rudp_process_probe (int fd, struct hdr *recvhdr)
{
    /* 
     * Send the acknowledgement with expected ack number and current window
     * size
     */
    rudp_send_ack(fd, cli_state->expected_seq, cli_state->advw_free);
}

/* 
 * add_buf_to_advw
 *
 * This function adds the recieved buffer to the client's window
 * It runs through the client's window and determines the Ack to be sent
 * If there are no free slots - return -1
 */
static int 
add_buf_to_advw (struct hdr *recvhdr, char *data_buf, int buf_len, 
                 uint8_t expected)

{
    char *p = NULL;
    int start = 0, end = 0;
    int ack_to_send = -1, slot;
    struct hdr *dhdr = NULL;
    int recvd_seq = -1;

    pthread_mutex_lock(&cli_state->advw_lock);

    if (cli_state->advw_free == 0) {
        pthread_mutex_unlock(&cli_state->advw_lock);
        return cli_state->expected_seq;
    }

    /* 
     * If this packet is expected seq number, then add the packet to where
     * end is pointing to and increment the end until a hole is found
     */
    if (expected == 1) {
        /* Make sure that end is pointing to a hole */
        assert(cli_state->advw[cli_state->advw_end].valid == 0);

        cli_state->advw[cli_state->advw_end].valid = 1;
        cli_state->advw[cli_state->advw_end].data_size = 
            buf_len + sizeof(struct hdr);
        char *p = cli_state->advw[cli_state->advw_end].data;
        memcpy((void *)p, (void *)recvhdr, sizeof(struct hdr));
        memcpy(p + sizeof(struct hdr), data_buf, buf_len);

        end = cli_state->advw_end = 
            (cli_state->advw_end + 1) % cli_state->advw_size;
        start = cli_state->advw_start;
        cli_state->advw_free--;

        ack_to_send = ntohl(recvhdr->seq) + 1;

        /* 
         * Now walk the buffer, until a hole is found and then set end to it.
         */
        for( ; end != start ; ) {
            if (cli_state->advw[end].valid) {
                dhdr = (struct hdr *) cli_state->advw[end].data;
                ack_to_send = ntohl(dhdr->seq) + 1;
                end = ( end + 1 ) % cli_state->advw_size;
            } else {
                break;
            }
        }

        /* Update the end */
        cli_state->advw_end = end;
        cli_state->expected_seq = ack_to_send;

        //XXX : if end == start, check if windowsize = 0
    } else {
        /* out-of-order packet - check if this can be added to client window */

        recvd_seq = ntohl(recvhdr->seq);

        if (recvd_seq - cli_state->expected_seq < cli_state->advw_free) {
            /* There is a free slot, add this to client window */
            ack_to_send = cli_state->expected_seq;
            slot = (cli_state->advw_end + 
                    (recvd_seq - cli_state->expected_seq)) % 
                     cli_state->advw_size;

            cli_state->advw[slot].valid = 1;
            cli_state->advw[slot].data_size = buf_len + sizeof(struct hdr);
            p = cli_state->advw[slot].data;
            memcpy(p, recvhdr, sizeof(struct hdr));
            memcpy(p + sizeof(struct hdr), data_buf, buf_len);
            cli_state->advw_free--;
        } else {
            /* Can't accomodate this packet */
            ack_to_send = cli_state->expected_seq;
        }
    }

    pthread_mutex_unlock( &cli_state->advw_lock );
    return ack_to_send;
}

/*
 * rudp_process_data
 *
 * This function processes the data message recieved from the server.
 * if the expected_sequence number is same as recived sequence number , Ack the
 * latest contiguous valid packet
 * if the recieved sequence < expected . Ignore the packet
 * if the received sequence > expected , store the packet(if possible) and send 
 * dup-ack.
 */
static int 
rudp_process_data (int fd, struct hdr *recvhdr, char *data_buf, int buf_len)
{
    int ack_to_send;
    uint32_t rcvd_seq = ntohl(recvhdr->seq);

    if ((rcvd_seq == cli_state->expected_seq) || 
         (rcvd_seq > cli_state->expected_seq)) {
        /* 
         * Got a expected packet. Add the packet to advw (if possible).
         * compute the Ack to be sent and send the Ack. If the window size is
         * already 0, it means we have already put the sender in persist mode.
         * So, don't send anything until the window opens up.
         */
        if (cli_state->advw_free == 0) {
            return 0;
        }

        ack_to_send = add_buf_to_advw(recvhdr, data_buf, buf_len, 
                                      (rcvd_seq == cli_state->expected_seq));

    } else {
        ack_to_send = cli_state->expected_seq;
    }

    /* 
     * If the advertised window is full, we are putting the sender in persist
     * mode. Sender will retransmit all the lost packets after he comes out of
     * persist mode. So, flush our receive buffer in kernel so that we don't
     * end up processing duplicate packets and send duplicate acks.
     */
    if (!cli_state->advw_free) {
        printf("ADVERTISED WINDOW FULL\n");
    }

    printf("received seq: %d\n", rcvd_seq);
    rudp_send_ack(fd, ack_to_send, cli_state->advw_free);

    return 0;
}

/*
 * rudp_recv
 *
 * Receive a message on the given socket. This is invoked by the RUDP thread.
 * Ignore src_addr and src_len as we are receiving on a connected socket.
 */
int
rudp_recv (int fd, struct sockaddr *src_addr, int *src_len)
{
    int bytes_read, fin_received = 0;
    struct iovec iovrecv[2];
    char buf[FILE_PAYLOAD_SIZE];

    /* Initialize the RTT library if we are coming here for the first time */
    if (rttinit == 0) {
        rtt_init(&rttinfo);
        rttinit = 1;
        rtt_d_flag = 1;
    }

    while (1) {

        /* Initialize the receive buffer */
        msgrecv.msg_name = NULL;
        msgrecv.msg_namelen = 0;
        msgrecv.msg_iov = iovrecv;
        msgrecv.msg_iovlen = 2;

        iovrecv[0].iov_base = (void *)&recvhdr;
        iovrecv[0].iov_len = sizeof(struct hdr);
        iovrecv[1].iov_base = buf;
        iovrecv[1].iov_len = FILE_PAYLOAD_SIZE;

        /* Start the timer */
        if (!fin_received) {
            rudp_start_timer(RUDP_CLIENT_TIMEOUT * USEC_IN_SEC);
        } else {
            rudp_start_timer(RUDP_TIME_WAIT_INTERVAL * USEC_IN_SEC);
        }

        /* Handle timeout */
        if (sigsetjmp(jmpbuf, 1) != 0) {
            /* Set the "fin_received" flag to notify the consumer thread */
            cli_state->fin_received = 1;

            if (!fin_received) {
                cli_state->advw_start = cli_state->advw_end;
                printf("rudp_recv: server terminated prematurely\n");
            } else {
                printf("rudp_recv: received fin from server\n");
            }
            printf("\nRUDP thread terminating. Waiting for Consumer "
                   "thread to terminate.\n\n");

            break;
        }

read_again:

        /* Wait till the server sends something or we timeout */
        bytes_read = recvmsg(fd, &msgrecv, 0);
        if (bytes_read < 0) {
            if (errno == ECONNREFUSED) {
                cli_state->fin_received = 1;
                printf("rudp_recv: received fin from server\n");
                printf("\nRUDP thread terminating. Waiting for Consumer "
                       "thread to terminate.\n\n");
                break;
            } else {
                assert(0);
            }
        }

        if (rudp_cli_drop_packet()) {
            printf("rudp_recv: dropping packet with seq %d\n", 
                   ntohl(recvhdr.seq));
            goto read_again;
        }

        /* Stop the timer */
        rudp_stop_timer();

        if (ntohl(recvhdr.msg_type) == MSG_TYPE_CONNECTION_PORT) {
            /* 
             * Server lost the acknowledgement we sent after receiving the
             * connection port. Resend the acknowledgement.
             */
            printf("Ack for connection-port message got lost. Resending..\n");
            rudp_send_ack(fd, 0, cli_state->advw_size);

        } else if (ntohl(recvhdr.msg_type) == MSG_TYPE_FIN) {
            /* 
             * The server terminated. Free our resources and terminate. Also
             * notify the consumer thread.
             */
            rudp_send_ack(fd, 0, 0);
            fin_received = 1;
            continue;

        } else if (ntohl(recvhdr.msg_type) == MSG_TYPE_WINDOW_PROBE) {
            /* We got a probe message. Send updated window size to the server */
            rudp_process_probe(fd, &recvhdr);

        } else if (ntohl(recvhdr.msg_type) == MSG_TYPE_FILE_DATA) {
            /* 
             * We got file data from the server. Read it and send back an
             * acknowledgement.
             */
            rudp_process_data(fd, &recvhdr, buf, 
                              (bytes_read - sizeof(struct hdr)));

        } else if (ntohl(recvhdr.msg_type) == MSG_TYPE_ERROR_INVALID_FILE) {
            /* Log a message, notify the consumer thread and bail */
            printf("rudp_recv: invalid file error received from the server\n");
            printf("\nRUDP thread terminating. Waiting for Consumer thread to "
                   "terminate.\n\n");
            cli_state->fin_received = 1;
            break;
        }
    }

    return 0;
}

/* End of File */
