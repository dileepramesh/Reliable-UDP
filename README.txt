
README for CSE 533 Assignment 2 (Network Programming)
-----------------------------------------------------

Authors: Dileep Ramesh (108028179)
         Manikantan Subramanian (108231320)

In this assignment, we have implemented a reliable file transfer service in a
client-service paradigm on top of an existing UDP connection. TCP like
features have been implemented on top of this existing UDP connection to make
the file transfer ordered and reliable.

Following are the some of the important changes that we have implemented as
part of this assignment:

1. Maintaining multiple listening sockets on the Server
-------------------------------------------------------

- The server creates multiple UDP sockets to listening for incoming
  connections, one for each interface. The get_ifi_info() routine has been
  used to obtain information related to each interface. This is stored in an
  array of structures of the type conn_info_t which is defined as follows:

    typedef struct conn_info_s {
        char                ifname[IFNAME_LEN];
        int                 sock;
        struct sockaddr_in  ip;
        struct sockaddr_in  netmask;
        struct sockaddr_in  subnet;
    } conn_info_t;

  There is one instance of this structure for every interface on the system.
  The server listens on all these interfaces for incoming connections.
  Additional changes have been introduced to the get_ifi_info() routine to get
  the netmask associated with the interface address as well.

- The get_ifi_info() routine issues an ioctl and gets all the addresses
  associated with an interface in a structure of type ifi_info. This
  includes the primary unicast address (ifi_addr), broadcast address
  (ifi_brdaddr) and the destination address (ifi_dstaddr). We use only
  ifi_addr and bind this address to the corresponding listening socket.


2. Modifications done to the RTT library functions in rtt.c and unprtt.h
------------------------------------------------------------------------

- Timers for detecting timeouts and retransmitting lost packets and
  acknowledgements have been implemented using the rtt_* apis provided in
  rtt.c. Since timeout values are in the sub-second range, we have used
  itimers instead of alarm().

- The functions rtt_init(), rtt_ts(), rtt_start() and rtt_stop() have been
  modified to measure time in microseconds rather than seconds. This
  modification has been done as the measured RTT in the compserv and sbpub
  machines were in the sub-second range.

- All the rtt_* functions have been modified to compute and store RTT and
  Smoothed RTT values as integers rather than floats. As part of this, struct
  rtt_info has been modified to store rtt_rtt, rtt_srtt, rtt_rto and rtt_base
  as type int rather than float.

3. Flow Control and Congestion Control implementation
-----------------------------------------------------

Window Size
-----------

  The sender and the receiver window size is specified in the server.in and
  client.in files respectively. On the server, this parameter represents the
  maximum size the congestion window can grow to. On the receiver, this
  represents the maximum number of packets that can be buffered.

Slow Start
----------

  The server will initially be in the slow start phase with a congestion
  window size of 1. For every valid acknowledgement received, it increases it's
  window by 1 MSS (1 packet of 512 bytes in our case). Thus, for the first
  ack, window grows from 1 to 2 and 2 packets are sent in the next iteration.
  Both the acks will be received in the same RTT initially, so the window
  grows from 2 to 4, effectively doubling each time. This continues till the
  server either times out on an acknowledgement or the SS threshold is hit
  (Initial value is set to the receiver's window size advertised during
   connection establishment).

  In every iteration, the server tries to send as many packets as possible.
  This packet count is the minimum of the following 3 parameters:

  - Current free slots in the server's congestion window
  - Advertised window size of the receiver
  - Number of packet's still pending to be sent in the server's buffer

Congestion Avoidance
--------------------

  Whenever the server times out or gets 3 consecutive duplicate
  acknowledgements, it moves from slow start to congestion avoidance phase.
  In this phase, the congestion window grows linearly rather than
  exponentially. The current congestion window size is halved and stored as the
  new SS threshold. Whenever the congestion window size grows beyond the SS
  threshold, the window size is increased linearly instead of exponential
  increase. This is implemented by counting the number of valid acks and
  increasing the window by 1 MSS only when 'congestion-window size' number of
  vaalid acknowledgements are received.

Handling Cumulative acks
------------------------

  When packet drops are triggered, the server receives duplicate
  acknowledgements for lost packets. When the lost packets are retransmitted,
  the client may acknowledge multiple packets at once. This comes as a
  cumulative ack to the server. Here, we have 2 cases:

  - All the acked packets are in the congestion window. In this case, we
    simply slide our window by updating the start aand end pointers. We also
    update the window size accordingly based on the current congestion state.

  - The cumulative ack is greater than the highest numbered packet in the
    sender's congestion window. This happens if the server as shrunk his
    congestion window and the receiver then sends a cumulative ack. In this
    case, all the packets in the congestion window are acknowledged. So, we
    drain the congestion window and start from the next unacknowledged packet.

Handling duplicate acknowledgements: Fast Retransmit and Fast Recovery
----------------------------------------------------------------------

  When a packet is lost and the server times out, we half the current window
  size and store it as the new threshold. The server moves back to slow start
  phase with window size of 1. It moves to congestion avoidance once the
  window size grows beyond the new SS threshold.

  When the server receives 3 duplicaate acks, it stops its timer and
  retransmits the lost packet immediately. This is the fast retransmit phase.
  After the retransmit, it again shrinks its window by half and stores this
  new size as the updated SS threshold. However, this time, instead of going
  back to the slow start phase, it directly starts from the congestion
  avoidance phase (starting window size = SS threshold value). This conforms
  with the implementation of fast recovery in TCP.

Persist Mode implementation on the server
-----------------------------------------

  Whenever the client's advertised window becomes full (this happens when the
  consumer thread sleeps for a longer duration), it sends the next
  acknowledgement with a window size of 0. When the server receives an
  acknowledgement with window size 0, it goes to the persist state. It starts
  the persist timer (5 second timer) and waits for the window to open up. When
  the timer expires, it sends a probe message to the client. If the client's
  window has openedup, it sends a duplicate acknowledgement with a non-zero
  window size. Otherwise it still advertises a window size of 0. As long as
  the server gets acknowledgements with window size 0, it stays in the persist
  mode by restarting the persist timer. The moment it gets an acknowledgement
  with a non-zero window value, it comes out of the persist mode and resumes
  sending packets from the next sequence number.

Timer implementation
--------------------

  In the actual TCP implementation, each segment is timed separately. However,
  in our implementation, we maintain one timer for the whole congestion
  window. This timer is always associated with the first unacknowledged packet
  in the sender's congestion window.

Implementation of Congestion window and Advertised window
---------------------------------------------------------

  Both the congestion window and advertised window are implemented as circular
  buffers with the following 4 parameters: Start, End, Free and Size

  cwnd_start: Points to the first unacknowledged packet. Updated whenever a
              valid ack is received.
  cwnd_end: Points to the first free slot. Updated whenever a packet is sent.
  cwnd_free: Represents the number of free slots
  cwnd_size: Current size of the congestion window.

  advw_start: Points to the first unread packet. Updated whenever the consumer
              packet drains the advertised window.
  advw_end: Points to the first free slot in the advertised window. Updated by
            the RUDP thread whenever it receives a packet and the window is
            not full.
  advw_free: Represents the number of free slots (Advertised window sent as
                                                  part of each ack)
  advw_size: Size of the advertised window

Structure of the message header
-------------------------------

Every packet sent by the server has the following header:

+-----------------+
|   MSG_TYPE      |
|-----------------|
|   SEQUENCE      |
|-----------------|
|   TIMESTAMP     |
|-----------------|
|  WINDOW SIZE    |
+-----------------+
|         |
|     DATA    |
.         .
.-----------------.

MSG_TYPE: is one of the following:

#define MSG_TYPE_CONNECTION_PORT        2
#define MSG_TYPE_FILE_DATA              3
#define MSG_TYPE_FIN                    5
#define MSG_TYPE_WINDOW_PROBE           6
#define MSG_TYPE_ERROR_INVALID_FILE     7

SEQUENCE: is incremented for every new packet sent

TIMESTAMP:  represents the time when the packet was sent. This is used to compute RTT
which in turn is used to determine the waiting time for timeout.


Following are the MSG_TYPE used by client

#define MSG_TYPE_FILENAME               1
#define MSG_TYPE_ACKNOWLEDGEMENT        4

SEQUENCE:  represents the next packet the client is expecting


4. Clean termination of the program after file transfer
-------------------------------------------------------
Server Implementation

When the server gets the  acknowlegdement for the last data packet,
it sends out a control packet containing the message type MSG_TYPE_FIN.
This message type is interpreted by the client as the end of file transfer.

The server process ( child ) keeps re-transmitting the FIN Message until it receives an ACK from the client
or the number of retransmission exceeds the threshold

On reciieving the Ack for the FIN packet the server( child ) process exits. which triggers the SIGCHLD to be delivered to the parent.


The Message format looks as below -

+-----------------+
|  MSG_TYPE_FIN   |
|-----------------|
| SEQUENCE ( 0 )  |
|-----------------|
| TIMESTAMP       |
|-----------------|
| WINDOW SIZE(0)  |
+-----------------+


The parent handles the SIGCHLD signal and determines the process-id (waitpid) of the the child and
then purges the record associated with that connection from its table


Client Implementation :
On Recieving the MSG_TYPE_FIN message from the server, the client sends the ACK to the server.
In order to ensure reliable delivery of ACK message to the server, the Client starts a timer for 5 seconds and .
If the client receives a re-transmitted FIN message, it sends the Acknowledgement and re-starts the timer and moves to TIME_WAIT state
The client exits, when the timer expires.

5. Aditional notes
------------------

- On a local machine, we were able to transfer a 1.5GB file in 40 minutes with
  0% drop probability and 1000 window size. Not able to test this on Solaris
  due to memory constraints.

- On the solaris machine, we were able to transfer a 360MB file in 50 minutes
  with 0% drop probability and 1000 window size.

- On the solaris machine, we were able to transfer a 360MB file in 50 minutes
  with 0% drop probability and 1000 window size.

- On the solaris machine, we were able to transfer a 10MB file in 25 minutes
  with 25% drop probability and 1000 window size.

- For aiding testing, we are additionally dumping the received file contents
  in a separate file. By taking a diff of the input and output file, we are
  ensuring that the file transfer was indeed successful.

END OF FILE
