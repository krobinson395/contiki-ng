/*
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * This file is part of the Contiki operating system.
 *
 */

#include "contiki.h"
#include "net/routing/routing.h"
#include "net/netstack.h"

#include "sys/log.h"

#include "unistd.h"
#include "stdlib.h"

/* Socket includes */
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>

#include "PacketDrillHandlerTask.h"

#define LOG_MODULE "App"
#define LOG_LEVEL LOG_LEVEL_INFO

#define WITH_SERVER_REPLY  1
#define UDP_CLIENT_PORT	8765
#define UDP_SERVER_PORT	5678

#define BACKLOG 5
#define SOCKET_NAME "/tmp/mysocket1"
#define BUF_SIZE 20

#define SOCKET_UDP 1
#define SOCKET_TCP 2

/*---------------------------------------------------------------------------*/

struct ContikiSocket {
    uint8_t initialized;
    union {
        struct simple_udp_connection *udp_conn;
        struct tcp_socket *tcp_conn;
    };
};

#define MAX_SOCKET_ARRAY 10

struct ContikiSocket socketArray[MAX_SOCKET_ARRAY];
int socketCounter = 3;

uint8_t destinationMacBytes[6] = {0x46, 0xE7, 0xD7, 0xAA, 0x9B, 0x5F};

struct RxCallbackData {
    uint8_t pending_data;
    struct in6_addr sender_addr;
    uint16_t sender_port;
    uint16_t datalen;
    struct simple_udp_connection *udp_conn;
    struct tcp_socket *tcp_sock;
};

static struct RxCallbackData rxData;

struct EventCallbackData {
    uint8_t pending_data;
    tcp_socket_event_t event;
    struct tcp_socket *sock; 
    void *ptr;
};

static struct EventCallbackData ecData;


/*!
 * @brief print binary packet in hex
 * @param [in] bin_daa data to print
 * @param [in] len length of the data
 */
static void print_hex( unsigned const char * const bin_data,
                       size_t len )
{
    size_t i;

    for( i = 0; i < len; ++i )
    {
        printf( "%.2X ", bin_data[ i ] );
    }

    printf( "\n" );
}



//static struct simple_udp_connection udp_conn;

PROCESS(udp_server_process, "UDP server");
AUTOSTART_PROCESSES(&udp_server_process);
/*---------------------------------------------------------------------------*/

static void
udp_rx_callback(struct simple_udp_connection *c,
         const uip_ipaddr_t *sender_addr,
         uint16_t sender_port,
         const uip_ipaddr_t *receiver_addr,
         uint16_t receiver_port,
         const uint8_t *data,
         uint16_t datalen)
{
  LOG_INFO("Received package from ");
  LOG_INFO_6ADDR(sender_addr);
  LOG_INFO_("\n");

  rxData.pending_data = 1;
  rxData.sender_port = sender_port;
  memcpy(&rxData.sender_addr.s6_addr, sender_addr->u8, 16);
  rxData.datalen = datalen;

  process_poll(&udp_server_process);

}

/*****************************************************************************/
static int
tcp_rx_callback(struct tcp_socket *sock, void *ptr, const uint8_t *input, int len)
{
  LOG_INFO("RECV %d bytes\n", len);

  rxData.pending_data = 1;
  rxData.datalen = len;
  rxData.tcp_sock = sock;

  process_poll(&udp_server_process);

  return 0;
}
/*****************************************************************************/
static void
tcp_event_callback(struct tcp_socket *sock, void *ptr, tcp_socket_event_t event)
{

    ecData.event = event;
    ecData.ptr = ptr;
    ecData.sock = sock;

  LOG_INFO("TCP socket event: ");
  switch(event) {
  case TCP_SOCKET_CONNECTED:
    LOG_INFO_("CONNECTED\n");
    // LOG_INFO_("CONNECTED\n");
    // // Previously, I updated the sock->c only when it was null. But this was leading to errors with stale connections.
    // printf("Allocating connection to port %d from source: ", sock->listen_port);
    // print_hex((unsigned char *) uip_conn->ripaddr.u8, 16 );
    // sock->c = uip_conn; // Since uip_conn always points to the current connection, that would imply the connection that just got connected as well.
    // ecData.pending_data = 1;
    // //TODO: I can post an event only when a flag is true. The flag is set when theres someone waiting for the event
    // process_post(&udp_server_process, event, ptr);

    if (sock->c == NULL) {
        printf("Allocating connection to port %d from source: ", sock->listen_port);
        print_hex((unsigned char *) uip_conn->ripaddr.u8, 16 );
        sock->c = uip_conn; // Since uip_conn always points to the current connection, that would imply the connection that just got connected as well.
    } else {
        printf("Socket already had conn to port %d from source: ", sock->listen_port);
        print_hex((unsigned char *) sock->c->ripaddr.u8, 16);

        printf("The current connection is from source: ");
        print_hex((unsigned char *) uip_conn->ripaddr.u8, 16 );
    }
    ecData.pending_data = 1;
    //TODO: I can post an event only when a flag is true. The flag is set when theres someone waiting for the event
    process_post(&udp_server_process, event, ptr);
  
    break;
  case TCP_SOCKET_CLOSED:
    LOG_INFO_("CLOSED\n");
    break;
  case TCP_SOCKET_TIMEDOUT:
    LOG_INFO_("TIMED OUT\n");
    break;
  case TCP_SOCKET_ABORTED:
    LOG_INFO_("ABORTED\n");
    break;
  case TCP_SOCKET_DATA_SENT:
    LOG_INFO_("DATA SENT\n");
    break;
  default:
    LOG_INFO_("UNKNOWN (%d)\n", (int)event);
    break;
  }

  //tcp_socket_unregister(&server_sock);
}

/*---------------------------------------------------------------------------*/

/*---------------------------------------------------------------------------*/
PROCESS_THREAD(udp_server_process, ev, data)
{

    static struct SyscallResponsePackage syscallResponse;
    static struct SyscallPackage syscallPackage;
    static int sfd, cfd;
    static uint16_t pendingBindPort = 0;

  PROCESS_BEGIN();

  /* Initialize DAG root */
  NETSTACK_ROUTING.root_start();

  printf("PacketDrill Bridge Thread started...\n");

  struct sockaddr_un addr;

  unlink(SOCKET_NAME);

  sfd = socket(AF_UNIX, SOCK_STREAM, 0);

  if (sfd == -1) {
      printf("Error creating socket...\n");
      return -1;
  }

  // Zero out the address, and set family and path.
  memset(&addr, 0, sizeof(struct sockaddr_un));
  addr.sun_family = AF_UNIX;
  strcpy(addr.sun_path, SOCKET_NAME);

  if (bind(sfd, (struct sockaddr *) &addr, sizeof(struct sockaddr_un)) == -1) {
      printf("Error binding socket to port...\n");
      return -1;
  }

  if (listen(sfd, BACKLOG) ==-1) {
      printf("Error listening on socket...\n");
      return -1;
  }

  for (;;) {

    #ifdef __AFL_HAVE_MANUAL_CONTROL

    while (__AFL_LOOP(1000)) {

    #endif

    printf("Waiting to accept a connection...\n");

    cfd = accept(sfd, NULL, NULL); // Suppressed -Werror=maybe-uninitialized on sfd

    if (cfd == -1) {
      printf("Error accepting connection...\n");
      return -1;
    }

    printf("accept returned with cfd %d...\n", cfd);

    //
    // Transfer data from connected socket to stdout until EOF 
    //

    ssize_t numRead;

    while ((numRead = read(cfd, &syscallPackage, sizeof(struct SyscallPackage))) > 0) {

        if (syscallPackage.bufferedMessage == 1) {
        void *buffer = malloc(syscallPackage.bufferedCount);
        ssize_t bufferCount = read(cfd, buffer, syscallPackage.bufferedCount);

        if (bufferCount <= 0) {
            printf("Error reading buffer content from socket\n");
        } else if (bufferCount != syscallPackage.bufferedCount) {
            printf("Count of buffer not equal to expected count.\n");
        } else {
            printf("Successfully read buffer count from socket.\n");
        }

        syscallPackage.buffer = buffer;

        }

        printf("Packetdrill command received: %s\n", syscallPackage.syscallId);

        int8_t response = 0;

        if (strcmp(syscallPackage.syscallId, "socket_create") == 0) {
            /* Create a TCP socket. */

            struct SocketPackage socketPackage = syscallPackage.socketPackage;

            int8_t socketResult = 0;

            struct ContikiSocket xSocket;
            if (socketPackage.protocol == 17) {

                /* Initialize UDP connection */
                struct simple_udp_connection *udp_conn = calloc(1, sizeof(struct simple_udp_connection));
                socketResult = simple_udp_register(udp_conn, 0, NULL,
                    0, udp_rx_callback);
                xSocket.udp_conn = udp_conn;
                xSocket.initialized = SOCKET_UDP;
            } else {
                #define SOCKET_BUF_SIZE 10000

                struct tcp_socket *server_sock = calloc(1, sizeof(struct tcp_socket));
                uint8_t *in_buf = malloc(SOCKET_BUF_SIZE);
                uint8_t *out_buf = malloc(SOCKET_BUF_SIZE);
                socketResult = tcp_socket_register(server_sock, NULL, in_buf, SOCKET_BUF_SIZE,
                                    out_buf, SOCKET_BUF_SIZE,
                                    tcp_rx_callback, tcp_event_callback);
                xSocket.tcp_conn = server_sock;
                xSocket.initialized = SOCKET_TCP;
            }

            if ( socketResult != 1) {
                response = -1;
                printf("Error creating socket...\n");
                syscallResponse.result = response;
                
            } else {
                // TODO: Check for array out of bounds access
                socketArray[socketCounter] = xSocket;

                // TODO: Add timeout
                response = socketCounter;
                socketCounter++;
            }

            syscallResponse.result = response;

        } else if (strcmp(syscallPackage.syscallId, "socket_bind") == 0) {

            struct BindPackage bindPackage = syscallPackage.bindPackage;

            struct sockaddr_in *sock_addr = (struct sockaddr_in *) &bindPackage.addr;
            
            struct ContikiSocket xSocket = socketArray[bindPackage.sockfd];

            int bindResult;
            if (xSocket.initialized == SOCKET_UDP) {
                printf("Binding socket to port %d...\n", sock_addr->sin_port);
                udp_bind(xSocket.udp_conn->udp_conn, sock_addr->sin_port);
                bindResult = 0;
            } else if (xSocket.initialized == SOCKET_TCP) {
                // No bind implementation for TCP yet
                pendingBindPort = sock_addr->sin_port;
                printf("Binding to port %d or %d...\n", pendingBindPort, uip_htons(pendingBindPort));
                bindResult = 0;
            } else {
                printf("Error binding to port...\n");
                bindResult = -1;
            }

            syscallResponse.result = bindResult;

        } else if (strcmp(syscallPackage.syscallId, "socket_listen") == 0) {

            struct ListenPackage listenPackage = syscallPackage.listenPackage;

            struct ContikiSocket xSocket = socketArray[listenPackage.sockfd];

            int listenResult;
            if (xSocket.initialized == SOCKET_TCP) {
                listenResult = tcp_socket_listen(xSocket.tcp_conn, uip_htons(pendingBindPort)); // Seems like we need to specify the receiver port
            } else {
                listenResult = -1;
            }

            

            if (listenResult < 0) {
                printf("Error listening on socket with response: %d\n", listenResult);
            }

            syscallResponse.result = listenResult == 1 ? 0 : -1;

        } else if (strcmp(syscallPackage.syscallId, "socket_accept") == 0) {

            //struct AcceptPackage acceptPackage = syscallPackage.acceptPackage;
            // TODO: Ensure sockfd exists and matches the connection that was established

            if (ecData.pending_data != 1 || ecData.event != TCP_SOCKET_CONNECTED) { // Socket hasn't connected yet
                printf("About to yield in accept...\n");
                PROCESS_WAIT_EVENT();
            }

            printf("Waking up from yield...\n");

            if (ecData.event == TCP_SOCKET_CONNECTED && ecData.sock != NULL && ecData.sock->c != NULL) {
                struct ContikiSocket xSocket;
                xSocket.initialized = SOCKET_TCP;
                xSocket.tcp_conn = ecData.sock;
                socketArray[socketCounter] = xSocket;

                response = socketCounter;
                socketCounter++;

                struct sockaddr_in6 addr;
                addr.sin6_family = AF_INET6;
                addr.sin6_port = ecData.sock->c->rport;
                memcpy(addr.sin6_addr.s6_addr, ecData.sock->c->ripaddr.u8, 16);

                struct AcceptResponsePackage acceptResponse;
                acceptResponse.addr6 = addr;
                acceptResponse.addrlen = sizeof(struct sockaddr_in6);

                syscallResponse.result = response;
                syscallResponse.acceptResponse = acceptResponse;

                ecData.pending_data = 0;
                memset(&ecData, 0, sizeof(struct EventCallbackData));
            } else {
                syscallResponse.result = -1;
            }

        } else if (strcmp(syscallPackage.syscallId, "socket_connect") == 0) {

            struct BindPackage connectPackage = syscallPackage.connectPackage;

            struct ContikiSocket xSocket = socketArray[connectPackage.sockfd];

            int connectResult = -1;
            if (xSocket.initialized == SOCKET_TCP) {
                uip_ipaddr_t dest_ipaddr;
                memcpy(dest_ipaddr.u8, &connectPackage.addr6.sin6_addr, 16);

                connectResult = tcp_socket_connect(xSocket.tcp_conn, &dest_ipaddr, uip_htons(connectPackage.addr6.sin6_port));
            }

            if (connectResult < 0) {
                printf("Error connecting to socket with response: %d\n", connectResult);
                syscallResponse.result = -1;
            } else {
                PROCESS_WAIT_EVENT();
                printf("Successfully connected to socket\n");
                syscallResponse.result = 0;
            }

            
        } else if (strcmp(syscallPackage.syscallId, "socket_write") == 0) {

            struct WritePackage writePackage = syscallPackage.writePackage;

            struct ContikiSocket xSocket = socketArray[writePackage.sockfd];

            int writeResult = -1;
            if (xSocket.initialized == SOCKET_TCP) {
                writeResult = tcp_socket_send(xSocket.tcp_conn, syscallPackage.buffer, syscallPackage.bufferedCount);
            } 

            syscallResponse.result = writeResult;

            if (writeResult < 0) {
                printf("Error writing to socket with response: %d\n", writeResult);
            } else {
                PROCESS_PAUSE();
            }
            
        } else if (strcmp(syscallPackage.syscallId, "socket_sendto") == 0) {

            struct SendToPackage sendtoPackage = syscallPackage.sendToPackage; // Suppressed -Werror=maybe-uninitialized

            struct ContikiSocket xSocket = socketArray[sendtoPackage.sockfd];

            int writeResult = 0;
            
            if ( xSocket.initialized == SOCKET_UDP) {
                
                uip_ipaddr_t dest_ipaddr;
                memcpy(dest_ipaddr.u8, &sendtoPackage.addr6.sin6_addr, 16);

                simple_udp_sendto_port(xSocket.udp_conn, syscallPackage.buffer, syscallPackage.bufferedCount, 
                &dest_ipaddr, uip_ntohs(sendtoPackage.addr6.sin6_port));

                writeResult = syscallPackage.bufferedCount;

            }

            syscallResponse.result = writeResult;
        } else if (strcmp(syscallPackage.syscallId, "socket_read") == 0) {

            if (rxData.pending_data != 1) {
                printf("About to yield...\n");
                PROCESS_WAIT_EVENT();
            }

            printf("Just woke up from yielding...\n");

            // For our fuzz testing, we assume only one socket would receive data, the one we are trying to read from
            struct ReadPackage readPackage = syscallPackage.readPackage;
            struct ContikiSocket xSocket = socketArray[readPackage.sockfd];

            if (rxData.pending_data == 1 && xSocket.tcp_conn->listen_port == rxData.tcp_sock->listen_port) {
                syscallResponse.result = rxData.datalen;
                memset(&rxData, 0, sizeof(struct RxCallbackData));
                rxData.pending_data = 0;
            } else {
                syscallResponse.result = 0;
            }

        } else if (strcmp(syscallPackage.syscallId, "socket_recvfrom") == 0) {

            if (rxData.pending_data != 1) {
                printf("About to yield...\n");
                PROCESS_WAIT_EVENT();
            }

            printf("Just woke up from yielding...\n");


            if (rxData.pending_data == 1) {
                struct sockaddr_in6 addr;
                addr.sin6_port = rxData.sender_port;
                addr.sin6_addr = rxData.sender_addr;

                struct AcceptResponsePackage acceptResponse;
                acceptResponse.addr6 = addr;
                acceptResponse.addrlen = sizeof(struct sockaddr_in6);

                syscallResponse.result = rxData.datalen;
                syscallResponse.acceptResponse = acceptResponse; // Suppressed -Werror=maybe-uninitialized
                rxData.pending_data = 0;
            } else {
                syscallResponse.result = 0;
            }

            

        } else if (strcmp(syscallPackage.syscallId, "socket_close") == 0){

            struct ClosePackage closePackage = syscallPackage.closePackage;

            struct ContikiSocket xSocket = socketArray[closePackage.sockfd];

            int closeResult = -1;
            if (xSocket.initialized == SOCKET_TCP) {
                closeResult = tcp_socket_close(xSocket.tcp_conn);
            }

            if (closeResult != 0) {
                printf("Error closing socket with response: %d\n", closeResult);
            }

            syscallResponse.result = closeResult == 1 ? 0 : -1;
        } else if (strcmp(syscallPackage.syscallId, "freertos_init") == 0){
    
            int sizeSocketArray = resetPacketDrillTask();

            syscallResponse.result = sizeSocketArray;
        } else {
                syscallResponse.result = 0;
        }

      printf("Syscall response buffer received: %d...\n", syscallResponse.result);

      int numWrote = send(cfd, &syscallResponse, sizeof(struct SyscallResponsePackage), MSG_NOSIGNAL); // Suppressed -Werror=maybe-uninitialized on cfd

      if (numWrote == -1) {
          printf("Error writing socket response with errno %d...\n", errno);
      } else {
          printf("Successfully wrote socket response to Packetdrill...\n");
      }

    }

    if (numRead == 0) {
      printf("About to unlink\n");
    } else if (numRead == -1) {
      printf("Error reading from socket with errno %d...\n", errno);
    }

    pendingBindPort = 0;

    if (close(cfd) == -1) {
      printf("Error closing socket...\n");
    }

    #ifdef __AFL_HAVE_MANUAL_CONTROL
    }
    #endif

  }

  PROCESS_END();
}


/*---------------------------------------------------------------------------*/



// void handlePacketDrillCommand2(struct SyscallPackage *syscallPackage, struct SyscallResponsePackage *syscallResponse) {


//     printf("Packetdrill command received: %s\n", syscallPackage->syscallId);

//     int8_t response = 0;

//     if (strcmp(syscallPackage->syscallId, "socket_create") == 0) {
//         /* Create a TCP socket. */

//         struct SocketPackage socketPackage = syscallPackage->socketPackage;

//         int8_t socketResult = 0;

//         struct ContikiSocket xSocket;
//         if (socketPackage.protocol == 17) {

//             /* Initialize UDP connection */
//             struct simple_udp_connection *udp_conn = malloc(sizeof(struct simple_udp_connection));
//             socketResult = simple_udp_register(udp_conn, 0, NULL,
//                 0, udp_rx_callback);
//             xSocket.udp_conn = udp_conn;
//             xSocket.initialized = 1;
//         } else {
//             #define SOCKET_BUF_SIZE 128

//             struct tcp_socket *server_sock = malloc(sizeof(struct tcp_socket));
//             static uint8_t in_buf[SOCKET_BUF_SIZE];
//             static uint8_t out_buf[SOCKET_BUF_SIZE];
//             socketResult = tcp_socket_register(server_sock, NULL, in_buf, sizeof(in_buf),
//                                 out_buf, sizeof(out_buf),
//                                 tcp_rx_callback, tcp_event_callback);
//             xSocket.tcp_conn = server_sock;
//             xSocket.initialized = 1;
//         }

//         if ( socketResult != 1) {
//             response = -1;
//             printf("Error creating socket...\n");
//             syscallResponse->result = response;
//             return;
//         }

//         // TODO: Check for array out of bounds access
//         socketArray[socketCounter] = xSocket;

//         /* Set a time out so a missing reply does not cause the task to block
//         indefinitely. */
//         //FreeRTOS_setsockopt( xSocket, 0, FREERTOS_SO_RCVTIMEO, &xReceiveTimeOut, sizeof( xReceiveTimeOut ) );
//         //FreeRTOS_setsockopt( xSocket, 0, FREERTOS_SO_SNDTIMEO, &xSendTimeOut, sizeof( xSendTimeOut ) );

//         response = socketCounter;
//         socketCounter++;

//         syscallResponse->result = response;

//     } else if (strcmp(syscallPackage->syscallId, "socket_bind") == 0) {

//         struct BindPackage bindPackage = syscallPackage->bindPackage;

//         struct sockaddr_in *sock_addr = (struct sockaddr_in *) &bindPackage.addr;
        
//         struct ContikiSocket xSocket = socketArray[bindPackage.sockfd];

//         int bindResult;
//         if (xSocket.initialized != 0 && xSocket.udp_conn != NULL) {
//             printf("Binding socket to port %d...\n", sock_addr->sin_port);
//             udp_bind(xSocket.udp_conn->udp_conn, sock_addr->sin_port);
//             bindResult = 0;
//         } else if (xSocket.initialized != 0 && xSocket.tcp_conn != NULL) {
//             // No bind implementation for TCP yet
//             bindResult = 0;
//         } else {
//             printf("Error binding to port...\n");
//             bindResult = -1;
//         }

//         syscallResponse->result = bindResult;

//     } else if (strcmp(syscallPackage->syscallId, "socket_listen") == 0) {

//         struct ListenPackage listenPackage = syscallPackage->listenPackage;

//         struct ContikiSocket xSocket = socketArray[listenPackage.sockfd];

//         int listenResult;
//         if (xSocket.initialized == 1 && xSocket.tcp_conn != NULL) {
//             listenResult = tcp_socket_listen(xSocket.tcp_conn, 0); // Seems like we need to specify the receiver port
//         } else {
//             listenResult = -1;
//         }

        

//         if (listenResult < 0) {
//             printf("Error listening on socket with response: %d\n", listenResult);
//         }

//         syscallResponse->result = listenResult == 1 ? 0 : -1;

//     } /*else if (strcmp(syscallPackage->syscallId, "socket_accept") == 0) {

//         struct AcceptPackage acceptPackage = syscallPackage->acceptPackage;

//         struct freertos_sockaddr xClient;
//         socklen_t xSize = sizeof( xClient );

//         FreeRTOS_setsockopt( socketArray[acceptPackage.sockfd], 0, FREERTOS_SO_RCVTIMEO, &xConnectTimeOut, sizeof( xConnectTimeOut ) );

//         //TODO: Return the client socket to packetdrill
//         Socket_t xConnectedSocket = FreeRTOS_accept( socketArray[acceptPackage.sockfd], &xClient, &xSize );

//         FreeRTOS_setsockopt( socketArray[acceptPackage.sockfd], 0, FREERTOS_SO_RCVTIMEO, &xReceiveTimeOut, sizeof( xReceiveTimeOut ) );

//         if ( xConnectedSocket == FREERTOS_INVALID_SOCKET ) {
//             response = 0;
//             FreeRTOS_debug_printf(("Error connecting to client socket...\n"));

//             syscallResponse->result = response;
//             continue;
//         } else if (xConnectedSocket == NULL) {
//             response = 0;
//             FreeRTOS_debug_printf(("Error connecting to client socket with null...\n"));

//             syscallResponse->result = response;
//             continue;
//         }

//         // TODO: Check for array out of bounds access
//         socketArray[socketCounter] = xConnectedSocket;

//         response = socketCounter;
//         socketCounter++;

//         struct sockaddr_in addr;
//         addr.sin_family = AF_INET;
//         addr.sin_port = xClient.sin_port;
//         addr.sin_addr = getUnixSinAddr(xClient.sin_addr);

//         struct AcceptResponsePackage acceptResponse;
//         acceptResponse.addr = *((struct sockaddr *)(&addr));
//         acceptResponse.addrlen = sizeof(struct sockaddr_in);

//         syscallResponse->result = response;
//         syscallResponse->acceptResponse = acceptResponse;

//     }*/ else if (strcmp(syscallPackage->syscallId, "socket_connect") == 0) {

//         struct BindPackage connectPackage = syscallPackage->connectPackage;

//         struct ContikiSocket xSocket = socketArray[connectPackage.sockfd];

//         int connectResult = -1;
//         if (xSocket.initialized == 1 && xSocket.tcp_conn != NULL) {
//             uip_ipaddr_t dest_ipaddr;
//             memcpy(dest_ipaddr.u8, &connectPackage.addr6.sin6_addr, 16);

//             connectResult = tcp_socket_connect(xSocket.tcp_conn, &dest_ipaddr, uip_htons(connectPackage.addr6.sin6_port));
//         }

//         if (connectResult < 0) {
//             printf("Error connecting to socket with response: %d\n", connectResult);
//         } else {
//             printf("Successfully connected to socket\n");

//         }

//         syscallResponse->result = connectResult == 1 ? 0 : -1;
//     } else if (strcmp(syscallPackage->syscallId, "socket_write") == 0) {

//         struct WritePackage writePackage = syscallPackage->writePackage;

//         struct ContikiSocket xSocket = socketArray[writePackage.sockfd];

//         int writeResult = -1;
//         if (xSocket.initialized == 1 && xSocket.tcp_conn != NULL) {
//             writeResult = tcp_socket_send(xSocket.tcp_conn, syscallPackage->buffer, syscallPackage->bufferedCount);
//         } 

//         if (writeResult < 0) {
//             printf("Error writing to socket with response: %d\n", writeResult);
//         }

//         syscallResponse->result = writeResult;
//     } else if (strcmp(syscallPackage->syscallId, "socket_sendto") == 0) {

//         struct SendToPackage sendtoPackage = syscallPackage->sendToPackage;

//         struct ContikiSocket xSocket = socketArray[sendtoPackage.sockfd];

//         int writeResult = 0;
        
//         if ( xSocket.initialized != 0 && xSocket.udp_conn != NULL ) {
            
//             uip_ipaddr_t dest_ipaddr;
//             memcpy(dest_ipaddr.u8, &sendtoPackage.addr6.sin6_addr, 16);

//             simple_udp_sendto_port(xSocket.udp_conn, syscallPackage->buffer, syscallPackage->bufferedCount, 
//             &dest_ipaddr, uip_ntohs(sendtoPackage.addr6.sin6_port));

//             writeResult = syscallPackage->bufferedCount;

//         }

//         syscallResponse->result = writeResult;
//     } else if (strcmp(syscallPackage->syscallId, "socket_read") == 0) {

//         struct ReadPackage readPackage = syscallPackage->readPackage;

//         char *readBuffer = malloc(readPackage.count);

//         int result = 0; // Hook up with evemt
    
//         free(readBuffer);

//         syscallResponse->result = result;

//     } else if (strcmp(syscallPackage->syscallId, "socket_recvfrom") == 0) {

//         if (rxData.pending_data != 1) {
//             printf("About to yield...\n");
//             PROCESS_WAIT_EVENT();
//         }

//         printf("Just woke up from yielding...\n");


//         if (rxData.pending_data == 1) {
//             struct sockaddr_in6 addr;
//             addr.sin6_port = rxData.sender_port;
//             addr.sin6_addr = rxData.sender_addr;

//             struct AcceptResponsePackage acceptResponse;
//             acceptResponse.addr6 = addr;
//             acceptResponse.addrlen = sizeof(struct sockaddr_in6);

//             syscallResponse->result = rxData.datalen;
//             syscallResponse->acceptResponse = acceptResponse;
//         } else {
//             syscallResponse->result = 0;
//         }

        

//     } else if (strcmp(syscallPackage->syscallId, "socket_close") == 0){

//         struct ClosePackage closePackage = syscallPackage->closePackage;

//         struct ContikiSocket xSocket = socketArray[closePackage.sockfd];

//         int closeResult = -1;
//         if (xSocket.initialized == 1 && xSocket.tcp_conn != NULL) {
//             closeResult = tcp_socket_close(xSocket.tcp_conn);
//         }

//         if (closeResult != 0) {
//             printf("Error closing socket with response: %d\n", closeResult);
//         }

//         syscallResponse->result = closeResult == 1 ? 0 : -1;
//     } else if (strcmp(syscallPackage->syscallId, "freertos_init") == 0){
 
//         int sizeSocketArray = resetPacketDrillTask();

//         syscallResponse->result = sizeSocketArray;
//     } else {
//             syscallResponse->result = 0;
//     }

// }

int resetPacketDrillTask() {
    int sizeSocketArray = socketCounter - 3;
    if (sizeSocketArray > 0) {
        
        //We want to close all the socket we opened during this session 
        for (int counter = 3; counter < socketCounter; counter++) {
            struct ContikiSocket xSocket = socketArray[counter];
            if (xSocket.initialized == SOCKET_TCP) {
                tcp_socket_unregister(xSocket.tcp_conn);
                
            } 
        }

        memset(socketArray, 0, MAX_SOCKET_ARRAY * sizeof(struct ContikiSocket));

    }

    socketCounter = 3;

    printf("PacketDrill Handler Task Reset..\n");

    return sizeSocketArray;

}

