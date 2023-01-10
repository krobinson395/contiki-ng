/*
 * FreeRTOS V202112.00
 * Copyright (C) 2020 Amazon.com, Inc. or its affiliates.  All Rights Reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 * the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 * IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * https://www.FreeRTOS.org
 * https://github.com/FreeRTOS
 *
 */

/* Standard includes. */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include "sys/log.h"
//#include <string.h>


#include "PacketDrillHandlerTask.h"

#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/msg.h>

#include "contiki.h"
#include "net/ipv6/simple-udp.h"
#include <net/ipv6/tcp-socket.h>

#define LOG_MODULE "App"
#define LOG_LEVEL LOG_LEVEL_INFO

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
    struct simple_udp_connection udp_conn;
};

static struct RxCallbackData rxData;

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

}

/*****************************************************************************/
static int
tcp_rx_callback(struct tcp_socket *sock, void *ptr, const uint8_t *input, int len)
{
  LOG_INFO("RECV %d bytes\n", len);

  return 0;
}
/*****************************************************************************/
static void
tcp_event_callback(struct tcp_socket *sock, void *ptr, tcp_socket_event_t event)
{
  LOG_INFO("TCP socket event: ");
  switch(event) {
  case TCP_SOCKET_CONNECTED:
    LOG_INFO_("CONNECTED\n");
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

void handlePacketDrillCommand(struct SyscallPackage *syscallPackage, struct SyscallResponsePackage *syscallResponse) {


    printf("Packetdrill command received: %s\n", syscallPackage->syscallId);

    int8_t response = 0;

    if (strcmp(syscallPackage->syscallId, "socket_create") == 0) {
        /* Create a TCP socket. */

        struct SocketPackage socketPackage = syscallPackage->socketPackage;

        int8_t socketResult = 0;

        struct ContikiSocket xSocket;
        if (socketPackage.protocol == 17) {

            /* Initialize UDP connection */
            struct simple_udp_connection *udp_conn = malloc(sizeof(struct simple_udp_connection));
            socketResult = simple_udp_register(udp_conn, 0, NULL,
                0, udp_rx_callback);
            xSocket.udp_conn = udp_conn;
            xSocket.initialized = 1;
        } else {
            #define SOCKET_BUF_SIZE 128

            struct tcp_socket *server_sock = malloc(sizeof(struct tcp_socket));
            static uint8_t in_buf[SOCKET_BUF_SIZE];
            static uint8_t out_buf[SOCKET_BUF_SIZE];
            socketResult = tcp_socket_register(server_sock, NULL, in_buf, sizeof(in_buf),
                                out_buf, sizeof(out_buf),
                                tcp_rx_callback, tcp_event_callback);
            xSocket.tcp_conn = server_sock;
            xSocket.initialized = 1;
        }

        if ( socketResult != 1) {
            response = -1;
            printf("Error creating socket...\n");
            syscallResponse->result = response;
            return;
        }

        // TODO: Check for array out of bounds access
        socketArray[socketCounter] = xSocket;

        /* Set a time out so a missing reply does not cause the task to block
        indefinitely. */
        //FreeRTOS_setsockopt( xSocket, 0, FREERTOS_SO_RCVTIMEO, &xReceiveTimeOut, sizeof( xReceiveTimeOut ) );
        //FreeRTOS_setsockopt( xSocket, 0, FREERTOS_SO_SNDTIMEO, &xSendTimeOut, sizeof( xSendTimeOut ) );

        response = socketCounter;
        socketCounter++;

        syscallResponse->result = response;

    } else if (strcmp(syscallPackage->syscallId, "socket_bind") == 0) {

        struct BindPackage bindPackage = syscallPackage->bindPackage;

        struct sockaddr_in *sock_addr = (struct sockaddr_in *) &bindPackage.addr;
        
        struct ContikiSocket xSocket = socketArray[bindPackage.sockfd];

        int bindResult;
        if (xSocket.initialized != 0 && xSocket.udp_conn != NULL) {
            printf("Binding socket to port %d...\n", sock_addr->sin_port);
            udp_bind(xSocket.udp_conn->udp_conn, sock_addr->sin_port);
            bindResult = 0;
        } else if (xSocket.initialized != 0 && xSocket.tcp_conn != NULL) {
            // No bind implementation for TCP yet
            bindResult = 0;
        } else {
            printf("Error binding to port...\n");
            bindResult = -1;
        }

        syscallResponse->result = bindResult;

    } else if (strcmp(syscallPackage->syscallId, "socket_listen") == 0) {

        struct ListenPackage listenPackage = syscallPackage->listenPackage;

        struct ContikiSocket xSocket = socketArray[listenPackage.sockfd];

        int listenResult;
        if (xSocket.initialized == 1 && xSocket.tcp_conn != NULL) {
            listenResult = tcp_socket_listen(xSocket.tcp_conn, 0); // Seems like we need to specify the receiver port
        } else {
            listenResult = -1;
        }

        

        if (listenResult < 0) {
            printf("Error listening on socket with response: %d\n", listenResult);
        }

        syscallResponse->result = listenResult == 1 ? 0 : -1;

    } /*else if (strcmp(syscallPackage->syscallId, "socket_accept") == 0) {

        struct AcceptPackage acceptPackage = syscallPackage->acceptPackage;

        struct freertos_sockaddr xClient;
        socklen_t xSize = sizeof( xClient );

        FreeRTOS_setsockopt( socketArray[acceptPackage.sockfd], 0, FREERTOS_SO_RCVTIMEO, &xConnectTimeOut, sizeof( xConnectTimeOut ) );

        //TODO: Return the client socket to packetdrill
        Socket_t xConnectedSocket = FreeRTOS_accept( socketArray[acceptPackage.sockfd], &xClient, &xSize );

        FreeRTOS_setsockopt( socketArray[acceptPackage.sockfd], 0, FREERTOS_SO_RCVTIMEO, &xReceiveTimeOut, sizeof( xReceiveTimeOut ) );

        if ( xConnectedSocket == FREERTOS_INVALID_SOCKET ) {
            response = 0;
            FreeRTOS_debug_printf(("Error connecting to client socket...\n"));

            syscallResponse->result = response;
            continue;
        } else if (xConnectedSocket == NULL) {
            response = 0;
            FreeRTOS_debug_printf(("Error connecting to client socket with null...\n"));

            syscallResponse->result = response;
            continue;
        }

        // TODO: Check for array out of bounds access
        socketArray[socketCounter] = xConnectedSocket;

        response = socketCounter;
        socketCounter++;

        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = xClient.sin_port;
        addr.sin_addr = getUnixSinAddr(xClient.sin_addr);

        struct AcceptResponsePackage acceptResponse;
        acceptResponse.addr = *((struct sockaddr *)(&addr));
        acceptResponse.addrlen = sizeof(struct sockaddr_in);

        syscallResponse->result = response;
        syscallResponse->acceptResponse = acceptResponse;

    }*/ else if (strcmp(syscallPackage->syscallId, "socket_connect") == 0) {

        struct BindPackage connectPackage = syscallPackage->connectPackage;

        struct ContikiSocket xSocket = socketArray[connectPackage.sockfd];

        int connectResult = -1;
        if (xSocket.initialized == 1 && xSocket.tcp_conn != NULL) {
            uip_ipaddr_t dest_ipaddr;
            memcpy(dest_ipaddr.u8, &connectPackage.addr6.sin6_addr, 16);

            connectResult = tcp_socket_connect(xSocket.tcp_conn, &dest_ipaddr, uip_htons(connectPackage.addr6.sin6_port));
        }

        if (connectResult < 0) {
            printf("Error connecting to socket with response: %d\n", connectResult);
        } else {
            printf("Successfully connected to socket\n");

        }

        syscallResponse->result = connectResult == 1 ? 0 : -1;
    } else if (strcmp(syscallPackage->syscallId, "socket_write") == 0) {

        struct WritePackage writePackage = syscallPackage->writePackage;

        struct ContikiSocket xSocket = socketArray[writePackage.sockfd];

        int writeResult = -1;
        if (xSocket.initialized == 1 && xSocket.tcp_conn != NULL) {
            writeResult = tcp_socket_send(xSocket.tcp_conn, syscallPackage->buffer, syscallPackage->bufferedCount);
        } 

        if (writeResult < 0) {
            printf("Error writing to socket with response: %d\n", writeResult);
        }

        syscallResponse->result = writeResult;
    } else if (strcmp(syscallPackage->syscallId, "socket_sendto") == 0) {

        struct SendToPackage sendtoPackage = syscallPackage->sendToPackage;

        struct ContikiSocket xSocket = socketArray[sendtoPackage.sockfd];

        int writeResult = 0;
        
        if ( xSocket.initialized != 0 && xSocket.udp_conn != NULL ) {
            
            uip_ipaddr_t dest_ipaddr;
            memcpy(dest_ipaddr.u8, &sendtoPackage.addr6.sin6_addr, 16);

            simple_udp_sendto_port(xSocket.udp_conn, syscallPackage->buffer, syscallPackage->bufferedCount, 
            &dest_ipaddr, uip_ntohs(sendtoPackage.addr6.sin6_port));

            writeResult = syscallPackage->bufferedCount;

        }

        syscallResponse->result = writeResult;
    } else if (strcmp(syscallPackage->syscallId, "socket_read") == 0) {

        struct ReadPackage readPackage = syscallPackage->readPackage;

        char *readBuffer = malloc(readPackage.count);

        int result = 0; // Hook up with evemt
    
        free(readBuffer);

        syscallResponse->result = result;

    } else if (strcmp(syscallPackage->syscallId, "socket_recvfrom") == 0) {

        // if (rxData.pending_data != 1) {
        //     printf("About to yield...\n");
        //     PROCESS_WAIT_EVENT();
        // }

        printf("Just woke up from yielding...\n");


        if (rxData.pending_data == 1) {
            struct sockaddr_in6 addr;
            addr.sin6_port = rxData.sender_port;
            addr.sin6_addr = rxData.sender_addr;

            struct AcceptResponsePackage acceptResponse;
            acceptResponse.addr6 = addr;
            acceptResponse.addrlen = sizeof(struct sockaddr_in6);

            syscallResponse->result = rxData.datalen;
            syscallResponse->acceptResponse = acceptResponse;
        } else {
            syscallResponse->result = 0;
        }

        

    } else if (strcmp(syscallPackage->syscallId, "socket_close") == 0){

        struct ClosePackage closePackage = syscallPackage->closePackage;

        struct ContikiSocket xSocket = socketArray[closePackage.sockfd];

        int closeResult = -1;
        if (xSocket.initialized == 1 && xSocket.tcp_conn != NULL) {
            closeResult = tcp_socket_close(xSocket.tcp_conn);
        }

        if (closeResult != 0) {
            printf("Error closing socket with response: %d\n", closeResult);
        }

        syscallResponse->result = closeResult == 1 ? 0 : -1;
    } else if (strcmp(syscallPackage->syscallId, "freertos_init") == 0){
 
        int sizeSocketArray = resetPacketDrillTask();

        syscallResponse->result = sizeSocketArray;
    } else {
            syscallResponse->result = 0;
    }

}

int resetPacketDrillTask() {
    int sizeSocketArray = socketCounter - 3;
    if (sizeSocketArray > 0) {
        
        //We want to close all the socket we opened during this session 
        for (int counter = 3; counter < socketCounter; counter++) {
            struct ContikiSocket xSocket = socketArray[counter];
            if (xSocket.initialized) {
                if (xSocket.tcp_conn != NULL) {
                    tcp_socket_unregister(xSocket.tcp_conn);
                } 
            }
        }

        memset(socketArray, 0, MAX_SOCKET_ARRAY * sizeof(struct ContikiSocket));

    }

    socketCounter = 3;

    printf("PacketDrill Handler Task Reset..\n");

    return sizeSocketArray;

}
