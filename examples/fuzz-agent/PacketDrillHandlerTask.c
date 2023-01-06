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

#include "net/ipv6/simple-udp.h"

#define LOG_MODULE "App"
#define LOG_LEVEL LOG_LEVEL_INFO

struct ContikiSocket {
    uint8_t initialized;
    union {
        struct simple_udp_connection *udp_conn;
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
            socketResult= simple_udp_register(udp_conn, 0, NULL,
                0, udp_rx_callback);
            xSocket.udp_conn = udp_conn;
            xSocket.initialized = 1;
        }

        if ( socketResult == 0 ) {
            response = 0;
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
            udp_bind(xSocket.udp_conn->udp_conn, UIP_HTONS(sock_addr->sin_port));
            bindResult = 0;
        } else {
            printf("Error binding to port...\n");
            bindResult = -1;
        }

        syscallResponse->result = bindResult;

    } /*else if (strcmp(syscallPackage->syscallId, "socket_listen") == 0) {

        struct ListenPackage listenPackage = syscallPackage->listenPackage;

        int listenResult = FreeRTOS_listen( socketArray[listenPackage.sockfd], listenPackage.backlog );

        if (listenResult < 0) {
            FreeRTOS_debug_printf(("Error listening on socket with response: %d\n", listenResult));
        }

        syscallResponse->result = listenResult;

    } else if (strcmp(syscallPackage->syscallId, "socket_accept") == 0) {

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

    } else if (strcmp(syscallPackage->syscallId, "socket_connect") == 0) {

        struct BindPackage connectPackage = syscallPackage->connectPackage;

        struct freertos_sockaddr xEchoServerAddress;

        struct sockaddr_in *sock_addr = (struct sockaddr_in *) &connectPackage.addr;
        xEchoServerAddress.sin_port = sock_addr->sin_port;
        uint32_t destinationIPAddress = getFreeRTOSSinAddr(sock_addr->sin_addr);
        xEchoServerAddress.sin_addr = destinationIPAddress;

        if (xIsIPInARPCache(xEchoServerAddress->sin_addr) == pdFALSE) {
            FreeRTOS_debug_printf(("Connect IP address not in ARP cache...Adding now...\n"));
            MACAddress_t destinationMacAddress;
            memcpy(&destinationMacAddress, destinationMacBytes, sizeof(MACAddress_t));
            vARPRefreshCacheEntry( &destinationMacAddress, destinationIPAddress );
        } else {
            FreeRTOS_debug_printf(("Connect IP address found in ARP cache...\n"));
        }

        FreeRTOS_setsockopt( socketArray[connectPackage.sockfd], 0, FREERTOS_SO_RCVTIMEO, &xConnectTimeOut, sizeof( xReceiveTimeOut ) );

        int connectResult = FreeRTOS_connect( socketArray[connectPackage.sockfd],
                        &xEchoServerAddress, sizeof( xEchoServerAddress ) );

        FreeRTOS_setsockopt( socketArray[connectPackage.sockfd], 0, FREERTOS_SO_RCVTIMEO, &xReceiveTimeOut, sizeof( xReceiveTimeOut ) );

        if (connectResult < 0) {
            FreeRTOS_debug_printf(("Error connecting to socket with response: %d\n", connectResult));
        } else {
            FreeRTOS_debug_printf(("Successfully connected to socket\n"));

        }

        syscallResponse->result = connectResult;
    } else if (strcmp(syscallPackage->syscallId, "socket_write") == 0) {

        struct WritePackage writePackage = syscallPackage->writePackage;

        int writeResult = FreeRTOS_send(socketArray[writePackage.sockfd],
                                syscallPackage->buffer, syscallPackage->bufferedCount, 0);

        if (writeResult < 0) {
            FreeRTOS_debug_printf(("Error writing to socket with response: %d\n", writeResult));
        }

        syscallResponse->result = writeResult;
    }*/ else if (strcmp(syscallPackage->syscallId, "socket_sendto") == 0) {

        struct SendToPackage sendtoPackage = syscallPackage->sendToPackage;

        struct ContikiSocket xSocket = socketArray[sendtoPackage.sockfd];

        int writeResult = 0;
        
        if ( xSocket.initialized != 0 && xSocket.udp_conn != NULL ) {
            
            uip_ipaddr_t dest_ipaddr;
            memcpy(dest_ipaddr.u8, &sendtoPackage.addr6.sin6_addr, 16);

            writeResult = simple_udp_sendto_port(xSocket.udp_conn, syscallPackage->buffer, syscallPackage->bufferedCount, 
            &dest_ipaddr, sendtoPackage.addr6.sin6_port);

        }

        syscallResponse->result = writeResult;
    } /*else if (strcmp(syscallPackage->syscallId, "socket_read") == 0) {

        struct ReadPackage readPackage = syscallPackage.readPackage;

        char *readBuffer = pvPortMalloc(readPackage.count);

        int result = FreeRTOS_recv( socketArray[readPackage.sockfd],
                                    (void *) readBuffer,
                                    readPackage.count,
                                    0 );

        if (result < 0 ) {
            FreeRTOS_debug_printf(("Error reading from socket with result: %d\n", result));
        }

    
        vPortFree(readBuffer);

        syscallResponse->result = result;

    } */else if (strcmp(syscallPackage->syscallId, "socket_recvfrom") == 0) {

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

        

    } /*else if (strcmp(syscallPackage->syscallId, "socket_close") == 0){

        struct ClosePackage closePackage = syscallPackage->closePackage;

        Socket_t socketToClose = socketArray[closePackage.sockfd];

        int closeResult = FreeRTOS_shutdown(socketToClose, 0);

        if (closeResult != 0) {
            FreeRTOS_debug_printf(("Error closing socket with response: %d\n", closeResult));
        }

        syscallResponse->result = closeResult;
    }*/ else if (strcmp(syscallPackage->syscallId, "freertos_init") == 0){
 
    int sizeSocketArray = resetPacketDrillTask();

    syscallResponse->result = sizeSocketArray;
} else {
        syscallResponse->result = 0;
}



    


}

int resetPacketDrillTask() {
    int sizeSocketArray = socketCounter - 3;
    if (sizeSocketArray > 0) {
        memset(socketArray, 0, MAX_SOCKET_ARRAY * sizeof(struct ContikiSocket));

        /* We want to close all the socket we opened during this session 
        for (int counter = 0; counter < sizeSocketArray; counter++) {
            Socket_t socket = socketArray[counter + 3];
            FreeRTOS_closesocket(socket);
        }*/
    }

    socketCounter = 3;

    printf("PacketDrill Handler Task Reset..\n");

    return sizeSocketArray;

}
