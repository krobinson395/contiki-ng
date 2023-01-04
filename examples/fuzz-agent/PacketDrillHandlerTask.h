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

#ifndef PACKETDRILL_HANDLER_TASK_H
#define PACKETDRILL_HANDLER_TASK_H

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "stddef.h"

#include "FreeRTOS_Stream_Buffer.h"

/*
 * Create the PacketDrill handler task.
 */
int resetPacketDrillTask();
static void handlePacketDrillCommand(struct SyscallPackage *syscallPackage, struct SyscallResponsePackage *syscallResponse);



struct SocketPackage {
    int domain;
    int type;
    int protocol;
};

struct AcceptPackage {
    int sockfd;
};

struct BindPackage {
    int sockfd;
    struct sockaddr addr;
    socklen_t addrlen;
};

struct ListenPackage {
    int sockfd;
    int backlog;
};

struct WritePackage {
    int sockfd;
    int count;
};

struct SendToPackage {
    int sockfd;
    int flags;
    struct sockaddr addr;
    socklen_t addrlen;
};

struct ReadPackage {
    int sockfd;
    int count;
};

struct RecvFromPackage {
    int sockfd;
    int count;
    int flags;
};

struct ClosePackage {
    int sockfd;
};

struct AcceptResponsePackage {
    struct sockaddr addr;
    socklen_t addrlen;
};

struct SyscallResponsePackage {
    int result;
    union {
        struct AcceptResponsePackage acceptResponse;
    };
};


struct SyscallPackage {
    char syscallId[20];
    int bufferedMessage;
    int bufferedCount;
    void *buffer;
    union {
        struct SocketPackage socketPackage;
        struct BindPackage bindPackage;
        struct ListenPackage listenPackage;
        struct AcceptPackage acceptPackage;
        struct BindPackage connectPackage;
        struct WritePackage writePackage;
        struct SendToPackage sendToPackage;
        struct ClosePackage closePackage;
        struct ReadPackage readPackage;
        struct RecvFromPackage recvFromPackage;
    };
};

#endif /* PACKETDRILL_HANDLER_TASK_H */


