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
#include "net/ipv6/simple-udp.h"

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

//static struct simple_udp_connection udp_conn;

PROCESS(udp_server_process, "UDP server");
AUTOSTART_PROCESSES(&udp_server_process);
/*---------------------------------------------------------------------------*/

/*---------------------------------------------------------------------------*/
PROCESS_THREAD(udp_server_process, ev, data)
{
  PROCESS_BEGIN();

  /* Initialize DAG root */
  NETSTACK_ROUTING.root_start();

  printf("PacketDrill Bridge Thread started...\n");

  struct sockaddr_un addr;

  unlink(SOCKET_NAME);

  int sfd = socket(AF_UNIX, SOCK_STREAM, 0);

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
    printf("Waiting to accept a connection...\n");

    int cfd = accept(sfd, NULL, NULL);

    if (cfd == -1) {
      printf("Error accepting connection...\n");
      return -1;
    }

    printf("accept returned with cfd %d...\n", cfd);

    //
    // Transfer data from connected socket to stdout until EOF 
    //

    ssize_t numRead;
    struct SyscallPackage syscallPackage; 

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

      struct SyscallResponsePackage syscallResponse;
      handlePacketDrillCommand(&syscallPackage, &syscallResponse);

      printf("Syscall response buffer received: %d...\n", syscallResponse.result);

      int numWrote = send(cfd, &syscallResponse, sizeof(struct SyscallResponsePackage), MSG_NOSIGNAL);

      if (numWrote == -1) {
          printf("Error writing socket response...\n");
      } else {
          printf("Successfully wrote socket response to Packetdrill...\n");
      }

    }

    if (numRead == 0) {
      printf("About to unlink\n");
    } else if (numRead == -1) {
      printf("Error reading from socket with errno %d...\n", errno);
    }

    if (close(cfd) == -1) {
      printf("Error closing socket...\n");
    }

  }



  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
