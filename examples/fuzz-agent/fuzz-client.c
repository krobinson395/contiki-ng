#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

#define SOCKET_NAME "/tmp/mysocket1"

int main(int argc, char *argv[]) {
  signal(SIGTERM, handler);
  signal(SIGHUP, handler);
  signal(SIGINT, handler);
  int sockfd;
  struct sockaddr_un server_address;
  char buffer[] = "Sending this string";
  printf("STARTING MAIN FILE\n");
  printf("LOOKHERELOOKHERELOOKHERELOOKHERELOOKHERE");

  // Create a socket
  sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (sockfd < 0) {
    perror("Error creating socket");
    exit(1);
  }

  // Set up the server address
  memset(&server_address, 0, sizeof(struct sockaddr_un));
  server_address.sun_family = AF_UNIX;
  strncpy(server_address.sun_path, SOCKET_NAME, sizeof(server_address.sun_path) - 1);

  // Connect to the server
  if (connect(sockfd, (struct sockaddr *) &server_address, sizeof(struct sockaddr_un)) < 0) {
    perror("Error connecting to server");
    exit(1);
  }

  // Read data from the server
  int num_bytes = write(sockfd, buffer, sizeof(buffer));
  if (num_bytes < 0) {
    perror("Error writing to socket");
    exit(1);
  }

  // Print the received data
  printf("wrote %d bytes: %s\n", num_bytes, buffer);

  // Close the socket
  close(sockfd);

  return 0;
}

void handler(int signum) {
	exit(0);
}
