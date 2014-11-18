#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int main(int argc, char* argv[]) {
  int fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd == -1) {
    printf("create socket failed\n");
    exit(1);
  }

  int opt = 1;
  setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
  
  struct sockaddr_in server_addr;
  bzero(&server_addr, sizeof(struct sockaddr_in));
  server_addr.sin_family = AF_INET;
  server_addr.sin_addr.s_addr = inet_addr("0.0.0.0");
  server_addr.sin_port = htons(5223);
  if (bind(fd, (struct sockaddr*)&server_addr, sizeof(server_addr))) {
    printf("bind failed\n");
    exit(1);
  }

  if (listen(fd, 100)) {
    printf("listen failed\n");
    exit(1);
  }
  while (1) {
    struct sockaddr_in client_addr;
    int length = sizeof(client_addr);

    printf("ready to accept\n");
    int client_socket = accept(fd, (struct sockaddr*)&client_addr, (socklen_t*)&length);
    if (client_socket < 0) {
      printf("accept failed\n");
    } else {
      printf("accept success\n");
    }

#if 1
    char buffer[1024];
    bzero(buffer, sizeof(buffer));
    length = recv(client_socket, buffer, sizeof(buffer), 0);
    if (length < 0 || length == sizeof(buffer)) {
      printf("receive failed\n");
      continue;
    }
    printf("receive:%s\n", buffer);
    send(client_socket, buffer, strlen(buffer), 0);
    if (length < 0) {
      printf("send failed\n");
      continue;
    }
#endif
  }
}
