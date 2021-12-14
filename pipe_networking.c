#include "pipe_networking.h"

#define CHECKTRUEMSG(value, msg) do {       \
    if (!(value)) {                         \
        printf("ERROR: "msg"\n");           \
        exit(-1);                           \
    }                                       \
} while(0);

#define CHECKNEG1MSG(value, msg) CHECKTRUEMSG((value) != (typeof(value))-1, msg": %m")

// reads a string from file descriptor `fd`
// the implementation reads an `int` as `len`,
// then reads `len+1` characters from `fd`
// if the sender did not send a terminating 0, then it won't be received either, be warned!
char *read_string(int fd) {
    int len;
    if (read(fd, &len, sizeof(int)) != sizeof(int)) return NULL;
    char *result = malloc(len+1);
    CHECKTRUEMSG(len+1 == read(fd, result, len+1), "could not read correct number of bytes");
    return result;
}

// writes a `len`-length string `str` to file descriptor `fd`
// the implementation writes `len` to `str`, then `len+1` characters of `str`
// (to send terminating 0 as well)
void write_string_len(int fd, char *str, int len) {
    CHECKNEG1MSG(write(fd, &len, sizeof(int)), "could not write int");
    CHECKNEG1MSG(write(fd, str, len+1), "could not write string");
}

// shortcut for `write_string_len(fd, str, strlen(str))`
void write_string(int fd, char *str) {
    write_string_len(fd, str, strlen(str));
}

/*=========================
  server_handshake
  args: int * to_client

  Performs the server side pipe 3 way handshake.
  Sets *to_client to the file descriptor to the downstream pipe.

  returns the file descriptor for the upstream pipe.
  =========================*/
int server_handshake(int *to_client) {
  printf("creating named pipe '"WKP"' for client to write to\n");
  CHECKNEG1MSG(mkfifo(WKP, 0644), "failed to create pipe '"WKP"'");
  
  printf("opening pipe (waiting for client to connect)\n");
  int from_client = open(WKP, O_RDONLY);
  CHECKNEG1MSG(from_client, "failed to open pipe");
  
  printf("opened! removing named pipe\n");
  CHECKNEG1MSG(remove(WKP), "could not remove named pipe");
  
  printf("reading secret pipe name\n");
  char *secret_name = read_string(from_client);
  CHECKTRUEMSG(secret_name != NULL, "secret pipe name was not receieved");
  
  printf("got name of secret pipe! opening connection\n");
  *to_client = open(secret_name, O_WRONLY);
  CHECKNEG1MSG(*to_client, "could not open secret pipe");
  free(secret_name);
  
  printf("sending '"ACK"' to client\n");
  write_string(*to_client, ACK);
  
  printf("ensuring '"ACK"' is received from client\n");
  char *should_be_ack = read_string(from_client);
  CHECKTRUEMSG(should_be_ack != NULL && !strcmp(ACK, should_be_ack), "'"ACK"' was not received from client");
  
  printf("connection established!\n");
  return from_client;
}

// returns dynamically-allocated string
// ensured to be unique to this process
// by using its pid
char *create_secret_name() {
  unsigned int pid = getpid();
  int size = 10;
  char *result = malloc(size);
  int n = snprintf(result, size, "%u", pid);
  if (n >= size) {
    result = realloc(result, n+1);
    snprintf(result, n+1, "%u",pid);
  }
  return result;
}

/*=========================
  client_handshake
  args: int * to_server

  Performs the client side pipe 3 way handshake.
  Sets *to_server to the file descriptor for the upstream pipe.

  returns the file descriptor for the downstream pipe.
  =========================*/
int client_handshake(int *to_server) {
  printf("connecting to well-known pipe '"WKP"'\n");
  *to_server = open(WKP, O_WRONLY);
  CHECKNEG1MSG(*to_server, "could not connect to '"WKP"'\n");
  
  printf("connected! creating secret pipe\n");
  char *secret_name = create_secret_name();
  CHECKNEG1MSG(mkfifo(secret_name, 0644), "could not create secret pipe");
  
  printf("sending name of secret pipe to server\n");
  write_string(*to_server, secret_name);
  
  printf("opening secret pipe (waiting for server to connect)\n");
  int from_server = open(secret_name, O_RDONLY);
  CHECKNEG1MSG(from_server, "could not open secret pipe");
  
  printf("connected! removing secret pipe\n");
  CHECKNEG1MSG(unlink(secret_name), "could not remove secret pipe");
  free(secret_name);
  
  printf("ensuring '"ACK"' is received from server\n");
  char *should_be_ack = read_string(from_server);
  CHECKTRUEMSG(should_be_ack != NULL && !strcmp(ACK, should_be_ack), "'"ACK"' was not received from server");
  
  printf("sending '"ACK"' to server\n");
  write_string(*to_server, ACK);
  
  printf("connection established!\n");
  return from_server;
}
