/*
 * proxy.c - A Simple Sequential Web proxy
 *
 * Course Name: 14:332:456-Network Centric Programming
 * Assignment 2
 * Student Name: Udayan Rai
 * 
 * IMPORTANT: Give a high level description of your code here. You
 * must also provide a header comment at the beginning of each
 * function that describes what that function does.
 */ 

#include "csapp.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>

#define DEFAULT_PORT 80
#define MAXLINE 8192
#define LISTENQ 1024

/*
 * Function prototypes
 */
void format_log_entry(char* logstring, struct sockaddr_in* sockaddr, char* uri,
                      int size);

void get_method(char* request, char** method);
void tokenize(char* request, char** method, char** hostname, char** filepath,
               int* port, char** uri, char** version, char** headers, char** formatReq);
void getHostPort(char* request, char** hostname, int* port);
void getURI(char* request, char** uri);
void getVersion(char* request, char** version);
void getHeaders(char* request, char** headers);
void logReq(struct sockaddr_in* sockaddr, char* uri, int size);


/*
 * main - Main routine for the proxy program
 */
int main(int argc, char** argv) {
  /* Check arguments */
  if (argc != 2) {
    fprintf(stderr, "Usage: %s <port number>\n", argv[0]);
    exit(0);
  }

  int ssocketFD = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

  int portNumber = atoi(argv[1]);
  if (portNumber < 1) {
    fprintf(stderr, "Usage: %s <port number>.\n", argv[0]);
    exit(1);
  }
  uint16_t server_port = htons(portNumber);

  struct sockaddr_in server_add;
  bzero(&server_add, sizeof(server_add));  
  server_add.sin_family = AF_INET;
  server_add.sin_addr.s_addr = htonl(INADDR_ANY);
  server_add.sin_port = server_port;

  if (bind(ssocketFD, (struct sockaddr*)&server_add, sizeof(server_add)) < 0) {
    fprintf(stderr, "Error in bind""Usage: %s <port number>.\n", argv[0]);
    exit(2);
  }

  if (listen(ssocketFD, LISTENQ) < 0) {
    fprintf(stderr,"Error in listen");
    exit(3);
  }

  struct sockaddr_in clientAddInfo;
  socklen_t clientAddInfo_size = sizeof(clientAddInfo);
  memset(&clientAddInfo, 0, sizeof(clientAddInfo));

  char receiveBuf[MAXLINE];  
  char responseSendBuf[MAXLINE];

  char *method = NULL, *filepath = NULL, *hostname = NULL, *uri = NULL,
      *version = NULL, *headers = NULL, *formatReq = NULL;
  int port = 80; // port variable
  int desBytesReceived; // bytes read from destination
  int clientNum = 0;  

  int dest_ssocketFD,totalBytesRes = 0; 
  int connectErr = 0; 
  int writeErr = 0; 
  int readErr = 0; 
  while (1) {
    printf("Waiting for client %d ...\n", clientNum);
    clientNum++;

    int csocketFD =
        accept(ssocketFD, (struct sockaddr*)&clientAddInfo,
               &clientAddInfo_size);
    if (csocketFD < 0) {
      printf("Error: %d\n", errno);

      fprintf(stderr, "Retry");
      break;
    }

    printf("Socket connected\n");

    memset(receiveBuf, 0, MAXLINE);  

    read(csocketFD, receiveBuf, MAXLINE - 1);

    tokenize(receiveBuf, &method, &hostname, &filepath, &port, &uri, &version,
            &headers, &formatReq);

    printf("Request: \n%s\n-------------------------------\n", formatReq);

    if(strcmp(method, "GET") != 0) {
      fprintf(stderr, "Err: Only GET requests are supported.\n");
      printf("Request denied because not GET.\n");
      close(csocketFD);
      continue;
    }

    dest_ssocketFD = open_clientfd(hostname, port);
    if (dest_ssocketFD < 0) {
      fprintf(stderr,"Connection failure.\n");
      connectErr = 1;
      break;
    }

    if(write(dest_ssocketFD, formatReq, strlen(formatReq)) < 0) {
      fprintf(stderr, "Writing data failure.\n");
      connectErr = 1;
      break;
    }

    readErr = 0;
    printf("Reading from host\n");
    do {
      memset(responseSendBuf, 0, sizeof(responseSendBuf));
      desBytesReceived = read(dest_ssocketFD, responseSendBuf, sizeof(responseSendBuf)); 
      if (desBytesReceived < 0) {
        fprintf(stderr, "Writing data failure\n");
        readErr = 1;
        break;
      }
      printf("%d bytes read\n", desBytesReceived);
      totalBytesRes += desBytesReceived;
      if (desBytesReceived == 0) {  // end of message
        break;
      }

      printf("%d bytes returning\n", desBytesReceived);
      if (write(csocketFD, responseSendBuf, desBytesReceived) < 0) {
        fprintf(stderr,"Failure to respond\n");
        writeErr = 1;
        break;
      }
      desBytesReceived = 0;
    } while (1);
    if (readErr || writeErr) {
      close(csocketFD);
      continue;  
    }
    printf("Writing finished\n");

    printf("HTTP response sent for logging\n");
    logReq(&clientAddInfo, uri, totalBytesRes);

    close(csocketFD);
  }

  if(connectErr) {
    printf("Connection failure\n");
  }
  if (method != NULL) free(method);
  if (filepath != NULL) free(filepath);
  if (hostname != NULL) free(hostname);
  if (uri != NULL) free(uri);
  if (version != NULL) free(version);
  if (headers != NULL) free(headers);
  if (formatReq != NULL) free(formatReq);


  printf("Close server\n");
  close(dest_ssocketFD);
  close(ssocketFD);

  exit(0);
}

/*
 * format_log_entry - Create a formatted log entry in logstring.
 *
 * The inputs are the socket address of the requesting client
 * (sockaddr), the URI from the request (uri), and the size in bytes
 * of the response from the server (size).
 */
void format_log_entry(char* logstring, struct sockaddr_in* sockaddr, char* uri,
                      int size) {
  time_t now;
  char time_str[MAXLINE];
  unsigned long host;
  unsigned char a, b, c, d;

  /* Get a formatted time string */
  now = time(NULL);
  strftime(time_str, MAXLINE, "%a %d %b %Y %H:%M:%S %Z", localtime(&now));

  /*
   * Convert the IP address in network byte order to dotted decimal
   * form. Note that we could have used inet_ntoa, but chose not to
   * because inet_ntoa is a Class 3 thread unsafe function that
   * returns a pointer to a static variable (Ch 13, CS:APP).
   */
  host = ntohl(sockaddr->sin_addr.s_addr);
  a = host >> 24;
  b = (host >> 16) & 0xff;
  c = (host >> 8) & 0xff;
  d = host & 0xff;

  /* Return the formatted log entry string */
  sprintf(logstring, "%s: %d.%d.%d.%d %s %d", time_str, a, b, c, d, uri, size);
}


void getHostPort(char* request, char** hostname, int* port) {
  *hostname = Calloc(strlen(request) + 1, sizeof(char));
  char* localReq = Calloc(strlen(request) + 1, sizeof(char));
  char* localStart = localReq;

  int charsTillN = (int)(strchr(request, '\n') - request) + 1;
  strncpy(localReq, request, charsTillN);

  
  strsep(&localReq, "/");
  strsep(&localReq, "/");

  char* token = strsep(&localReq, "/");

  if (strchr(token, ':') != NULL) {
    char* portstr = strchr(token, ':') + 1;
    *port = atoi(portstr);
    token[strlen(token) - strlen(portstr) - 1] = '\0';
  } else {
    *port = DEFAULT_PORT;
  }

  strncpy(*hostname, token, strlen(token) + 1);

  (*hostname)[strlen(token)] = '\0';

  *hostname = realloc(*hostname, strlen(token) + 1);

  free(localStart);
}

void get_method(char* request, char** method) {
  *method = Calloc(strlen(request) + 1, sizeof(char));

  char* localReq = Calloc(strlen(request) + 1, sizeof(char));
  char* localStart = localReq;

  int charsTillN = (int)(strchr(request, '\n') - request) + 1;
  strncpy(localReq, request, charsTillN);
  char* token = strsep(&localReq, " ");
  strncpy(*method, token, strlen(token) + 1);

  (*method)[strlen(token)] = '\0';

  // realloc to free up memory
  *method = realloc(*method, strlen(token) + 1);

  // Free the copy
  free(localStart);
}

void getURI(char* request, char** uri) {
  char* localReq = Calloc(strlen(request) + 1, sizeof(char));
  char* localStart = localReq;

  /* Get first line from request */
  strncpy(localReq, request, (int)(strchr(request, '\n') - request) + 1);

  /* uri comes between first and second space in request */
  strsep(&localReq, " ");
  char* token = strsep(&localReq, " ");

  /* Copy, then free */
  *uri = Calloc(strlen(token) + 1, sizeof(char));
  strncpy(*uri, token, strlen(token) + 1);
  (*uri)[strlen(token)] = '\0';

  free(localStart);
}

void logReq(struct sockaddr_in* sockaddr, char* uri, int size) {
  printf("Logging request:\n");
  char logstring[MAXLINE];
  format_log_entry(logstring, sockaddr, uri, size);

  if (access("proxy.log", F_OK) == -1) {
    FILE* fp = fopen("proxy.log", "w");
    fprintf(fp, "%s\n", logstring);
    fclose(fp);
  } else {  
    FILE* fp = fopen("proxy.log", "a");
    fprintf(fp, "%s\n", logstring);
    fclose(fp);
  }
}

void getHeaders(char* request, char** headers) {
  char* localReq = Calloc(strlen(request) + 1, sizeof(char));
  char* localStart = localReq;

  /* Get first line from request */
  strncpy(localReq, request, strlen(request));
  strsep(&localReq, "\n");

  printf("original headers: \n%s\n ----------------------\n", localReq);

  *headers = Calloc(sizeof(char), strlen(localReq) + 1);
  char* currentheader = NULL;
  size_t buffersize;
  size_t cursize;

  buffersize = strlen(localReq) + 1;

  cursize = 0;
  while ((currentheader = strsep(&localReq, "\n")) != NULL) {
    
    if (strlen(currentheader) + 3 + cursize > buffersize) {
      void* tmp = realloc(*headers, buffersize * 2);
      if(tmp == NULL) {
        strcat(*headers, "\n");
        free(localStart);
        return;
      }
      buffersize *= 2;
    }

    
    if (strlen(currentheader) == 0) {
      break;
    }

    if (strspn("Proxy-Connection:", currentheader) ==
        strlen("Proxy-Connection:")) {
      strcat(*headers, "Proxy-Connection: close\r\n");
    } else if (strspn("Connection:", currentheader) == strlen("Connection:")) {
      strcat(*headers, "Connection: close\r\n");
    } else {
      strcat(*headers, currentheader);
      strcat(*headers, "\n");
    }
  }
  free(localStart);
}

void getVersion(char* request, char** version) {
  char* localReq = Calloc(strlen(request) + 1, sizeof(char));
  char* localStart = localReq;

  /* Get first line from request */
  strncpy(localReq, request, (int)(strchr(request, '\n') - request) + 1);

  /* version comes after second space in request and before the first newline */
  strsep(&localReq, " ");
  strsep(&localReq, " ");
  char* token = strsep(&localReq, "\n");

  /* Copy, then free */
  *version = Calloc(strlen(token) + 1, sizeof(char));
  strncpy(*version, token, strlen(token) + 1);
  (*version)[strlen(token)] = '\0';

  free(localStart);
}


void tokenize(char* request, char** method, char** hostname, char** filepath,
               int* port, char** uri, char** version, char** headers, char** formatReq) {
  get_method(request, method);
  getHostPort(request, hostname, port);
  char* localReq = Calloc(strlen(request) + 1, sizeof(char));
  char* localStart = localReq;

  strncpy(localReq, request, (int)(strchr(request, '\n') - request) + 1);

  /* Filepath comes after three /'s and before the http method */
  strsep(&localReq, "/");
  strsep(&localReq, "/");
  strsep(&localReq, "/");
  char* token = strsep(&localReq, " ");

  /* Copy, then free */
  *filepath = Calloc(strlen(token) + 2, sizeof(char));
  sprintf(*filepath, "/%s", token);
  (*filepath)[strlen(token) + 1] = '\0';

  free(localStart);
  

  getURI(request, uri);
  getVersion(request, version);
  getHeaders(request, headers);

  
  if(*method == NULL || *filepath == NULL || *version == NULL || *headers == NULL) {
    fprintf(stderr, "Error: invalid parsing of http request parameters\n");
  }

  int sizeOfformatReq = strlen(*method) + strlen(*filepath) + strlen(*version) + strlen(*headers) + 7;
  *formatReq = Calloc(sizeOfformatReq, sizeof(char));

  sprintf(*formatReq, "%s %s HTTP/1.0\r\n%s", *method, *filepath, *headers);
}