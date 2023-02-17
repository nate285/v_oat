#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/socket.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

int main(int argc, char *argv[])
{
    char *host_addr = argv[1];
    int port = atoi(argv[2]);

    /* Open a socket */
    int s;
    if ((s = socket(PF_INET, SOCK_STREAM, 0)) < 0)
    {
        perror("simplex-talk: socket");
        exit(1);
    }

    /* Config the server address */
    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = inet_addr(host_addr);
    sin.sin_port = htons(port);
    // Set all bits of the padding field to 0

    memset(sin.sin_zero, '\0', sizeof(sin.sin_zero));

    /* Connect to the server */
    if (connect(s, (struct sockaddr *)&sin, sizeof(sin)) < 0)
    {
        perror("simplex-talk: connect");
        close(s);
        exit(1);
    }
    size_t buf_size = 200;
    char *buf;
    char *recBuf;
    int ret;
    int len;
    int recLen;
    while (1)
    {
        recBuf = malloc(sizeof(char) * 200);
        recLen = recv(s, recBuf, sizeof(char) * 200, 0);
        recBuf[recLen] = '\0';
        if (recLen < 1)
            break;
        fputs(recBuf, stdout);
        fputc('\n', stdout);
        fflush(stdout);

        buf = malloc(sizeof(char) * 200);
        ret = getline(&buf, &buf_size, stdin);
        len = strlen(buf) + 1;
        if (ret == 0)
        {
            break;
        }
        send(s, buf, len, 0);
        free(buf);
        free(recBuf);
    }

    close(s);
}