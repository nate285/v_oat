#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/socket.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

#include <helib/helib.h>

std::vector<std::string> candidates;

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

    /* Check if connection is accepted */
    const char* accept = "CONNECTION ACCEPTED\n";
    char receive[200];
    recv(s, receive, 200, 0);
    if (strcmp(accept, receive) != 0) {
        fprintf(stdout, "Not Accepted");
        close(s);
    }
    fputs(receive, stdout);
    fflush(stdout);

    /* Receive Candidates */
    fprintf(stdout, "Candidates\n");
    size_t cand_len;
    if (recv(s, &cand_len, sizeof(size_t), 0) < 0) {
        perror("recv cand_len");
        exit(EXIT_FAILURE);
    }
    char cands[cand_len+1] = "";
    if (recv(s, cands, cand_len+1, 0) < 0) {
        perror("recv cand_len");
        exit(EXIT_FAILURE);
    }

    char *token;
    token = strtok(cands, "&");
    do
    {
        std::string candid(token);
        candidates.emplace_back(candid);
    } while (token = strtok(NULL, "&"));
    //TODO: Print candidates function
    for (int i = 0; i < candidates.size(); ++i) {
        std::cout << i << ") " << candidates[i] << std::endl;
    }

    size_t len;
    recv(s, &len, sizeof(size_t), 0);
    fprintf(stdout, "Received len: %ld\n", len);
    char json[len+1] = "";
    recv(s, json, len+1, 0);
    fputs(json, stdout);
    fflush(stdout);

    const char* rec = "RECEIVED";
    if (send(s, rec, strlen(rec), 0) < 0) {
        perror("send");
        close(s);
    }

    close(s);
}