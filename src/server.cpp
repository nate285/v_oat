#include <iostream>
#include <sstream>
#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>

#include <openssl/rsa.h>
#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include <sys/socket.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <helib/helib.h>
#include <helib/EncryptedArray.h>
#include <helib/ArgMap.h>
#include <NTL/BasicThreadPool.h>

#include "Ballot.hpp"
#include "helpers.hpp"

using namespace std;

#define HOME "./"

#define CERTF HOME "cert.pem"

#define KEYF HOME "key.pem"

#define CHK_NULL(x)  \
    if ((x) == NULL) \
    exit(1)
#define CHK_ERR(err, s) \
    if ((err) == -1)    \
    {                   \
        perror(s);      \
        exit(1);        \
    }
#define CHK_SSL(err)                 \
    if ((err) == -1)                 \
    {                                \
        ERR_print_errors_fp(stderr); \
        exit(2);                     \
    }

helib::Context *context;
helib::PubKey *public_key;
vector<string> candidates;
Ballot *ballot;

SSL_CTX *ctx;
const SSL_METHOD *meth;

void InitializeSSL()
{

    signal(SIGPIPE, SIG_IGN);

    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
    meth = TLS_server_method();
    ctx = SSL_CTX_new(meth);
    if (!ctx)
    {
        ERR_print_errors_fp(stderr);
        exit(2);
    }

    if (SSL_CTX_use_certificate_file(ctx, CERTF, SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr);
        exit(3);
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, KEYF, SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr);
        exit(4);
    }

    if (!SSL_CTX_check_private_key(ctx))
    {
        fprintf(stderr, "Private key does not match the certificate public key\n");
        exit(5);
    }
}

void *casting_vote(void *socket_ptr)
{
    int new_s = *((int *)socket_ptr);
    size_t client_len;
    SSL *ssl;
    X509 *client_cert;

    ssl = SSL_new(ctx);
    SSL_use_certificate_file(ssl, "cert.pem", SSL_FILETYPE_PEM);
    SSL_use_PrivateKey_file(ssl, "key.pem", SSL_FILETYPE_PEM);

    SSL_set_fd(ssl, new_s);

    SSL_accept(ssl);

    client_cert = SSL_get_peer_certificate(ssl);
    char *strr;

    if (client_cert != NULL)
    {
        printf("Client certificate:\n");

        strr = X509_NAME_oneline(X509_get_subject_name(client_cert), 0, 0);
        CHK_NULL(strr);
        printf("\t subject: %s\n", strr);
        OPENSSL_free(strr);

        strr = X509_NAME_oneline(X509_get_issuer_name(client_cert), 0, 0);
        CHK_NULL(strr);
        printf("\t issuer: %s\n", strr);
        OPENSSL_free(strr);
        X509_free(client_cert);
    }
    else
    {
        fprintf(stderr, "no cert\n");
    }

    const char *accept = "CONNECTION ACCEPTED\n";
    if (SSL_write(ssl, accept, strlen(accept) + 1) < 0)
    {
        perror("send accept");
        exit(EXIT_FAILURE);
    }
    sendCandidateInfo(ssl); // send candidate names

    helib::Ctxt *v_template;
    helib::Ctxt *received;
    while (true)
    {
        helib::Ptxt<helib::BGV> ptxt_vote_template(*context);
        // TODO: insert random numbers as OTP saltq
        // right now is just 0~size-1
        for (long i = 0; i < context->getNSlots(); ++i)
        {
            ptxt_vote_template.at(i) = i;
        }

        helib::Ctxt vote_template(*public_key);
        public_key->Encrypt(vote_template, ptxt_vote_template);

        int len = sendVoteTemplate(ssl, vote_template);

        helib::Ctxt received_vote(receiveVote(ssl, len));
        if (verifyVote(received_vote))
        {
            v_template = &vote_template;
            received = &received_vote;
            break;
        }
        const char *accept = "Invalid Vote. Please try again.";
        if (SSL_write(ssl, accept, strlen(accept) + 1) < 0)
        {
            perror("send accept");
            exit(EXIT_FAILURE);
        }
    }

    helib::Ctxt vote(*received);
    vote -= *v_template; // TODO: Recrypt if needed

    ballot->cast(0, vote); // TODO: replace 0 with voter id

    return NULL;
}

void sendCandidateInfo(SSL *ssl)
{
    stringstream cand_ss;
    int i;
    for (i = 0; i < candidates.size() - 1; ++i)
    {
        cand_ss << candidates[i] << "&";
    }
    cand_ss << candidates[i];
    // cout << cand_ss.str() << endl;
    string cand_string = cand_ss.str();
    const char *cand = cand_string.c_str();
    size_t len = strlen(cand);
    if (SSL_write(ssl, &len, sizeof(len)) < 0)
    {
        perror("send length");
        exit(EXIT_FAILURE);
    }
    if (SSL_write(ssl, cand, strlen(cand)) < 0)
    {
        perror("send candidates");
        exit(EXIT_FAILURE);
    }
}

int sendVoteTemplate(SSL *ssl, helib::Ctxt &vote_template)
{
    stringstream vt_stream;
    vote_template.writeToJSON(vt_stream);
    string vt_string = vt_stream.str() + '\0';
    const char *vt_cstr = vt_string.c_str();
    size_t length = strlen(vt_cstr);
    if (SSL_write(ssl, &length, sizeof(length)) < 0)
    {
        perror("send vote template length");
        exit(EXIT_FAILURE);
    }
    int len;
    if ((len = SSL_write(ssl, vt_cstr, strlen(vt_cstr))) < 0)
    {
        perror("send vote template");
        exit(EXIT_FAILURE);
    }
    return len;
}

helib::Ctxt receiveVote(SSL *ssl, int length)
{
    char rec_buf[length + 1];
    if (SSL_read(ssl, rec_buf, length + 1) < 0)
    {
        perror("receive vote");
        exit(EXIT_FAILURE);
    }
    // string rv = rec_buf;
    stringstream rv_stream;
    rv_stream << rec_buf;
    helib::Ctxt deserialized_vote = helib::Ctxt::readFrom(rv_stream, *public_key);
    return deserialized_vote;
}

bool verifyVote(helib::Ctxt &received_vote)
{
    return true;
}

int main(int argc, char *argv[])
{
    /* -----------------------------------------------------------------------*/
    /* INITIALIZATION */
    /* -----------------------------------------------------------------------*/
    cout << "Registering Candidates" << endl;
    cout << "How many canidates would you like to register?" << endl;
    int num_candidates;
    cin >> num_candidates; // TODO: buffer overflow?
    for (int i = 0; i < num_candidates; i++)
    {
        char *candidate_name = (char *)malloc(sizeof(char) * 100);
        cout << "Registering candidate " << i + 1 << endl;
        cout << "Enter name " << endl;
        cin >> candidate_name; // TODO: buffer overflow?
        candidates.emplace_back(candidate_name);
        free(candidate_name);
    }

    /* HELIB INITIALIZATION */
    unsigned long p = 131;
    unsigned long m = 130;
    unsigned long r = 1;
    unsigned long bits = 1000;
    unsigned long c = 2;

    cout << "---Initialising HE Environment ... ";

    /* CONTEXT */
    cout << "\nInitializing the Context ... ";
    context = new helib::Context(helib::ContextBuilder<helib::BGV>()
                                     .m(m)
                                     .p(p)
                                     .r(r)
                                     .bits(bits)
                                     .c(c)
                                     .build());

    /* SECRET KEY */
    cout << "\nCreating Secret Key ...";
    // Create a secret key associated with the context
    helib::SecKey secret_key = helib::SecKey(*context);
    // Generate the secret key
    secret_key.GenSecKey();
    // Compute key-switching matrices that we need
    helib::addSome1DMatrices(secret_key);

    /* PUBLIC KEY */
    cout << "\nCreating Public Key ...";
    public_key = new helib::PubKey(secret_key);
    // Get the EncryptedArray of the context
    const helib::EncryptedArray &ea = context->getEA();

    // Print the security level
    // Note: This will be negligible to improve performance time.
    cout << "\n***Security Level: " << context->securityLevel()
         << " *** Negligible for this example ***" << endl;

    // Get the number of slot (phi(m))
    long nslots = ea.size();
    cout << "\nNumber of slots: " << nslots << endl;

    cout << "\nInitialization Completed" << endl;
    cout << "--------------------------" << endl;

    helib::Ptxt<helib::BGV> ptxt_ballot(*context);
    /* CREATE BALLOT */
    ballot = new Ballot{candidates, ptxt_ballot, *public_key};

    ballot->showCandidateInfo();

    /* -----------------------------------------------------------------------*/
    /* OPENING SERVER */
    /* -----------------------------------------------------------------------*/
    InitializeSSL();
    int sock;
    int port = 8080; // TODO: change port
    if ((sock = socket(PF_INET, SOCK_STREAM, 0)) < 0)
    {
        perror("simplex-talk: socket");
        exit(1);
    }
    /* Config the server address */
    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = inet_addr("127.0.0.1"); // TODO: change inet addr
    sin.sin_port = htons(port);
    // Set all bits of the padding field to 0
    memset(sin.sin_zero, '\0', sizeof(sin.sin_zero));

    /* Bind the socket to the address */
    if ((bind(sock, (struct sockaddr *)&sin, sizeof(sin))) < 0)
    {
        perror("simplex-talk: bind");
        exit(1);
    }

    // connections can be pending if many concurrent client requests
    listen(sock, 10); // TODO: change concurrent max

    int new_s;
    socklen_t len = sizeof(sin);

    int vote_count = 0;

    while (vote_count++ < 1) // done when we reach maximum vote count or when time limit reaches?
    {
        if ((new_s = accept(sock, (struct sockaddr *)&sin, &len)) < 0)
        {
            perror("simplex-talk:accepct");
            exit(1);
        }

        pthread_t new_thread;
        pthread_create(&new_thread, NULL, casting_vote, &new_s);
    }
    // close ballot
    ballot->close();
    ballot->showResult(context, secret_key);
}