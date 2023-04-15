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

#define MAX_LENGTH 16000

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
std::vector<std::pair<helib::Ctxt, helib::Ctxt>> encrypted_user_db;
Ballot *ballot;
SSL *ssl_maintainer;
int sock;
int sock_maintainer;
int maintainer_connection;
int num_candidates;
int num_voters;

/* HELIB INITIALIZATION */
unsigned long p = 131;
unsigned long m = 130;
unsigned long r = 1;
unsigned long bits = 1000;
unsigned long c = 3;

SSL_CTX *ctx;
const SSL_METHOD *meth;

void sigStpHandler(int signum)
{
    close(sock);
}

bool verifyNonZero(helib::Ctxt ctxt) {
    ctxt.power(p-1);
    totalSums(ctxt);
    ctxt.power(p-1);
    return verifyChecker(ctxt);
}

bool verifyUser(SSL* ssl) {
    helib::Ctxt username = receiveVote(ssl, 0);
    //check if username is just E(0)
    if (!verifyNonZero(username))
        return false;
    std::cout << "username nonzero" << std::endl;
    
    int receive = 1;
    if (SSL_write(ssl, &receive, sizeof(int)) <= 0)
    {
        perror("SSL_write receive");
        exit(EXIT_FAILURE);
    }
    std::vector<helib::Ctxt> duplicateCheck;
    for (auto pair : encrypted_user_db) {
        helib::Ctxt username_copy = pair.first;
        username_copy -= username;                //difference
        username_copy.power(p-1);                 //flt
        totalSums(username_copy);                 //totalsum
        username_copy.power(p-1);                 //flt
        username_copy.negate();                   //negate
        username_copy.addConstant(NTL::ZZX(1));   //add 1
        // at this point it is E(1) if match, or E(0) if not
        duplicateCheck.push_back(username_copy);  //for use later
    }
    std::cout << "username comparison complete" << std::endl;
    helib::Ctxt password = receiveVote(ssl, 0);
    if (!verifyNonZero(password))
        return false;
    std::cout << "password nonzero" << std::endl;

    helib::Ctxt checker = duplicateCheck[0];
    checker *= encrypted_user_db[0].second;
    for (int i = 1; i < encrypted_user_db.size(); ++i) {
        helib::Ctxt checkCopy = duplicateCheck[i];
        checkCopy *= encrypted_user_db[i].second;
        checker += checkCopy;
    }
    std::cout << "password addition complete" << std::endl;
    // should be E(password) if match
    checker -= password;
    checker.addConstant(NTL::ZZX(1)); 
    if (verifyChecker(checker)) {
        for (int i = 0; i < encrypted_user_db.size(); ++i) {
            helib::Ctxt name_copy = encrypted_user_db[i].first;
            name_copy *= duplicateCheck[i];
            encrypted_user_db[i].first -= name_copy; //should be 0 if match or remain
            helib::Ctxt pass_copy = encrypted_user_db[i].second;
            pass_copy *= duplicateCheck[i];
            encrypted_user_db[i].second -= pass_copy; //should be 0 if match or remain
        }
        return true;
    }
    return false;
}

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
    if (SSL_write(ssl, accept, 21) < 0)
    {
        perror("send accept");
        exit(EXIT_FAILURE);
    }
    sendCandidateInfo(ssl); // send candidate names
    int receive;
    if (SSL_read(ssl, &receive, sizeof(int)) <= 0)
    {
        perror("SSL_read verify");
        exit(EXIT_FAILURE);
    }
    if (receive) std::cout << "CANDIDATE SUCCESS" << std::endl;
    sendContext(ssl);
    if (SSL_read(ssl, &receive, sizeof(int)) <= 0)
    {
        perror("SSL_read verify");
        exit(EXIT_FAILURE);
    }
    if (receive) std::cout << "CONTEXT SUCCESS" << std::endl;
    sendPubKey(ssl);
    if (SSL_read(ssl, &receive, sizeof(int)) <= 0)
    {
        perror("SSL_read verify");
        exit(EXIT_FAILURE);
    }
    if (receive) std::cout << "PUBKEY SUCCESS" << std::endl;

    /* USER VERIFICATION */
    int count = 5;
    while (true) {
        if (!verifyUser(ssl)) {
            int not_good = 0;
            if (SSL_write(ssl, &not_good, sizeof(int)) <= 0)
            {
                perror("SSL_read verify");
                exit(EXIT_FAILURE);
            }
            if (count-- == 0) {
                pthread_exit(NULL);
            }
        } else break;
    }
    int good = 1;
    if (SSL_write(ssl, &good, sizeof(int)) <= 0)
    {
        perror("SSL_read verify");
        exit(EXIT_FAILURE);
    }

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
        if (verifyVote(received_vote, vote_template))
        {
            cout << "CASTING...." << endl;
            helib::Ctxt vote(received_vote);
            vote -= vote_template; // TODO: Recrypt if needed

            ballot->cast(0, vote); // TODO: replace 0 with voter id
            cout << "CASTING COMPLETE" << endl;
            const char *vote_casted = "Vote Valid and accepted\n";
            if (SSL_write(ssl, vote_casted, strnlen(vote_casted, 25)) < 0)
            {
                perror("send vote_valid");
                exit(EXIT_FAILURE);
            }
            break;
        }
        const char *accept = "Not accepted\n";
        if (SSL_write(ssl, accept, strlen(accept) + 1) < 0)
        {
            perror("send accept");
            exit(EXIT_FAILURE);
        }
    }

    pthread_exit(NULL);
}

bool verify(SSL *ssl, const char *msg, int len)
{
    std::cout << "verify: " << msg << std::endl;
    char *receive = (char *)malloc(sizeof(char) * (len + 1));
    if (SSL_read(ssl, receive, len) <= 0)
    {
        perror("SSL_read verify");
        exit(EXIT_FAILURE);
    }
    receive[len] = '\0';
    int ret = strncmp(msg, receive, len + 1);
    free(receive);
    return ret;
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

int sendContext(SSL *ssl)
{
    stringstream context_stream;
    context->writeToJSON(context_stream);
    string context_string = context_stream.str();
    const char *context_cstr = context_string.c_str();
    size_t length = context_string.length();
    if (SSL_write(ssl, context_cstr, length) < 0)
    {
        perror("send context");
        exit(EXIT_FAILURE);
    }
    return 1;
}

int sendPubKey(SSL *ssl)
{
    stringstream pubkey_stream;
    public_key->writeToJSON(pubkey_stream);
    string pubkey_string = pubkey_stream.str();
    const char *pubkey_cstr = pubkey_string.c_str();
    size_t length = pubkey_string.length();
    int wrote = 0;
    char pubkey_buf[MAX_LENGTH + 1]{0};
    // int counter = 1;
    while (wrote < length)
    {
        // std::cout << counter++ << ": " << wrote << std::endl;
        strncpy(pubkey_buf, &pubkey_cstr[wrote], MAX_LENGTH);
        if (SSL_write(ssl, pubkey_buf, strlen(pubkey_buf) + 1) < 0)
        {
            perror("send Public Key");
            exit(EXIT_FAILURE);
        }
        // cout << strlen(pubkey_buf) << endl;
        wrote += MAX_LENGTH;
    }
    return 1;
}

int sendVoteTemplate(SSL *ssl, helib::Ctxt &vote_template)
{
    stringstream vt_stream;
    vote_template.writeToJSON(vt_stream);
    string vt_string = vt_stream.str();
    const char *vt_cstr = vt_string.c_str();
    size_t length = vt_string.length();
    int wrote = 0;
    char vt_buf[MAX_LENGTH + 1]{0};
    while (wrote < length)
    {
        strncpy(vt_buf, &vt_cstr[wrote], MAX_LENGTH);
        if (SSL_write(ssl, vt_buf, strlen(vt_buf) + 1) < 0)
        {
            perror("send Public Key");
            exit(EXIT_FAILURE);
        }
        // cout << strlen(vt_buf) << endl;
        wrote += MAX_LENGTH;
    }

    return length;
}

helib::Ctxt receiveVote(SSL *ssl, int length)
{
    int data_read = 0;
    char *vote = (char *)malloc(MAX_LENGTH + 2);
    std::stringstream vote_stream;
    while (true)
    {
        memset(vote, 0, MAX_LENGTH + 1);
        if ((data_read = SSL_read(ssl, vote, MAX_LENGTH + 1)) <= 0)
        {
            perror("SSL_read ciph");
            exit(EXIT_FAILURE);
        }
        vote[MAX_LENGTH + 1] = '\0';
        vote_stream << vote;
        if (data_read < MAX_LENGTH + 1)
            break;
    }
    free(vote);
    helib::Ctxt deserialized_vote = helib::Ctxt::readFromJSON(vote_stream, *public_key);
    return deserialized_vote;
}

bool verifyVote(helib::Ctxt &received_vote, helib::Ctxt &vote_template)
{
    // check for noisebound
    // noisebound must be exactly double that of original
    const NTL::xdouble original_noise = vote_template.getNoiseBound();
    const NTL::xdouble received_noise = received_vote.getNoiseBound();
    std::cout << "noise" << std::endl;
    if (!(original_noise * 2 == received_noise))
        return false;

    helib::Ctxt one_hot_checker = received_vote; // copy constructor
    helib::Ctxt multiple_votes_checker = received_vote;
    helib::Ctxt valid_region_checker = received_vote;

    // one hot
    one_hot_checker -= vote_template;
    one_hot_checker.power(p - 1);
    helib::totalSums(one_hot_checker);
    // check if 11111
    if (!verifyChecker(one_hot_checker))
        return false;

    // multiple votes
    multiple_votes_checker -= vote_template;
    helib::totalSums(multiple_votes_checker);
    // check if 11111
    if (!verifyChecker(multiple_votes_checker))
        return false;

    // valid region
    valid_region_checker -= vote_template;
    int nslots = context->getNSlots();
    helib::Ptxt<helib::BGV> valid_region(*context);
    for (int i = 0; i < num_candidates; ++i)
        valid_region.at(i) = 1;
    valid_region_checker *= valid_region;
    helib::totalSums(valid_region_checker);
    // check if 11111
    return verifyChecker(valid_region_checker);
}

bool verifyChecker(helib::Ctxt& ctxt)
{
    int type = 0;
    if (SSL_write(ssl_maintainer, &type, sizeof(int)) < 0)
    {
        perror("send type");
        exit(EXIT_FAILURE);
    }
    stringstream ctxt_stream;
    ctxt.writeToJSON(ctxt_stream);
    string ctxt_string = ctxt_stream.str();
    const char *ctxt_cstr = ctxt_string.c_str();
    size_t length = ctxt_string.length();
    int wrote = 0;
    char vt_buf[MAX_LENGTH + 1]{0};
    while (wrote < length)
    {
        strncpy(vt_buf, &ctxt_cstr[wrote], MAX_LENGTH);
        if (SSL_write(ssl_maintainer, vt_buf, strlen(vt_buf) + 1) < 0)
        {
            perror("send checker");
            exit(EXIT_FAILURE);
        }
        // cout << strlen(vt_buf) << endl;
        wrote += MAX_LENGTH;
    }
    int check;
    if (SSL_read(ssl_maintainer, &check, sizeof(int)) < 0)
    {
        perror("receive check");
        exit(EXIT_FAILURE);
    }
    return check == 1;
}

void handleMaintainerConnectionInit() {
    X509 *client_cert;

    ssl_maintainer = SSL_new(ctx);
    SSL_use_certificate_file(ssl_maintainer, "cert.pem", SSL_FILETYPE_PEM);
    SSL_use_PrivateKey_file(ssl_maintainer, "key.pem", SSL_FILETYPE_PEM);
    SSL_set_fd(ssl_maintainer, maintainer_connection);
    SSL_accept(ssl_maintainer);
    client_cert = SSL_get_peer_certificate(ssl_maintainer);
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
    if (SSL_write(ssl_maintainer, accept, 21) < 0)
    {
        perror("send accept");
        exit(EXIT_FAILURE);
    }

    if (SSL_read(ssl_maintainer, &num_candidates, sizeof(int)) <= 0)
    {
        perror("SSL_read num_candidates");
        exit(EXIT_FAILURE);
    }
    
    if (SSL_read(ssl_maintainer, &num_voters, sizeof(int)) <= 0)
    {
        perror("SSL_read num_voters");
        exit(EXIT_FAILURE);
    }

    
    if (SSL_write(ssl_maintainer, &p, sizeof(unsigned long)) < 0)
    {
        perror("send p");
        exit(EXIT_FAILURE);
    }
    if (SSL_write(ssl_maintainer, &m, sizeof(unsigned long)) < 0)
    {
        perror("send m");
        exit(EXIT_FAILURE);
    }
    if (SSL_write(ssl_maintainer, &r, sizeof(unsigned long)) < 0)
    {
        perror("send r");
        exit(EXIT_FAILURE);
    }
    if (SSL_write(ssl_maintainer, &bits, sizeof(unsigned long)) < 0)
    {
        perror("send bits");
        exit(EXIT_FAILURE);
    }
    if (SSL_write(ssl_maintainer, &c, sizeof(unsigned long)) < 0)
    {
        perror("send c");
        exit(EXIT_FAILURE);
    }

    size_t cand_len;
    if (SSL_read(ssl_maintainer, &cand_len, sizeof(size_t)) <= 0)
    {
        perror("SSL_read cand_len");
        exit(EXIT_FAILURE);
    }
    char *cands = (char *)malloc(sizeof(char) * (cand_len + 2));
    if (SSL_read(ssl_maintainer, cands, cand_len + 1) <= 0)
    {
        perror("SSL_read candidates");
        exit(EXIT_FAILURE);
    }
    cands[cand_len + 1] = '\0';
    stringstream cand_ss{std::string{cands}};
    string candidate;
    while(std::getline(cand_ss, candidate, '&')) {
        candidates.push_back(candidate);
    }

    // Print Candidates
    for (int i = 0; i < candidates.size(); ++i)
    {
        std::cout << i + 1 << ") " << candidates[i] << std::endl;
    }

    int receive = 1;
    if (SSL_write(ssl_maintainer, &receive, sizeof(int)) <= 0)
    {
        perror("SSL_write receive");
        exit(EXIT_FAILURE);
    }
}

void getVoterInformation() {
    int receive = 1;
    for (int i = 0; i < num_voters; ++i) 
    {
        helib::Ctxt username = receiveVote(ssl_maintainer, 0);
        if (SSL_write(ssl_maintainer, &receive, sizeof(int)) <= 0)
        {
            perror("SSL_write receive");
            exit(EXIT_FAILURE);
        }
        helib::Ctxt password = receiveVote(ssl_maintainer, 0);
        if (SSL_write(ssl_maintainer, &receive, sizeof(int)) <= 0)
        {
            perror("SSL_write receive");
            exit(EXIT_FAILURE);
        }
        encrypted_user_db.push_back(std::make_pair(username, password));
    }
    std::cout << "num voters: " << encrypted_user_db.size() << std::endl;
}

int main(int argc, char *argv[])
{
    signal(SIGTSTP, sigStpHandler);
    /* -----------------------------------------------------------------------*/
    /* OPEN CONNECTION WITH MAINTAINER */
    /* -----------------------------------------------------------------------*/
    InitializeSSL();
    if ((sock_maintainer = socket(PF_INET, SOCK_STREAM, 0)) < 0)
    {
        perror("simplex-talk: socket");
        exit(1);
    }
    /* Config the server address */
    struct sockaddr_in sin_maintainer;
    sin_maintainer.sin_family = AF_INET;
    sin_maintainer.sin_addr.s_addr = inet_addr("127.0.0.1"); // TODO: change inet addr
    sin_maintainer.sin_port = htons(8081);
    // Set all bits of the padding field to 0
    memset(sin_maintainer.sin_zero, '\0', sizeof(sin_maintainer.sin_zero));

    /* Bind the socket to the address */
    if ((bind(sock_maintainer, (struct sockaddr *)&sin_maintainer, sizeof(sin_maintainer))) < 0)
    {
        perror("simplex-talk: bind");
        exit(1);
    }

    // connections can be pending if many concurrent client requests
    listen(sock_maintainer, 1); // TODO: change concurrent max

    socklen_t len_maintainer = sizeof(sin_maintainer);
    if ((maintainer_connection = accept(sock_maintainer, (struct sockaddr *)&sin_maintainer, &len_maintainer)) < 0)
    {
        perror("simplex-talk:accepct");
        exit(1);
    }
    handleMaintainerConnectionInit();
    
    /* RECEIVE CONTEXT*/
    char buffer[MAX_LENGTH + 1]{0};
    if (SSL_read(ssl_maintainer, buffer, MAX_LENGTH + 1) <= 0)
    {
        perror("SSL_read context");
        exit(EXIT_FAILURE);
    }
    std::stringstream context_stream{std::string(buffer)};
    helib::Context ctxt = helib::Context::readFromJSON(context_stream);
    context = &ctxt;
    int receive = 1;
    if (SSL_write(ssl_maintainer, &receive, sizeof(int)) < 0)
    {
        perror("send receive");
        exit(EXIT_FAILURE);
    }

    /* RECEIVE PUBLIC KEY*/
    int data_read = 0;
    std::stringstream pubkey_stream;
    std::cout << "Reading pubkey..." << std::endl;
    while (true)
    {
        memset(buffer, 0, MAX_LENGTH + 1);
        if ((data_read = SSL_read(ssl_maintainer, buffer, MAX_LENGTH + 1)) <= 0)
        {
            perror("SSL_read pubkey");
            exit(EXIT_FAILURE);
        }
        pubkey_stream << buffer;
        if (data_read < MAX_LENGTH + 1)
            break;
    }
    std::cout << "Reading pubkey success" << std::endl;
    helib::PubKey pubkey = helib::PubKey::readFromJSON(pubkey_stream, ctxt);
    public_key = &pubkey;
    if (SSL_write(ssl_maintainer, &receive, sizeof(int)) < 0)
    {
        perror("send receive");
        exit(EXIT_FAILURE);
    }
    getVoterInformation();

    helib::Ptxt<helib::BGV> ptxt_ballot(*context);
    /* CREATE BALLOT */
    ballot = new Ballot{candidates, ptxt_ballot, *public_key};

    ballot->showCandidateInfo();

    /* -----------------------------------------------------------------------*/
    /* OPENING USER SERVER */
    /* -----------------------------------------------------------------------*/

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

    while (1) // done when we reach maximum vote count or when time limit reaches?
    {
        if ((new_s = accept(sock, (struct sockaddr *)&sin, &len)) < 0)
        {
            perror("simplex-talk:accepct");
            break;
        }

        pthread_t new_thread;
        pthread_create(&new_thread, NULL, casting_vote, &new_s);
    }
    // close ballot
    ballot->close();
    ballot->showResult(context, ssl_maintainer);
}