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
int num_votes = 0;

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

void sendVerify(SSL* ssl, int receive) {
    if (SSL_write(ssl, &receive, sizeof(int)) <= 0)
    {
        perror("[ERROR]: SSL_write receive");
    }
}

int receiveVerify(SSL* ssl) {
    int receive;
    if (SSL_read(ssl, &receive, sizeof(int)) <= 0)
    {
        perror("[ERROR]: SSL_read verify");
        SSL_free(ssl);
        return -1;
    }
    return receive;
}

bool verifyNonZero(helib::Ctxt ctxt) {
    ctxt.power(p-1);
    totalSums(ctxt);
    ctxt.power(p-1);
    return verifyChecker(ctxt);
}

bool verifyUser(SSL* ssl) {
    helib::Ctxt username = receiveCiphertext(ssl);
    //check if username is just E(0)
    if (!verifyNonZero(username))
        return false;
    
    sendVerify(ssl, 1);
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
    helib::Ctxt password = receiveCiphertext(ssl);
    if (!verifyNonZero(password))
        return false;

    helib::Ctxt checker = duplicateCheck[0];
    checker *= encrypted_user_db[0].second;
    for (int i = 1; i < encrypted_user_db.size(); ++i) {
        helib::Ctxt checkCopy = duplicateCheck[i];
        checkCopy *= encrypted_user_db[i].second;
        checker += checkCopy;
    }
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
    std::cout << "[INFO]: Initializing SSL ..." << std::endl;
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
    std::cout << "[INFO]: SSL Initialized." << std::endl;
}

SSL* handleUntilUserVerification(int new_s) {
    std::cout << "[INFO]: New voter accepted. Initializing SSL Connection ..." << std::endl;
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
    // else
    // {
    //     fprintf(stderr, "no cert\n");
    // }

    const char *accept = "CONNECTION ACCEPTED\n";
    if (SSL_write(ssl, accept, 21) < 0)
    {
        perror("send accept");
        exit(EXIT_FAILURE);
    }
    sendCandidateInfo(ssl); // send candidate names
    int receive = receiveVerify(ssl);
    if (receive) std::cout << "[INFO]: Candidate information sent." << std::endl;
    else return NULL;

    sendContext(ssl);
    receive = receiveVerify(ssl);
    if (receive) std::cout << "[INFO]: Context sent." << std::endl;
    else return NULL;
    
    sendPubKey(ssl);
    receive = receiveVerify(ssl);
    if (receive) std::cout << "[INFO]: Public Key sent." << std::endl;
    else return NULL;

    /* USER VERIFICATION */
    int count = 5;
    std::cout << "[INFO]: User Verification. User has 5 tries." << std::endl;
    while (true) {
        if (!verifyUser(ssl)) {
            std::cout << "[INFO]: Verification Failed. Trials left: " << --count << std::endl;
            sendVerify(ssl, 0);
            if (count == 0) {
                SSL_free(ssl);
                std::cout << "[INFO]: Verification Failed. Exiting ..." << std::endl;
                return NULL;
            }
        } else break;
    }
    sendVerify(ssl, 1);
    std::cout << "[INFO]: User Verified." << std::endl;
    return ssl;
}

void *casting_vote(void *socket_ptr)
{
    SSL* ssl = ((SSL *)socket_ptr);
    while (true)
    {
        std::cout << "[INFO]: Sending Vote Template ..." << std::endl;
        helib::Ptxt<helib::BGV> ptxt_vote_template(*context);
        // TODO: insert random numbers as OTP saltq
        // right now is just 0~size-1
        for (long i = 0; i < context->getNSlots(); ++i)
        {
            ptxt_vote_template.at(i) = i;
        }

        helib::Ctxt vote_template(*public_key);
        public_key->Encrypt(vote_template, ptxt_vote_template);

        int len = sendCiphertext(ssl, vote_template);

        std::cout << "[INFO]: Receiving Vote back ..." << std::endl;
        helib::Ctxt received_vote(receiveCiphertext(ssl));
        std::cout << "[INFO]: Verifying Vote ..." << std::endl;
        if (verifyVote(received_vote, vote_template))
        {
            std::cout << "[INFO]: Vote Verified. Casting ..." << std::endl;
            helib::Ctxt vote(received_vote);
            vote -= vote_template; // TODO: Recrypt if needed

            ballot->cast(0, vote); // TODO: replace 0 with voter id
            cout << "[INFO]: Casting Complete" << endl;
            const char *vote_casted = "Vote Valid and accepted\n";
            if (SSL_write(ssl, vote_casted, strnlen(vote_casted, 25)) < 0)
            {
                perror("send vote_valid");
                exit(EXIT_FAILURE);
            }
            break;
        }
        std::cout << "[INFO]: Trying Again ..." << std::endl;
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

int sendCiphertext(SSL *ssl, helib::Ctxt &vote_template)
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
        wrote += MAX_LENGTH;
    }

    return length;
}

helib::Ctxt receiveCiphertext(SSL *ssl)
{
    int data_read = 0;
    char *vote = (char *)malloc(MAX_LENGTH + 2);
    std::stringstream vote_stream;
    while (true)
    {
        memset(vote, 0, MAX_LENGTH + 1);
        if ((data_read = SSL_read(ssl, vote, MAX_LENGTH + 1)) <= 0)
        {
            perror("[ERROR]: SSL_read ciph");
            exit(1);
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
    if (!(original_noise * 2 == received_noise)) {
        std::cout << "[ERROR]: Verification Failed. Noise too big." << std::endl;
        return false;
    }

    helib::Ctxt one_hot_checker = received_vote; // copy constructor
    helib::Ctxt multiple_votes_checker = received_vote;
    helib::Ctxt valid_region_checker = received_vote;

    // one hot
    one_hot_checker -= vote_template;
    one_hot_checker.power(p - 1);
    helib::totalSums(one_hot_checker);
    // check if 11111
    if (!verifyChecker(one_hot_checker)) {
        std::cout << "[ERROR]: Verification Failed. Not one hot." << std::endl;
        return false;
    }

    // multiple votes
    multiple_votes_checker -= vote_template;
    helib::totalSums(multiple_votes_checker);
    // check if 11111
    if (!verifyChecker(multiple_votes_checker)) {
        std::cout << "[ERROR]: Verification Failed. Found Multiple Votes." << std::endl;
        return false;
    }

    // valid region
    valid_region_checker -= vote_template;
    int nslots = context->getNSlots();
    helib::Ptxt<helib::BGV> valid_region(*context);
    for (int i = 0; i < num_candidates; ++i)
        valid_region.at(i) = 1;
    valid_region_checker *= valid_region;
    helib::totalSums(valid_region_checker);
    // check if 11111
    if (!verifyChecker(valid_region_checker)) {
        std::cout << "[ERROR]: Verification Failed. Vote not in valid region." << std::endl;
        return false;
    }
    return true;
}

bool verifyChecker(helib::Ctxt& ctxt)
{
    sendVerify(ssl_maintainer, 0);
    sendCiphertext(ssl_maintainer, ctxt);
    int check = receiveVerify(ssl_maintainer);
    return check == 1;
}

void handleMaintainerConnectionInit() {
    std::cout << "[INFO]: Opening socket connection with maintainer ..." << std::endl;
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
    listen(sock_maintainer, 1);

    socklen_t len_maintainer = sizeof(sin_maintainer);
    std::cout << "[INFO]: Listening for maintainer connections ..." << std::endl;
    if ((maintainer_connection = accept(sock_maintainer, (struct sockaddr *)&sin_maintainer, &len_maintainer)) < 0)
    {
        perror("simplex-talk:accept");
        exit(1);
    }
    std::cout << "[INFO]: Maintainer Connection Accepted" << std::endl;
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

    std::cout << "[INFO]: Getting Ballot information and sending appropriate crypto context parameters ..." << std::endl;
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
    std::cout << "[INFO]: Got Candidates:" << std::endl;
    for (int i = 0; i < candidates.size(); ++i)
    {
        std::cout << i + 1 << ") " << candidates[i] << std::endl;
    }
    std::cout << std::endl;
    sendVerify(ssl_maintainer, 1);
}

void getVoterInformation() {
    std::cout << "[INFO]: Receiving Voter Information ..." << std::endl;
    for (int i = 0; i < num_voters; ++i) 
    {
        helib::Ctxt username = receiveCiphertext(ssl_maintainer);
        sendVerify(ssl_maintainer, 1);
        helib::Ctxt password = receiveCiphertext(ssl_maintainer);
        sendVerify(ssl_maintainer, 1);
        encrypted_user_db.push_back(std::make_pair(username, password));
    }
    std::cout << "[INFO]: Received and Saved. Number of voters: " << num_voters << std::endl;
}

int main(int argc, char *argv[])
{
    signal(SIGTSTP, sigStpHandler);
    /* -----------------------------------------------------------------------*/
    /* OPEN CONNECTION WITH MAINTAINER */
    /* -----------------------------------------------------------------------*/
    InitializeSSL();
    handleMaintainerConnectionInit();
    
    /* RECEIVE CONTEXT*/
    std::cout << "[INFO]: Receiving Crypto-Context and Public Key ..." << std::endl;
    char buffer[MAX_LENGTH + 1]{0};
    if (SSL_read(ssl_maintainer, buffer, MAX_LENGTH + 1) <= 0)
    {
        perror("SSL_read context");
        exit(EXIT_FAILURE);
    }
    std::stringstream context_stream{std::string(buffer)};
    helib::Context ctxt = helib::Context::readFromJSON(context_stream);
    context = &ctxt;
    sendVerify(ssl_maintainer, 1);

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
    sendVerify(ssl_maintainer, 1);
    std::cout << "\n***Security Level: " << ctxt.securityLevel()
              << "\n*** Negligible for this example to improve performance time ***\n" << std::endl;
    getVoterInformation();

    helib::Ptxt<helib::BGV> ptxt_ballot(*context);
    /* CREATE BALLOT */
    std::cout << "\n[INFO]: Creating Unique Ballot ..." << std::endl;
    ballot = new Ballot{candidates, ptxt_ballot, *public_key};

    std::cout << "[INFO]: Initialization Complete. Ready to listen to voter clients" << std::endl;
    std::cout << "-----------------------------------------------------------------" << std::endl;

    /* -----------------------------------------------------------------------*/
    /* OPENING USER SERVER */
    /* -----------------------------------------------------------------------*/
    std::cout << "\n\n[INFO]: Opening Voter Server ..." << std::endl;
    if ((sock = socket(PF_INET, SOCK_STREAM, 0)) < 0)
    {
        perror("simplex-talk: socket");
        exit(1);
    }
    /* Config the server address */
    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = inet_addr("127.0.0.1"); // TODO: change inet addr
    sin.sin_port = htons(8080); // change port
    // Set all bits of the padding field to 0
    memset(sin.sin_zero, '\0', sizeof(sin.sin_zero));

    /* Bind the socket to the address */
    if ((bind(sock, (struct sockaddr *)&sin, sizeof(sin))) < 0)
    {
        perror("simplex-talk: bind");
        exit(1);
    }

    listen(sock, 10); // TODO: change concurrent max
    socklen_t len = sizeof(sin);

    while (num_votes <= num_voters) // done when we reach maximum vote count or when time limit reaches?
    {
        int* new_s = (int *)calloc(1, sizeof(int));
        std::cout << "[INFO]: Listening for voters ..." << std::endl;
        if ((*new_s = accept(sock, (struct sockaddr *)&sin, &len)) < 0)
        {
            std::cout << "[INFO]: Closing ballot signal" << std::endl;
            break;
        }
        //want user verification to be serial, then vote casting parallel
        SSL* ssl = handleUntilUserVerification(*new_s);
        if (ssl == NULL) continue;
        
        pthread_t new_thread;
        pthread_create(&new_thread, NULL, casting_vote, (void*) ssl);
    }
    // close ballot
    ballot->close();
    ballot->showResult(context, ssl_maintainer);
}