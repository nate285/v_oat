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
helib::SecKey *secret_key;
vector<string> candidates;
std::vector<std::pair<helib::Ctxt, helib::Ctxt>> encrypted_user_db;
Ballot *ballot;
int sock;
int num_candidates;

/* HELIB INITIALIZATION */
// unsigned long p = 131;
// unsigned long m = 130;
// unsigned long r = 1;
// unsigned long bits = 1000;
// unsigned long c = 3;
unsigned long p = 2;
unsigned long m = 28679;
unsigned long r = 7;
unsigned long bits = 1000;
unsigned long c = 3;
unsigned long t = 64;
std::vector<long> mvec = std::vector<long>{17, 7, 241};
std::vector<long> gens = std::vector<long>{15184, 4098, 28204};
std::vector<long> ords = std::vector<long>{16, 6, -10};

SSL_CTX *ctx;
const SSL_METHOD *meth;

void sigStpHandler(int signum) {
  close(sock);
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
    if (SSL_write(ssl, accept, strlen(accept) + 1) < 0)
    {
        perror("send accept");
        exit(EXIT_FAILURE);
    }
    sendCandidateInfo(ssl); // send candidate names
    const char candidate_success[27] = "CANDIDATE RECIEVE SUCCESS\n";
    if (!verify(ssl, candidate_success, 27)) exit(EXIT_FAILURE);
    sendContext(ssl);
    const char context_success[25] = "CONTEXT RECIEVE SUCCESS\n";
    if (!verify(ssl, context_success, 25)) exit(EXIT_FAILURE);
    sendPubKey(ssl);
    const char pubkey_success[24] = "PUBKEY RECIEVE SUCCESS\n";
    if (!verify(ssl, pubkey_success, 24)) exit(EXIT_FAILURE);

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
            if (SSL_write(ssl, vote_casted, strlen(vote_casted) + 1) < 0)
            {
                perror("send vote_valid");
                exit(EXIT_FAILURE);
            }
            break;
        }
        const char *accept = "Not accepted\n";
        if (SSL_write(ssl, accept, strlen(accept) + 1) < 0) {
            perror("send accept");
            exit(EXIT_FAILURE);
        }
    }

    pthread_exit(NULL);
}

bool verify(SSL *ssl, const char* msg, int len) {
    std::cout << "verify: " << msg << std::endl;
    char receive[len]{0};
    if (SSL_read(ssl, receive, len) <= 0)
    {
        perror("SSL_read verify");
        exit(EXIT_FAILURE);
    }
    // std::cout << receive << endl;
    return strcmp(msg, receive) == 0;
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

int sendContext(SSL *ssl) {
    stringstream context_stream;
    context->writeToJSON(context_stream);
    string context_string = context_stream.str();
    const char* context_cstr = context_string.c_str();
    size_t length = context_string.length();
    if (SSL_write(ssl, context_cstr, length) < 0)
    {
        perror("send context");
        exit(EXIT_FAILURE);
    }
    return 1;
}

int sendPubKey(SSL *ssl) {
    stringstream pubkey_stream;
    std::cout << "writing pubkey to stream" << std::endl;
    public_key->writeToJSON(pubkey_stream);
    std::cout << "converting to string" << std::endl;
    string pubkey_string = pubkey_stream.str();
    std::cout << "converting to cstr" << std::endl;
    const char* pubkey_cstr = pubkey_string.c_str();
    std::cout << "getting length" << std::endl;
    size_t length = pubkey_string.length();
    std::cout << "length: " << length << std::endl;
    int wrote = 0;
    char pubkey_buf[MAX_LENGTH+1]{0};
    int counter = 1;
    while (wrote < length) {
        std::cout << counter++ << ": " << wrote << std::endl;
        strncpy(pubkey_buf, &pubkey_cstr[wrote], MAX_LENGTH);
        if (SSL_write(ssl, pubkey_buf, strlen(pubkey_buf) + 1) < 0) {
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
    char vt_buf[MAX_LENGTH+1]{0};
    while (wrote < length) {
        strncpy(vt_buf, &vt_cstr[wrote], MAX_LENGTH);
        if (SSL_write(ssl, vt_buf, strlen(vt_buf) + 1) < 0) {
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
    char vote[MAX_LENGTH+1]{0};
    std::stringstream vote_stream;
    while(true) {
        memset(vote, 0, MAX_LENGTH+1);
        if ((data_read = SSL_read(ssl, vote, MAX_LENGTH+1)) <= 0) {
            perror("SSL_read ciph");
            exit(EXIT_FAILURE);
        }        
        vote_stream << vote;
        if (data_read < MAX_LENGTH + 1) break;
    }
    helib::Ctxt deserialized_vote = helib::Ctxt::readFromJSON(vote_stream, *public_key);
    return deserialized_vote;
}

bool verifyVote(helib::Ctxt &received_vote, helib::Ctxt &vote_template)
{
    //check for noisebound
    //noisebound must be exactly double that of original
    const NTL::xdouble original_noise = vote_template.getNoiseBound();
    const NTL::xdouble received_noise = received_vote.getNoiseBound();
    if (!(original_noise * 2 == received_noise)) return false;

    helib::Ctxt one_hot_checker = received_vote; //copy constructor
    helib::Ctxt multiple_votes_checker = received_vote;
    helib::Ctxt valid_region_checker = received_vote;

    //one hot
    one_hot_checker -= vote_template;
    one_hot_checker.power(p-1);
    helib::totalSums(one_hot_checker);
    //check if 11111
    helib::Ptxt<helib::BGV> one_hot(*context);
    secret_key->Decrypt(one_hot, one_hot_checker);
    if (!verifyCheckerPtxt(one_hot)) return false;

    //multiple votes
    multiple_votes_checker -= vote_template;
    helib::totalSums(multiple_votes_checker);
    //check if 11111
    helib::Ptxt<helib::BGV> multiple_votes(*context);
    secret_key->Decrypt(multiple_votes, multiple_votes_checker);
    if (!verifyCheckerPtxt(multiple_votes)) return false;

    //valid region
    valid_region_checker -= vote_template;
    int nslots = context->getNSlots();
    helib::Ptxt<helib::BGV> valid_region(*context);
    for (int i = 0; i < num_candidates; ++i)
        valid_region.at(i) = 1;
    valid_region_checker *= valid_region;
    helib::totalSums(valid_region_checker);
    //check if 11111
    helib::Ptxt<helib::BGV> valid_regions(*context);
    secret_key->Decrypt(valid_regions, valid_region_checker);

    return verifyCheckerPtxt(valid_regions);
}

bool verifyCheckerPtxt(helib::Ptxt<helib::BGV> ptxt) {
    for (int i = 0 ; i < context->getNSlots(); ++i) {
        if (ptxt.at(i) != 1) return false;
    }
    return true;
}

// Utility function to read <K,V> CSV data from file
std::vector<std::pair<std::string, std::string>> read_csv(std::string filename)
{
  std::vector<std::pair<std::string, std::string>> dataset;
  std::ifstream data_file(filename);

  if (!data_file.is_open())
    throw std::runtime_error(
        "Error: This example failed trying to open the data file: " + filename +
        "\n           Please check this file exists and try again.");

  std::vector<std::string> row;
  std::string line, entry, temp;

  if (data_file.good()) {
    // Read each line of file
    while (std::getline(data_file, line)) {
      row.clear();
      std::stringstream ss(line);
      while (getline(ss, entry, ',')) {
        row.push_back(entry);
      }
      // Add key value pairs to dataset
      dataset.push_back(std::make_pair(row[0], row[1]));
    }
  }

  data_file.close();
  return dataset;
}

void RegisterVoters(std::string db_filename) {
    /************ Read in the database ************/
    std::vector<std::pair<std::string, std::string>> user_db;
    try {
        user_db = read_csv(db_filename);
    } catch (std::runtime_error& e) {
        std::cerr << "\n" << e.what() << std::endl;
        exit(1);
    }

     // Convert strings into numerical vectors
    std::cout << "\n---Initializing the encrypted key,value pair database ("
                << user_db.size() << " entries)...";
    std::cout
        << "\nConverting strings to numeric representation into Ptxt objects ..."
        << std::endl;

    // Generating the Plain text representation of User DB
    std::vector<std::pair<helib::Ptxt<helib::BGV>, helib::Ptxt<helib::BGV>>> user_db_ptxt;
    for (const auto& username_password_pair : user_db) {
        helib::Ptxt<helib::BGV> username(*context);
        for (long i = 0; i < username_password_pair.first.size(); ++i)
            username.at(i) = username_password_pair.first[i];

        helib::Ptxt<helib::BGV> password(*context);
        for (long i = 0; i < username_password_pair.second.size(); ++i)
            password.at(i) = username_password_pair.second[i];
        user_db_ptxt.emplace_back(std::move(username), std::move(password));
    }

    // Encrypt the User DB
    std::cout << "Encrypting the database..." << std::endl;
    for (const auto& username_password_pair : user_db_ptxt) {
        helib::Ctxt encrypted_username(*public_key);
        helib::Ctxt encrypted_password(*public_key);
        public_key->Encrypt(encrypted_username, username_password_pair.first);
        public_key->Encrypt(encrypted_password, username_password_pair.second);
        encrypted_user_db.emplace_back(std::move(encrypted_username), std::move(encrypted_password));
    }
    std::cout << "User Database Created" << std::endl;
}

int main(int argc, char *argv[])
{
    signal(SIGTSTP, sigStpHandler);
    /* -----------------------------------------------------------------------*/
    /* INITIALIZATION */
    /* -----------------------------------------------------------------------*/
    cout << "Registering Candidates" << endl;
    cout << "How many canidates would you like to register?" << endl;
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

    cout << "---Initialising HE Environment ... ";

    /* CONTEXT */
    cout << "\nInitializing the Context ... ";
    helib::Context ctxt = helib::ContextBuilder<helib::BGV>()
                                .m(m)
                                .p(p)
                                .r(r)
                                .bits(bits)
                                .c(c)
                                .gens(gens)
                                .ords(ords)
                                .mvec(mvec)
                                .bootstrappable(true)
                                .skHwt(t)
                                .build();

    // helib::Context ctxt = helib::ContextBuilder<helib::BGV>()
    //                            .m(m)
    //                            .p(p)
    //                            .r(r)
    //                            .bits(bits)
    //                            .c(c)
    //                            .build();
    context = &ctxt;

    /* SECRET KEY */
    cout << "\nCreating Secret Key ...";
    // Create a secret key associated with the context
    helib::SecKey sk = helib::SecKey(*context);
    // Generate the secret key
    sk.GenSecKey();
    std::cout << "\nGenerating key-switching matrices..." << std::endl;
    addSome1DMatrices(sk);
    addFrbMatrices(sk);
    // Generate bootstrapping data
    sk.genRecryptData();
    secret_key = &sk;

    /* PUBLIC KEY */
    cout << "\nCreating Public Key ...";
    public_key = new helib::PubKey(sk);
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
    /* VOTER REGISTRATION */
    /* -----------------------------------------------------------------------*/
    string db_filename = "../../user_dataset.csv";
    RegisterVoters(db_filename);

    /* -----------------------------------------------------------------------*/
    /* OPENING SERVER */
    /* -----------------------------------------------------------------------*/
    InitializeSSL();
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
    ballot->showResult(context, sk);
}