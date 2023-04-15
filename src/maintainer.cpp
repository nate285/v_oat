#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <string>
#include <sstream>
#include <iostream>

#include <sys/socket.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

#include <helib/helib.h>

#define MAX_LENGTH 16000

unsigned long p;
unsigned long m;
unsigned long r;
unsigned long bits;
unsigned long c;
// unsigned long t;
// std::vector<long> mvec = std::vector<long>{17, 7, 241};
// std::vector<long> gens = std::vector<long>{15184, 4098, 28204};
// std::vector<long> ords = std::vector<long>{16, 6, -10};

std::vector<std::string> candidates;
std::vector<std::pair<std::string, std::string>> voters;

helib::Context *context;
helib::PubKey *public_key;
helib::SecKey *secret_key;

BIO *certbio;
BIO *outbio;
SSL_CTX *ctx;
X509 *cert;
SSL *ssl;
int s;

bool verify() {
    int receive;
    if (SSL_read(ssl, &receive, sizeof(int)) <= 0)
    {
        perror("SSL_read verify");
        exit(EXIT_FAILURE);
    }
    return receive == 1;
}

void initSSL(int port) {
    std::cout << "[INFO]: Initializing SSL Connection with V-Oat ..." << std::endl;
    // Load algorithms and strings needed by OpenSSL
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
    SSL_load_error_strings();

    // Create the Input/Output BIOs
    certbio = BIO_new(BIO_s_file());
    outbio = BIO_new_fp(stdout, BIO_NOCLOSE);
    // Initialize OpenSSL.
    SSL_library_init();

    const SSL_METHOD *method = SSLv23_client_method();

    ctx = SSL_CTX_new(method);
    if (!ctx) {
        fprintf(stderr, "ctx no work\n\n");
    }

    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2);

    ssl = SSL_new(ctx);
    /* Open a socket */

    if ((s = socket(PF_INET, SOCK_STREAM, 0)) < 0)
    {
        perror("simplex-talk: socket");
        exit(1);
    }

    /* Config the server address */
    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = inet_addr("127.0.0.1"); //hard-coded
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
    if (SSL_set_fd(ssl, s) == 0)
    {
        perror("SSL_set_fd");
        exit(EXIT_FAILURE);
    }

    int err = SSL_connect(ssl);

    cert = SSL_get_peer_certificate(ssl);

    /* Check if connection is accepted */
    const char accept[21] = "CONNECTION ACCEPTED\n"; // for user authentication
    char receive[21];
    if (SSL_read(ssl, receive, 21) <= 0)
    {
        perror("SSL_read connection accepted");
        exit(EXIT_FAILURE);
    }
    if (strcmp(accept, receive) != 0) {
        fprintf(stdout, "Not Accepted");
        close(s);
    }
    std::cout << "[INFO]: Connection Complete and Accepted!" << std::endl;
}

std::vector<std::string> get_candidates(std::string filename) {
    std::vector<std::string> dataset;
    std::ifstream data_file(filename);

    if (!data_file.is_open())
        throw std::runtime_error(
            "Error: This example failed trying to open the data file: " + filename +
            "\n           Please check this file exists and try again.");

    std::string line;
    if (data_file.good())
    {
        while (std::getline(data_file, line))
        {
            dataset.push_back(line);
        }
    }

    data_file.close();
    return dataset;
}

// Utility function to read <K,V> CSV data from file
std::vector<std::pair<std::string, std::string>> get_voters(std::string filename)
{
    std::vector<std::pair<std::string, std::string>> dataset;
    std::ifstream data_file(filename);

    if (!data_file.is_open())
        throw std::runtime_error(
            "Error: This example failed trying to open the data file: " + filename +
            "\n           Please check this file exists and try again.");

    std::vector<std::string> row;
    std::string line, entry, temp;

    if (data_file.good())
    {
        // Read each line of file
        while (std::getline(data_file, line))
        {
            row.clear();
            std::stringstream ss(line);
            while (getline(ss, entry, ','))
            {
                row.push_back(entry);
            }
            // Add key value pairs to dataset
            dataset.push_back(std::make_pair(row[0], row[1]));
        }
    }

    data_file.close();
    return dataset;
}

void sendCiphertext(helib::Ctxt &ctxt) {
    std::stringstream ctxt_stream;
    ctxt.writeToJSON(ctxt_stream);
    std::string ctxt_string = ctxt_stream.str();
    const char *ctxt_cstr = ctxt_string.c_str();
    size_t length = ctxt_string.length();
    int wrote = 0;
    char ctxt_buf[MAX_LENGTH + 1]{0};
    while (wrote < length)
    {
        strncpy(ctxt_buf, &ctxt_cstr[wrote], MAX_LENGTH);
        if (SSL_write(ssl, ctxt_buf, strlen(ctxt_buf) + 1) < 0)
        {
            perror("send ctxt");
            exit(EXIT_FAILURE);
        }
        wrote += MAX_LENGTH;
    }
    if (!verify()) exit(1);
}



void initHelibContext(int num_candidates, int num_voters) {
    if (SSL_write(ssl, &num_candidates, sizeof(int)) < 0)
    {
        perror("send num candidates from maintainer");
        exit(EXIT_FAILURE);
    }
    if (SSL_write(ssl, &num_voters, sizeof(int)) < 0)
    {
        perror("send num voters from maintainer");
        exit(EXIT_FAILURE);
    }
    std::cout << "[INFO]: Sent V-Oat candidate and voter information" << std::endl;

    std::cout << "[INFO]: Receiving crypto parameters ..." << std::endl;
    if (SSL_read(ssl, &p, sizeof(unsigned long)) <= 0)
    {
        perror("SSL_read read p");
        exit(EXIT_FAILURE);
    }
    if (SSL_read(ssl, &m, sizeof(unsigned long)) <= 0)
    {
        perror("SSL_read read m");
        exit(EXIT_FAILURE);
    }
    if (SSL_read(ssl, &r, sizeof(unsigned long)) <= 0)
    {
        perror("SSL_read read r");
        exit(EXIT_FAILURE);
    }
    if (SSL_read(ssl, &bits, sizeof(unsigned long)) <= 0)
    {
        perror("SSL_read read bits");
        exit(EXIT_FAILURE);
    }
    if (SSL_read(ssl, &c, sizeof(unsigned long)) <= 0)
    {
        perror("SSL_read read c");
        exit(EXIT_FAILURE);
    }
    std::cout << "[INFO]: Crypto parameters received.\n[INFO]: Initializing Helib Context, Public Key, and Secret Key ..." << std::endl;
}

void sendCandidates() {
    std::cout << "[INFO]: Sending Candidate Information to V-Oat ..." << std::endl;
    std::stringstream cand_ss;
    int i;
    for (i = 0; i < candidates.size() - 1; ++i)
    {
        cand_ss << candidates[i] << "&";
    }
    cand_ss << candidates[i];
    std::string cand_string = cand_ss.str();
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
    if (!verify()) exit(1);
}

void encryptAndSendVoterInfo() {
    std::cout << "[INFO]: Encrypting voter database ..." << std::endl;
    std::vector<std::pair<helib::Ptxt<helib::BGV>, helib::Ptxt<helib::BGV>>> voters_ptxt;
    for (const auto &username_password_pair : voters)
    {
        helib::Ptxt<helib::BGV> username(*context);
        for (long i = 0; i < username_password_pair.first.size(); ++i)
            username.at(i) = username_password_pair.first[i];

        helib::Ptxt<helib::BGV> password(*context);
        for (long i = 0; i < username_password_pair.second.size(); ++i)
            password.at(i) = username_password_pair.second[i];
        voters_ptxt.emplace_back(std::move(username), std::move(password));
    }

    std::cout << "[INFO]: Sending Voter Information to V-Oat ..." << std::endl;
    for (const auto &username_password_pair : voters_ptxt)
    {
        helib::Ctxt encrypted_username(*public_key);
        helib::Ctxt encrypted_password(*public_key);
        public_key->Encrypt(encrypted_username, username_password_pair.first);
        public_key->Encrypt(encrypted_password, username_password_pair.second);
        sendCiphertext(encrypted_username);
        sendCiphertext(encrypted_password);
    }
}

void sendContext() {
    std::stringstream context_stream;
    context->writeToJSON(context_stream);
    std::string context_string = context_stream.str();
    const char *context_cstr = context_string.c_str();
    size_t length = context_string.length();
    if (SSL_write(ssl, context_cstr, length) < 0)
    {
        perror("send context");
        exit(EXIT_FAILURE);
    }
    std::cout << "[INFO]: Sending Context to V-Oat ..." << std::endl;
    int receive;
    if (SSL_read(ssl, &receive, sizeof(int)) <= 0)
    {
        perror("SSL_read verify context sent");
        exit(EXIT_FAILURE);
    }
}

void sendPubKey() {
    std::stringstream pubkey_stream;
    public_key->writeToJSON(pubkey_stream);
    std::string pubkey_string = pubkey_stream.str();
    const char *pubkey_cstr = pubkey_string.c_str();
    size_t length = pubkey_string.length();
    int wrote = 0;
    char pubkey_buf[MAX_LENGTH + 1]{0};
    while (wrote < length)
    {
        strncpy(pubkey_buf, &pubkey_cstr[wrote], MAX_LENGTH);
        if (SSL_write(ssl, pubkey_buf, strlen(pubkey_buf) + 1) < 0)
        {
            perror("send Public Key");
            exit(EXIT_FAILURE);
        }
        wrote += MAX_LENGTH;
    }
    std::cout << "[INFO]: Sending Public Key to V-Oat ..." << std::endl;
    int receive;
    if (SSL_read(ssl, &receive, sizeof(int)) <= 0)
    {
        perror("SSL_read verify pubkey sent");
        exit(EXIT_FAILURE);
    }
}

bool verify(helib::Ctxt& v_ctxt) {
    helib::Ptxt<helib::BGV> v_ptxt(*context);
    secret_key->Decrypt(v_ptxt, v_ctxt);

    for (int i = 0; i < context->getNSlots(); ++i)
    {
        if (v_ptxt.at(i) != 1)
            return false;
    }
    return true;
}

bool receiveAndDecrypt() {
    int type; //0: verify ctxt, 1: ballot
    if (SSL_read(ssl, &type, sizeof(int)) <= 0)
    {
        perror("SSL_read type");
        exit(1);
    }
    std::cout << "[INFO]: " << (type ? "Received Ballot, showing result ..." : "Received Verify Ciphertext. Decrypting ...") << std::endl;
    char buffer[MAX_LENGTH+1]{0};
    int data_read = 0;
    std::stringstream ctxt_stream;
    while (true)
    {
        memset(buffer, 0, MAX_LENGTH + 1);
        if ((data_read = SSL_read(ssl, buffer, MAX_LENGTH + 1)) <= 0)
        {
            perror("SSL_read ciph");
            return false;
        }
        ctxt_stream << buffer;
        if (data_read < MAX_LENGTH + 1)
            break;
    }
    helib::Ctxt ctxt = helib::Ctxt::readFromJSON(ctxt_stream, *public_key);
    helib::Ptxt<helib::BGV> ptxt(*context);
    secret_key->Decrypt(ptxt, ctxt);
    if (type) {
        // Convert from ASCII to a string
        int win{0};
        int cur{0};
        std::string string_result;
        for (long i{0}; i < ptxt.size(); ++i)
        {
            long num = static_cast<long>(ptxt[i]);
            if (num > cur)
            {
                win = i;
                cur = num;
            }
        }
        string_result = candidates[win];
        std::cout << "\n\n[INFO]: Winner is: " << string_result << "!" << std::endl;
        return false;
    } else {
        int v = 1;
        for (int i = 0; i < context->getNSlots(); ++i) {
            if (ptxt.at(i) != 1) {
                v = 0;
                break;
            }
        }
        std::cout << "[INFO]: Ciphertext " << (v ? "verified" : "not verified") << std::endl;
        if (SSL_write(ssl, &v, sizeof(v)) < 0)
        {
            perror("send v");
            exit(EXIT_FAILURE);
        }
    }
    return true;
}

int main(int argc, char *argv[])
{   
    if (argc > 1) {
        std::cerr << "Too many arguments." << std::endl;
        exit(EXIT_FAILURE);
    }
    candidates = get_candidates("../../candidate_dataset.csv");
    voters = get_voters("../../user_dataset.csv");

    initSSL(8081);
    initHelibContext(candidates.size(), voters.size());
    //TODO: Add more for bootstrappable key
    // helib::Context ctxt = helib::ContextBuilder<helib::BGV>()
    //                           .m(m)
    //                           .p(p)
    //                           .r(r)
    //                           .bits(bits)
    //                           .c(c)
    //                           .gens(gens)
    //                           .ords(ords)
    //                           .mvec(mvec)
    //                           .bootstrappable(true)
    //                           .skHwt(t)
    //                           .build();
    helib::Context ctxt = helib::ContextBuilder<helib::BGV>()
                                                        .m(m)
                                                        .p(p)
                                                        .r(r)
                                                        .bits(bits)
                                                        .c(c)
                                                        .build();
    context = &ctxt;
    /* SECRET KEY */
    helib::SecKey sk = helib::SecKey(*context);
    sk.GenSecKey();
    addSome1DMatrices(sk);
    // TODO: BELOW FOR Bootstrapping
    // addFrbMatrices(sk);
    // // Generate bootstrapping data
    // sk.genRecryptData();
    secret_key = &sk;

    /* PUBLIC KEY */
    public_key = new helib::PubKey(sk);

    std::cout << "\n***Security Level: " << context->securityLevel()
              << "\n*** Negligible for this example to improve performance time ***\n" << std::endl;

    std::cout << "[INFO]: HElib Initialization Completed" << std::endl;
    sendCandidates();
    sendContext();
    sendPubKey();
    encryptAndSendVoterInfo();
    std::cout << "[INFO]: All Information Exchange complete. Listening for Verifications ..." << std::endl;
    std::cout << "--------------------------------------------------------------------------" << std::endl;
    while(receiveAndDecrypt());

    BIO_free_all(certbio);
    BIO_free(outbio);
    SSL_free(ssl);
    close(s);
    X509_free(cert);
    SSL_CTX_free(ctx);
}