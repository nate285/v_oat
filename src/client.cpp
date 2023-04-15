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

std::vector<std::string> candidates;

void printCandidates() {
    // Print Candidates
    std::cout << "Candidate List" << std::endl;
    for (int i = 0; i < candidates.size(); ++i)
    {
        std::cout << i + 1 << ") " << candidates[i] << std::endl;
    }
    std::cout << std::endl;
}

int main(int argc, char *argv[])
{
    // Load algorithms and strings needed by OpenSSL
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
    SSL_load_error_strings();

    // Create the Input/Output BIOs
    BIO *certbio = BIO_new(BIO_s_file());
    BIO *outbio = BIO_new_fp(stdout, BIO_NOCLOSE);
    // Initialize OpenSSL.
    SSL_library_init();

    // The SSLv23_client_method function indicates that the application is a
    // client and supports Transport Layer Security version 1.0 (TLSv1.0),
    // Transport Layer Security version 1.1 (TLSv1.1), and Transport Layer
    // Security version 1.2 (TLSv1.2).
    const SSL_METHOD *method = SSLv23_client_method();

    // Create an SSL context.
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx)
    {
        fprintf(stderr, "ctx not working\n\n");
    }

    // Disabling SSLv2 will leaving v3 and TLSv1 for negotiation.
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2);

    // Create a new SSL session. This does not connect the socket.
    SSL *ssl = SSL_new(ctx);
    if (argc < 2)
    {
        fprintf(stderr, "Please enter with correct arguments");
    }

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
    if (SSL_set_fd(ssl, s) == 0)
    {
        perror("SSL_set_fd");
        exit(EXIT_FAILURE);
    }

    int err = SSL_connect(ssl);

    X509 *cert = SSL_get_peer_certificate(ssl);

    // Get certificate name
    // X509_NAME *certname = X509_get_subject_name(cert);

    // Print the TLS Certificate's Subject
    // X509_NAME_print_ex(outbio, certname, 0, 0);

    /* Check if connection is accepted */
    const char accept[21] = "CONNECTION ACCEPTED\n"; // for user authentication
    char accept_receive[21];
    if (SSL_read(ssl, accept_receive, 21) <= 0)
    {
        perror("SSL_read connection accepted");
        exit(EXIT_FAILURE);
    }
    accept_receive[20] = '\0';
    if (strncmp(accept, accept_receive, 21) != 0)
    {
        fprintf(stdout, "Not Accepted");
        close(s);
    }
    std::cout << "[INFO]: Voter Client" << std::endl;
    std::string username;
    std::string password;
    std::cout << "Please input username: " << std::endl;
    std::cin.width(25);
    std::cin >> username;
    std::cout << "Please input password: " << std::endl;
    std::cin.width(25);
    std::cin >> password;

    std::cout << "Registered Candidates:" << std::endl;

    size_t cand_len;
    if (SSL_read(ssl, &cand_len, sizeof(size_t)) <= 0)
    {
        perror("SSL_read cand_len");
        exit(EXIT_FAILURE);
    }
    char *cands = (char *)malloc(sizeof(char) * (cand_len + 2));
    if (SSL_read(ssl, cands, cand_len + 1) <= 0)
    {
        perror("SSL_read candidates");
        exit(EXIT_FAILURE);
    }
    cands[cand_len + 1] = '\0';

    char *token;
    token = strsep(&cands, "&");
    do
    {
        std::string candid(token);
        candidates.emplace_back(candid);
    } while (token = strsep(&cands, "&"));

    printCandidates();

    // send candidate success
    int receive = 1;
    if (SSL_write(ssl, &receive, sizeof(int)) < 0)
    {
        perror("send success");
        exit(EXIT_FAILURE);
    }

    /* RECEIVE HELIB CONTEXT*/
    char buffer[MAX_LENGTH + 1]{0};
    if (SSL_read(ssl, buffer, MAX_LENGTH + 1) <= 0)
    {
        perror("SSL_read context");
        exit(EXIT_FAILURE);
    }
    std::stringstream context_stream{buffer};
    helib::Context context = helib::Context::readFromJSON(context_stream);

    // send context success
    if (SSL_write(ssl, &receive, sizeof(int)) < 0)
    {
        perror("send success");
        exit(EXIT_FAILURE);
    }

    int data_read = 0;
    std::stringstream pubkey_stream;
    // int counter = 1;
    while (true)
    {
        // std::cout << counter++ << ": " << std::endl;
        memset(buffer, 0, MAX_LENGTH + 1);
        if ((data_read = SSL_read(ssl, buffer, MAX_LENGTH + 1)) <= 0)
        {
            perror("SSL_read pubkey");
            exit(EXIT_FAILURE);
        }
        pubkey_stream << buffer;
        // std::cout << data_read << std::endl;
        if (data_read < MAX_LENGTH + 1)
            break;
    }
    helib::PubKey pubkey = helib::PubKey::readFromJSON(pubkey_stream, context);
    // send pubkey success
    if (SSL_write(ssl, &receive, sizeof(int)) < 0)
    {
        perror("send success");
        exit(EXIT_FAILURE);
    }

    /* USER VERIFICATION */
    int verif_count = 5;
    while (verif_count > 0) {
        if (verif_count != 5) {
            std::cout << "\nEnter Username Again: " << std::endl;
            std::cin.width(25);
            std::cin >> username;
            std::cout << "Enter Password Again: " << std::endl;
            std::cin.width(25);
            std::cin >> password;
        }
        helib::Ptxt<helib::BGV> username_ptxt(context);
        for (long i = 0; i < username.size(); ++i)
            username_ptxt.at(i) = username[i];
        helib::Ctxt encrypted_username(pubkey);
        pubkey.Encrypt(encrypted_username, username_ptxt);

        std::stringstream ctxt_stream;
        encrypted_username.writeToJSON(ctxt_stream);
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
        int receive;
        if (SSL_read(ssl, &receive, sizeof(int)) <= 0)
        {
            perror("SSL_read verify");
            exit(EXIT_FAILURE);
        }
        if (!receive) {
            std::cerr << "[ERROR]: Invalid Credentials. Number of Trials left: " << --verif_count << std::endl;
            continue;
        }

        helib::Ptxt<helib::BGV> password_ptxt(context);
        for (long i = 0; i < password.size(); ++i)
            password_ptxt.at(i) = password[i];
        helib::Ctxt encrypted_password(pubkey);
        pubkey.Encrypt(encrypted_password, password_ptxt);

        ctxt_stream.str(std::string());
        encrypted_password.writeToJSON(ctxt_stream);
        ctxt_string = ctxt_stream.str();
        const char *pass_cstr = ctxt_string.c_str();
        length = ctxt_string.length();
        wrote = 0;
        while (wrote < length)
        {
            strncpy(ctxt_buf, &pass_cstr[wrote], MAX_LENGTH);
            if (SSL_write(ssl, ctxt_buf, strlen(ctxt_buf) + 1) < 0)
            {
                perror("send ctxt");
                exit(EXIT_FAILURE);
            }
            wrote += MAX_LENGTH;
        }
        if (SSL_read(ssl, &receive, sizeof(int)) <= 0)
        {
            perror("SSL_read verify");
            exit(EXIT_FAILURE);
        }
        if (!receive) {
            std::cerr << "[ERROR]: Invalid Credentials. Number of Trials left: " << --verif_count << std::endl;
            continue;
        }
        break;
    }
    if (verif_count == 0) {
        std::cout << "[ERROR]: Out of trials. Please connect again." << std::endl;
        SSL_free(ssl);
        close(s);
        return 0;
    }
    std::cout << "Authenticatd!" << std::endl;

    int vote_number;
    while (true)
    {
        std::cout << "\n\nWho would you like to vote for? (Input -1 to show list of clients)" << std::endl;
        while (true)
        {
            std::cin >> vote_number; // TODO: buffer overflow?
            if (vote_number == -1) {
                printCandidates();
                continue;
            }
            if (vote_number > 0 && vote_number <= candidates.size())
                break;
            std::cout << "Enter valid vote number in range: (1, " << candidates.size() << ") or -1" << std::endl;
        }
        std::cout << "You voted for candidate " << vote_number << ": " << candidates[--vote_number] << std::endl;

    
        std::stringstream template_stream;
        while (true)
        {
            memset(buffer, 0, MAX_LENGTH + 1);
            if ((data_read = SSL_read(ssl, buffer, MAX_LENGTH + 1)) <= 0)
            {
                perror("SSL_read ciph");
                exit(EXIT_FAILURE);
            }
            template_stream << buffer;
            if (data_read < MAX_LENGTH + 1)
                break;
        }
        helib::Ctxt vote_template = helib::Ctxt::readFromJSON(template_stream, pubkey);

        int nslots = context.getNSlots();
        helib::Ptxt<helib::BGV> vote(context);
        vote.at(vote_number) = 1;
        helib::Ctxt vote_cipher(pubkey);
        pubkey.Encrypt(vote_cipher, vote);

        vote_template += vote_cipher;

        std::stringstream vote_stream;
        vote_template.writeToJSON(vote_stream);
        std::string vote_string = vote_stream.str();
        const char *vote_cstr = vote_string.c_str();
        size_t vote_length = strlen(vote_cstr);
        int wrote = 0;
        char vote_buf[MAX_LENGTH + 1]{0};
        std::cout << "[INFO]: Sending Vote to V-Oat ..." << std::endl;
        while (wrote < vote_length)
        {
            strncpy(vote_buf, &vote_cstr[wrote], MAX_LENGTH);
            if (SSL_write(ssl, vote_buf, strlen(vote_buf) + 1) < 0)
            {
                perror("send vote");
                exit(EXIT_FAILURE);
            }
            wrote += MAX_LENGTH;
        }

        const char vote_success[25] = "Vote Valid and accepted\n"; // for user authentication
        char vote_success_receive[25];
        if (SSL_read(ssl, vote_success_receive, 25) <= 0)
        {
            perror("SSL_read vote accepted");
            exit(EXIT_FAILURE);
        }
        vote_success_receive[24] = '\0';
        if (strncmp(vote_success, vote_success_receive, 25) == 0)
            break;
        std::cout << "[ERROR]: From V-Oat. Vote Verification Failed. Try Again.\n"
                  << "If this issue Continues, please try reconnecting." << std::endl;
    }
    std::cout << "[INFO]: From V-Oat. Vote Casted!" << std::endl;

    BIO_free_all(certbio);
    BIO_free(outbio);
    SSL_free(ssl);
    close(s);
    X509_free(cert);
    SSL_CTX_free(ctx);
}