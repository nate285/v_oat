#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <string>
#include <sstream>

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

std::vector<std::string> candidates;

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
        fprintf(stderr, "ctx no work\n\n");
    }

    // Disabling SSLv2 will leaving v3 and TLSv1 for negotiation.
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2);

    // Create a new SSL session. This does not connect the socket.
    SSL *ssl = SSL_new(ctx);

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
    const char *accept = "CONNECTION ACCEPTED\n"; // for user authentication
    char receive[200];
    if (SSL_read(ssl, receive, 200) <= 0)
    {
        perror("SSL_read connection accepted");
        exit(EXIT_FAILURE);
    }
    if (strcmp(accept, receive) != 0)
    {
        fprintf(stdout, "Not Accepted");
        close(s);
    }
    fprintf(stdout, "%s", receive);

    /* Receive Candidates */
    fprintf(stdout, "Candidates\n");
    size_t cand_len;
    if (SSL_read(ssl, &cand_len, sizeof(size_t)) <= 0)
    {
        perror("SSL_read cand_len");
        exit(EXIT_FAILURE);
    }
    char cands[cand_len + 1] = "";
    if (SSL_read(ssl, cands, cand_len + 1) <= 0)
    {
        perror("SSL_read candidates");
        exit(EXIT_FAILURE);
    }

    char *token;
    token = strtok(cands, "&");
    do
    {
        std::string candid(token);
        candidates.emplace_back(candid);
    } while (token = strtok(NULL, "&"));
    // TODO: Print candidates function
    for (int i = 0; i < candidates.size(); ++i)
    {
        std::cout << i << ") " << candidates[i] << std::endl;
    }

    /* RECEIVE HELIB CONTEXT*/
    size_t len_context;
    if (SSL_read(ssl, &len_context, sizeof(size_t)) <= 0)
    {
        perror("SSL_read len context");
        exit(EXIT_FAILURE);
    }
    fprintf(stdout, "Received len: %ld\n", len_context);
    char *json_context = (char *)calloc((len_context + 1) * sizeof(char), 1);
    if (SSL_read(ssl, json_context, (len_context + 1) * 2) <= 0)
    {
        perror("SSL_read context");
        exit(EXIT_FAILURE);
    }
    // fprintf(stdout, "%s", json_context);
    std::stringstream context_stream;
    context_stream << json_context;
    std::cerr << "\n The stream on this side is \n"
              << json_context << "\n\n\n\n ";
    helib::Context context = helib::Context::readFrom(context_stream);
    free(json_context);

    std::cout << "HERE" <<std::endl;
    /* RECEIVE HELIB PUBKEY*/
    size_t len_pubkey;
    if (SSL_read(ssl, &len_pubkey, sizeof(size_t)) <= 0)
    {
        perror("SSL_read len pubkey");
        exit(EXIT_FAILURE);
    }
    fprintf(stderr, "making it to 170\n\n");
    fprintf(stdout, "Received len: %ld\n", len_pubkey);
    char *json_pubkey = (char *)calloc(len_pubkey + 1, 1);
    if (SSL_read(ssl, json_pubkey, len_pubkey + 1) <= 0)
    {
        perror("SSL_read ciph");
        exit(EXIT_FAILURE);
    }
    // fprintf(stdout, "%s", json_pubkey);
    std::stringstream pubkey_stream;
    pubkey_stream << json_pubkey;
    helib::PubKey pubkey = helib::PubKey::readFrom(pubkey_stream, context);
    free(json_pubkey);

    /* RECEIVE VOTE TEMPLATE */
    size_t len_template;
    if (SSL_read(ssl, &len_template, sizeof(size_t)) <= 0)
    {
        perror("SSL_read len ciph");
        exit(EXIT_FAILURE);
    }
    fprintf(stdout, "Received len: %ld\n", len_template);
    char *json_template = (char *)calloc(len_template + 1, 1);
    if (SSL_read(ssl, json_template, len_template + 1) <= 0)
    {
        perror("SSL_read ciph");
        exit(EXIT_FAILURE);
    }
    // fprintf(stdout, "%s", json_template);
    std::stringstream template_stream;
    template_stream << json_template;
    helib::Ctxt vote_template = helib::Ctxt::readFrom(template_stream, pubkey);
    free(json_template);

    int nslots = context.getNSlots();
    helib::Ptxt<helib::BGV> vote(context);
    vote.at(1) = 1;

    vote_template += vote;

    std::stringstream vote_stream;
    vote_template.writeToJSON(vote_stream);
    std::string vote_string = vote_stream.str() + '\0';
    const char *vote_cstr = vote_string.c_str();
    // size_t vote_length = strlen(vote_cstr);
    // if (SSL_write(ssl, &vote_length, sizeof(vote_length)) < 0)
    // {
    //     perror("send vote length");
    //     exit(EXIT_FAILURE);
    // }
    if (SSL_write(ssl, vote_cstr, strlen(vote_cstr)) < 0)
    {
        perror("send vote");
        exit(EXIT_FAILURE);
    }

    SSL_free(ssl);
    close(s);
    X509_free(cert);
    SSL_CTX_free(ctx);
}