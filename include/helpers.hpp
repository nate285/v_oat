#include <helib/helib.h>

#include <openssl/rsa.h>
#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

void *casting_vote(void *);
void sendCandidateInfo(SSL *ssl);
int sendVoteTemplate(SSL *ssl, helib::Ctxt &);
helib::Ctxt receiveVote(SSL *ssl, int);
bool verifyVote(helib::Ctxt &);
void showResult();