#include <helib/helib.h>

#include <openssl/rsa.h>
#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

void RegisterVoters(std::string);

void *casting_vote(void*);
void sendCandidateInfo(SSL*);
int sendVoteTemplate(SSL*, helib::Ctxt &);
helib::Ctxt receiveVote(SSL*, int);
bool verifyVote(helib::Ctxt &, helib::Ctxt &);
int sendContext(SSL*);
int sendPubKey(SSL*);
void showResult();
bool verify(SSL*, const char*, int);
bool verifyCheckerPtxt(helib::Ptxt<helib::BGV>);