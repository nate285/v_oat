#include <helib/helib.h>

void *casting_vote(void *);
void sendCandidateInfo(int);
int sendVoteTemplate(int, helib::Ctxt&);
helib::Ctxt receiveVote(int, int);
bool verifyVote(helib::Ctxt&);