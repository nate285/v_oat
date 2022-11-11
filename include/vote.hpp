#ifndef VOTE_HPP
#define VOTE_HPP

#include <helib/helib.h>

class vote {
    private:
    helib::Ctxt v;
    int id;
    int voter;
    bool ready = false;

    public:
    vote() = delete;
    vote(int, int, helib::Ctxt);
    vote(const vote &) = delete;
    vote(vote &&) = delete;
    vote &operator=(vote) = delete;

    void cast(helib::Context*, helib::PubKey*, int);
    int getId();
    int getVoter();
    helib::Ctxt getVote();
    bool voted();
};


#endif