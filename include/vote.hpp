#ifndef VOTE_HPP
#define VOTE_HPP

#include <helib/helib.h>

class vote
{
private:
    helib::Ctxt v;
    int id;
    int voter;
    bool ready = false;

public:
    vote();
    vote(int, int, helib::Ctxt);
    vote(const vote &);
    vote(vote &&);
    vote &operator=(vote);
    vote &operator=(const vote &);

    void cast(helib::Context *, helib::PubKey *, int);
    int getId();
    int getVoter();
    helib::Ctxt getVote();
    bool voted();

    friend void swap(vote &, vote &) noexcept;
};

#endif