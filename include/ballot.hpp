#ifndef BALLOT_HPP
#define BALLOT_HPP
#include <helib/helib.h>
#include "vote.hpp"

#include <memory>
#include <iostream>
#include <unordered_set>
#include <optional>


class ballot {
    private:
    std::vector<std::string> candidates;
    helib::Ctxt b;
    int max_votes;
    std::unordered_set<int> reg_voters;
    std::unordered_set<int> reg_votes;
    bool ready = false;
    bool closed = false;

    public:
    ballot() = delete;
    ballot(int, helib::Ctxt);
    ballot(const ballot &) = delete;
    ballot(ballot &&) = delete;
    ballot &operator=(ballot) = delete;

    void showCandidateInfo();
    void initBallot(helib::Context*, helib::PubKey*);
    int registerCandidate(std::string);
    int registerVoter(vote*);
    int cast(vote*);
    void close();
    void done();
    std::string getCandidate(int);

    helib::Ctxt showResult();
    
    // friend std::ostream &operator<<(std::ostream, const ballot);

};

#endif