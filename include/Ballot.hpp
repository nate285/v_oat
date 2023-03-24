#ifndef Ballot_HPP
#define Ballot_HPP
#include <helib/helib.h>

#include <memory>
#include <iostream>
#include <unordered_set>
#include <optional>

#define Ballot_INIT 0
#define Ballot_OPEN 1
#define Ballot_CLOSED 2
#define Ballot_ERROR 3

class Ballot
{
private:
    std::vector<std::string> candidates;
    int num_candidates;
    helib::Ctxt b; //actual Ballot
    std::unordered_set<int> reg_voters; // for voter auth?
    int state; // state of Ballot (defined by macros)

public:
    // constructors & destructors
    Ballot(std::vector<std::string>, 
           helib::Ptxt<helib::BGV>, 
           helib::PubKey&); // constructor of Ballot object
    ~Ballot() = default; // default destructor

    Ballot() = delete; // delete default constructor
    Ballot(const Ballot &) = delete; // delete copy constructor
    Ballot(Ballot &&) = delete; // delete move constructor
    Ballot &operator=(Ballot) = delete; // delete copy assignment
    Ballot &operator=(const Ballot &) = delete; // delete move assignment

    void showCandidateInfo();
    int getNumberCanidates();
    int registerVoter(); // TODO: for voter auth?
    int cast(int, helib::Ctxt&); // cast a vote
    void close(); // close the Ballot

    // helib::Ctxt create_vote_template();
    // helib::PubKey getPubKey();

    void showResult(helib::Context*, helib::SecKey); // display results
};

#endif