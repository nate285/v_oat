#include "Ballot.hpp"

Ballot::Ballot(std::vector<std::string> candidates, 
               helib::Ptxt<helib::BGV> ptxt_ballot,
               helib::PubKey& pubkey) : 
    candidates(candidates),
    num_candidates(candidates.size()),
    b(pubkey),
    state(Ballot_INIT) 
    {
        pubkey.Encrypt(b, ptxt_ballot);
    }


void Ballot::showCandidateInfo()
{
    std::cout << "Here are the registered candidates:\n";
    for (int i{0}; i < candidates.size(); ++i)
    {
        std::cout << i << ") " << candidates[i] << "\n";
    }
    std::cout << std::endl;
}

int Ballot::getNumberCanidates()
{
    return num_candidates;
}

int Ballot::registerVoter()
{
    reg_voters.insert(0);// TODO: voter auth
    return 0;
}

int Ballot::cast(int voter, helib::Ctxt &vote)
{
    // TODO: voter auth
    b += vote;
    // TODO: recrypt if not valid
    return 0;
}

void Ballot::close()
{
    state = Ballot_CLOSED;
}