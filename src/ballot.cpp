#include "ballot.hpp"
using namespace std;

ballot::ballot(int max, helib::Ctxt dummy) : max_votes{max}, b{dummy} {}

void ballot::showCandidateInfo()
{
    cout << "Here are the registered candidates: " << endl;
    for (int i{0}; i < candidates.size(); ++i)
        cout << i + 1 << ". " << candidates[i] << "\n";
    cout << endl;
}

void ballot::initBallot(helib::Context *context, helib::PubKey *public_key)
{
    helib::Ptxt<helib::BGV> p_b(*context);

    helib::Ctxt enc_b(*public_key);
    public_key->Encrypt(enc_b, p_b);
    b = enc_b;
}

int ballot::registerCandidate(string name)
{
    if (closed)
    {
        cerr << "ballot closed not accepting any more registers" << endl;
        return -1;
    }
    candidates.emplace_back(name);
    return 0;
}

int ballot::registerVoter(vote *v)
{
    if (reg_votes.count(v->getId()))
    {
        cerr << "vote already registered" << endl;
        return -1;
    }
    if (reg_voters.count(v->getVoter()))
    {
        cerr << "voter already registered" << endl;
        return -1;
    }
    reg_votes.insert(v->getId());
    reg_voters.insert(v->getVoter());
    return 0;
}

int ballot::cast(vote *v)
{
    if (!v->voted())
    {
        cerr << "vote not yet casted" << endl;
        return -1;
    }
    if (!reg_votes.count(v->getId()))
    {
        cerr << "vote not registered" << endl;
        return -1;
    }
    if (!reg_voters.count(v->getVoter()))
    {
        cerr << "voter not registered" << endl;
        return -1;
    }

    reg_votes.erase(reg_votes.find(v->getId()));
    reg_voters.erase(reg_voters.find(v->getVoter()));

    b += v->getVote();
}

helib::Ctxt ballot::showResult()
{
    if (!ready)
    {
        cerr << "ballot not ready" << endl;
        return b;
    }
    return b;
}

void ballot::close()
{
    closed = true;
}

void ballot::done()
{
    ready = true;
}

string ballot::getCandidate(int pos)
{
    return candidates[pos];
}