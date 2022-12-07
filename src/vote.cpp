#include "vote.hpp"

vote::vote(int id, int person, helib::Ctxt dummy) : id{id}, voter{person}, v{dummy} {}

vote::vote(const vote &vv) : id{vv.id}, voter{vv.voter}, v{vv.v}
{

    v = vv.v;
    voter = vv.voter;
    id = vv.id;
    ready = vv.ready;
}

void vote::cast(helib::Context *context, helib::PubKey *public_key, int to)
{
    helib::Ptxt<helib::BGV> p_v(*context);
    p_v.at(to) = 1;

    helib::Ctxt enc_v(*public_key);
    public_key->Encrypt(enc_v, p_v);
    v = enc_v;
    ready = true;
}

int vote::getId()
{
    return id;
}

int vote::getVoter()
{
    return voter;
}

helib::Ctxt vote::getVote()
{
    return v;
}

bool vote::voted()
{
    return ready;
}

// adding swap and copy operators

vote &vote::operator=(const vote &vo)
{
    v = vo.v;
    voter = vo.voter;
    id = vo.id;
    ready = vo.ready;
    return *this;
}

void swap(vote &i, vote &j) noexcept
{
    std::swap(i.v, j.v);
    std::swap(i.id, j.id);
    std::swap(i.voter, j.voter);
    std::swap(i.ready, j.ready);
}

vote &vote::operator=(vote v)
{
    swap(*this, v);
    return *this;
}