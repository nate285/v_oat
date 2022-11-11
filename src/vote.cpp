#include "vote.hpp"

vote::vote(int id, int person, helib::Ctxt dummy) : id{id}, voter{person}, v{dummy} {}

void vote::cast(helib::Context *context, helib::PubKey *public_key, int to) {
    helib::Ptxt<helib::BGV> p_v(*context);
    p_v.at(to) = 1;

    helib::Ctxt enc_v(*public_key);
    public_key->Encrypt(enc_v, p_v);
    v = enc_v;
    ready = true;
}

int vote::getId() {
    return id;
}

int vote::getVoter() {
    return voter;
}

helib::Ctxt vote::getVote() {
    return v;
}

bool vote::voted() {
    return ready;
}