#include "Ballot.hpp"
#include <sstream>


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

void Ballot::showResult(helib::Context* context, SSL* ssl)
{
    if (state != Ballot_CLOSED)
    {
        std::cerr << "Ballot not yet closed" << std::endl;
        return;
    }
    // std::cout << "Extracting and Decrypting Result" << std::endl;
    // helib::Ptxt<helib::BGV> plaintext_result(*context);
    // seckey.Decrypt(plaintext_result, b);

    // // Convert from ASCII to a string
    // int win{0};
    // int cur{0};
    // std::string string_result;
    // for (long i{0}; i < plaintext_result.size(); ++i)
    // {
    //     long num = static_cast<long>(plaintext_result[i]);
    //     if (num > cur)
    //     {
    //         win = i;
    //         cur = num;
    //     }
    // }
    // string_result = candidates[win];
    // std::cout << "\nWinner is: " << string_result << std::endl;
    std::stringstream ballot_stream;
    b.writeToJSON(ballot_stream);
    std::string ballot_string = ballot_stream.str();
    const char *ballot_cstr = ballot_string.c_str();
    size_t length = ballot_string.length();
    int wrote = 0;
    char vt_buf[16001]{0};
    int type = 1;
    if (SSL_write(ssl, &type, sizeof(int)) < 0)
    {
        perror("send type");
        exit(EXIT_FAILURE);
    }
    while (wrote < length)
    {
        strncpy(vt_buf, &ballot_cstr[wrote], 16000);
        if (SSL_write(ssl, vt_buf, strlen(vt_buf) + 1) < 0)
        {
            perror("send ballot");
            exit(EXIT_FAILURE);
        }
        // cout << strlen(vt_buf) << endl;
        wrote += 16000;
    }
}