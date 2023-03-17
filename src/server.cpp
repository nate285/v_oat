#include <iostream>
#include <sstream>
#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>

#include <sys/socket.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <helib/helib.h>
#include <helib/EncryptedArray.h>
#include <helib/ArgMap.h>
#include <NTL/BasicThreadPool.h>

#include "Ballot.hpp"
#include "helpers.hpp"

using namespace std;

helib::Context* context;
helib::PubKey* public_key;
vector<string> candidates;
Ballot* ballot;

void *casting_vote(void *socket_ptr)
{
    int new_s = *((int *)socket_ptr);

    const char* accept = "CONNECTION ACCEPTED\n";
    if (send(new_s, accept, strlen(accept) + 1, 0) < 0) {
        perror("send accept");
        exit(EXIT_FAILURE);
    }
    sendCandidateInfo(new_s); //send candidate names

    helib::Ctxt* v_template;
    helib::Ctxt* received;
    while (true) {
        helib::Ptxt<helib::BGV> ptxt_vote_template(*context);
        //TODO: insert random numbers as OTP saltq
        //right now is just 0~size-1
        for (long i = 0; i < context->getNSlots(); ++i) {
            ptxt_vote_template.at(i) = i;
        }

        helib::Ctxt vote_template(*public_key);
        public_key->Encrypt(vote_template, ptxt_vote_template);

        int len = sendVoteTemplate(new_s, vote_template);

        helib::Ctxt received_vote(receiveVote(new_s, len));
        if (verifyVote(received_vote)) {
            v_template = &vote_template;
            received = &received_vote;
            break;
        }
        const char* accept = "Invalid Vote. Please try again.";
        if (send(new_s, accept, strlen(accept) + 1, 0) < 0) {
            perror("send accept");
            exit(EXIT_FAILURE);
        }
    }

    helib::Ctxt vote(*received);
    vote -= *v_template;// TODO: Recrypt if needed
    
    ballot->cast(0, vote); //TODO: replace 0 with voter id

    return NULL;
}

void sendCandidateInfo(int new_s) {
    for (auto const &candidate: candidates) {
        string cand_string = candidate + '\0';
        const char* cand = cand_string.c_str();
        cout << cand << endl;
        if (send(new_s, cand, strlen(cand), 0) < 0) {
            perror("send candidates");
            exit(EXIT_FAILURE);
        }
    }
    const char* done = "INFORMATION_DONE";
    if (send(new_s, done, strlen(done)+1, 0) < 0) {
        perror("send candidates");
        exit(EXIT_FAILURE);
    }
}

int sendVoteTemplate(int new_s, helib::Ctxt& vote_template) {
    stringstream vt_stream;
    vote_template.writeToJSON(vt_stream);
    string vt_string = vt_stream.str() + '\0';
    const char* vt_cstr = vt_string.c_str();
    size_t length = strlen(vt_cstr);
    if (send(new_s, &length, sizeof(length), 0) < 0) {
        perror("send vote template length");
        exit(EXIT_FAILURE);
    }
    int len;
    if ((len = send(new_s, vt_cstr, strlen(vt_cstr), 0)) < 0) {
        perror("send vote template");
        exit(EXIT_FAILURE);
    }
    return len;
}

helib::Ctxt receiveVote(int new_s, int length) {
    char rec_buf[length+1];
    if (recv(new_s, rec_buf, length+1, 0) < 0) {
        perror("receive vote");
        exit(EXIT_FAILURE);
    }
    // string rv = rec_buf;
    stringstream rv_stream;
    rv_stream << rec_buf;
    helib::Ctxt deserialized_vote = helib::Ctxt::readFrom(rv_stream, *public_key);
    return deserialized_vote;
}

bool verifyVote(helib::Ctxt& received_vote) {
    return true;
}

int main(int argc, char *argv[])
{   
    /* -----------------------------------------------------------------------*/
    /* INITIALIZATION */
    /* -----------------------------------------------------------------------*/
    cout << "Registering Candidates" << endl;
    cout << "How many canidates would you like to register?" << endl;
    int num_candidates;
    cin >> num_candidates; // TODO: buffer overflow?
    for (int i = 0; i < num_candidates; i++)
    {
        char *candidate_name = (char *)malloc(sizeof(char) * 100);
        cout << "Registering candidate " << i + 1 << endl;
        cout << "Enter name " << endl;
        cin >> candidate_name; // TODO: buffer overflow?
        candidates.emplace_back(candidate_name);
        free(candidate_name);
    }

    /* HELIB INITIALIZATION */
    unsigned long p = 131;
    unsigned long m = 130;
    unsigned long r = 1;
    unsigned long bits = 1000;
    unsigned long c = 2;

    cout << "---Initialising HE Environment ... ";
    
    /* CONTEXT */
    cout << "\nInitializing the Context ... ";
    context = new helib::Context(helib::ContextBuilder<helib::BGV>()
                                 .m(m)
                                 .p(p)
                                 .r(r)
                                 .bits(bits)
                                 .c(c)
                                 .build());

    /* SECRET KEY */
    cout << "\nCreating Secret Key ...";
    // Create a secret key associated with the context
    helib::SecKey secret_key = helib::SecKey(*context);
    // Generate the secret key
    secret_key.GenSecKey();
    // Compute key-switching matrices that we need
    helib::addSome1DMatrices(secret_key);

    /* PUBLIC KEY */
    cout << "\nCreating Public Key ...";
    public_key = new helib::PubKey(secret_key);
    // Get the EncryptedArray of the context
    const helib::EncryptedArray &ea = context->getEA();

    // Print the security level
    // Note: This will be negligible to improve performance time.
    cout << "\n***Security Level: " << context->securityLevel()
         << " *** Negligible for this example ***" << endl;

    // Get the number of slot (phi(m))
    long nslots = ea.size();
    cout << "\nNumber of slots: " << nslots << endl;

    cout << "\nInitialization Completed" << endl;
    cout << "--------------------------" << endl;

    helib::Ptxt<helib::BGV> ptxt_ballot(*context);
    /* CREATE BALLOT */
    ballot = new Ballot{candidates, ptxt_ballot, *public_key};

    ballot->showCandidateInfo();

    /* -----------------------------------------------------------------------*/
    /* OPENING SERVER */
    /* -----------------------------------------------------------------------*/
    int sock;
    int port = 8080; // TODO: change port
    if ((sock = socket(PF_INET, SOCK_STREAM, 0)) < 0)
    {
        perror("simplex-talk: socket");
        exit(1);
    }
    /* Config the server address */
    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = inet_addr("127.0.0.1"); // TODO: change inet addr
    sin.sin_port = htons(port);
    // Set all bits of the padding field to 0
    memset(sin.sin_zero, '\0', sizeof(sin.sin_zero));

    /* Bind the socket to the address */
    if ((bind(sock, (struct sockaddr *)&sin, sizeof(sin))) < 0)
    {
        perror("simplex-talk: bind");
        exit(1);
    }

    // connections can be pending if many concurrent client requests
    listen(sock, 10); // TODO: change concurrent max

    int new_s;
    socklen_t len = sizeof(sin);

    int vote_count = 0;

    while (vote_count++ < 5) //done when we reach maximum vote count or when time limit reaches?
    {
        if ((new_s = accept(sock, (struct sockaddr *)&sin, &len)) < 0)
        {
          perror("simplex-talk:accepct");
          exit(1);
        }

        pthread_t new_thread;
        pthread_create(&new_thread, NULL, casting_vote, &new_s);
    }
    //close ballot
    ballot->close();
    //display results

// void Ballot::showResult()
// {
//     if (state != Ballot_CLOSED)
//     {
//         std::cerr << "Ballot not yet closed" << std::endl;
//         return;
//     }
//     std::cout << "Extracting and Decrypting Result" << std::endl;
//     helib::Ptxt<helib::BGV> plaintext_result(context);
//     seckey.Decrypt(plaintext_result, *b);

//     // Convert from ASCII to a string
//     int win{0};
//     int cur{0};
//     std::string string_result;
//     for (long i{0}; i < plaintext_result.size(); ++i)
//     {
//         long num = static_cast<long>(plaintext_result[i]);
//         if (num > cur)
//         {
//             win = i;
//             cur = num;
//         }
//     }
//     string_result = candidates[win];
//     std::cout << "\nWinner is: " << string_result << std::endl;
// }
}