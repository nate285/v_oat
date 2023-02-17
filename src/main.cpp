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

#include "platform.hpp"
#include "vote.hpp"
#include "ballot.hpp"

int brkk = 0;
int s;
ballot *bal;
helib::Ctxt *dumdum;
std::vector<vote *> voters;
helib::Context *ctxx;
helib::PubKey *pkey;

void sigStpHandler(int signum)
{
  brkk = 1;
  close(s);
}

ballot *candidateRegistration(helib::Ctxt dum)
{
  std::cout << "Registering Candidates" << std::endl;
  std::cout << "How many canidates would you like to register?" << std::endl;
  int r;
  std::cin >> r;
  ballot *bal = new ballot{r, dum};
  for (int i = 0; i < r; i++)
  {
    char *str = (char *)malloc(sizeof(char) * 30);
    std::cout << "Registering candidate " << i + 1 << std::endl;
    std::cout << "Enter name " << std::endl;
    std::cin >> str;
    bal->registerCandidate(str);
  }

  char *info = bal->showCandidateInfo();
  std::cout << info << std::endl;
  free(info);
  bal->close();
  return bal;
}

void *casting_vote(void *socket_ptr)
{
  int new_s = *((int *)socket_ptr);

  char buf[200];

  sprintf(buf, "Enter ID");
  int len = strlen(buf) + 1;

  send(new_s, buf, len, 0);

  char recBuf[200];
  char notValid[100];
  sprintf(notValid, "Not a valid candidate, please enter a vote \n");

  len = recv(new_s, recBuf, sizeof(recBuf), 0);

  int id = atoi(recBuf);
  std::cout << "ID is " << id << std::endl;
  int vote_val;
  char *candidateBuf;
  sprintf(buf, "Enter who you are voting for\nEnter -1 to see options");
  len = strlen(buf) + 1;

  send(new_s, buf, len, 0);
  while (1)
  {
    vote_val = -1;
    memset(recBuf, 0, sizeof(recBuf));

    len = recv(new_s, recBuf, sizeof(recBuf), 0);

    if (recBuf[0] == '\n')
    {

      send(new_s, "Enter a vote", 12, 0);
      continue;
    }
    vote_val = atoi(recBuf);
    std::cout << "The vote_val is " << vote_val << "\n";
    int num_candidates = bal->getNumberCanidates();
    if (vote_val > num_candidates - 1 || vote_val < -1)
    {
      len = strlen(notValid) + 1;
      send(new_s, notValid, len, 0);
      continue;
    }
    else if (vote_val != -1)
    {
      break;
    }

    candidateBuf = bal->showCandidateInfo();

    strcat(candidateBuf, buf);
    len = strlen(candidateBuf) + 1;
    send(new_s, candidateBuf, len, 0);

    free(candidateBuf);
  }
  close(new_s);

  std::cout << "They voted for " << vote_val << std::endl;

  vote *v = new vote(id, id + 1, *dumdum);

  voters.push_back(v);

  bal->registerVoter(v);

  v->cast(ctxx, pkey, vote_val);

  std::cout << "CASTING VOTE" << std::endl;

  bal->cast(v);
  return NULL;
}

void handleVoting()
{
  int port = 8080;
  if ((s = socket(PF_INET, SOCK_STREAM, 0)) < 0)
  {
    perror("simplex-talk: socket");
    exit(1);
  }
  /* Config the server address */
  struct sockaddr_in sin;
  sin.sin_family = AF_INET;
  sin.sin_addr.s_addr = inet_addr("127.0.0.1");
  sin.sin_port = htons(port);
  // Set all bits of the padding field to 0
  memset(sin.sin_zero, '\0', sizeof(sin.sin_zero));

  /* Bind the socket to the address */
  if ((bind(s, (struct sockaddr *)&sin, sizeof(sin))) < 0)
  {
    perror("simplex-talk: bind");
    exit(1);
  }

  // connections can be pending if many concurrent client requests
  listen(s, 10);

  int new_s;
  socklen_t len = sizeof(sin);

  char buf[20];

  while (1)
  {
    if ((new_s = accept(s, (struct sockaddr *)&sin, &len)) < 0)
    {
      //   perror("simplex-talk:accepct");
      //   exit(1);
    }
    if (brkk == 1)
    {
      close(s);
      break;
    }

    pthread_t new_thread;
    int *socket_ptr = (int *)malloc(sizeof(int));
    *socket_ptr = new_s;
    pthread_create(&new_thread, NULL, casting_vote, socket_ptr);
  }
}

int main(int argc, char *argv[])
{

  signal(SIGTSTP, sigStpHandler);
  unsigned long p = 131;
  unsigned long m = 130;
  unsigned long r = 1;
  unsigned long bits = 1000;
  unsigned long c = 2;
  unsigned long nthreads = 1;
  bool debug = false;

  helib::ArgMap amap;
  amap.arg("m", m, "Cyclotomic polynomial ring");
  amap.arg("p", p, "Plaintext prime modulus");
  amap.arg("r", r, "Hensel lifting");
  amap.arg("bits", bits, "# of bits in the modulus chain");
  amap.arg("c", c, "# fo columns of Key-Switching matrix");
  amap.arg("nthreads", nthreads, "Size of NTL thread pool");
  amap.toggle().arg("-debug", debug, "Toggle debug output", "");
  amap.parse(argc, argv);

  // set NTL Thread pool size
  if (nthreads > 1)
    NTL::SetNumThreads(nthreads);

  std::cout << "---Initialising HE Environment ... ";
  // Initialize context
  // This object will hold information about the algebra used for this scheme.
  std::cout << "\nInitializing the Context ... ";
  HELIB_NTIMER_START(timer_Context);
  helib::Context context = helib::ContextBuilder<helib::BGV>()
                               .m(m)
                               .p(p)
                               .r(r)
                               .bits(bits)
                               .c(c)
                               .build();
  HELIB_NTIMER_STOP(timer_Context);

  ctxx = &context;

  // Secret key management
  std::cout << "\nCreating Secret Key ...";
  HELIB_NTIMER_START(timer_SecKey);
  // Create a secret key associated with the context
  helib::SecKey secret_key = helib::SecKey(context);
  // Generate the secret key
  secret_key.GenSecKey();
  HELIB_NTIMER_STOP(timer_SecKey);

  // Compute key-switching matrices that we need
  HELIB_NTIMER_START(timer_SKM);
  helib::addSome1DMatrices(secret_key);
  HELIB_NTIMER_STOP(timer_SKM);

  // Public key management
  // Set the secret key (upcast: FHESecKey is a subclass of FHEPubKey)
  std::cout << "\nCreating Public Key ...";
  HELIB_NTIMER_START(timer_PubKey);
  helib::PubKey &public_key = secret_key;
  pkey = &public_key;
  HELIB_NTIMER_STOP(timer_PubKey);

  // Get the EncryptedArray of the context
  const helib::EncryptedArray &ea = context.getEA();

  // Print the context
  std::cout << std::endl;
  if (debug)
    context.printout();

  // Print the security level
  // Note: This will be negligible to improve performance time.
  std::cout << "\n***Security Level: " << context.securityLevel()
            << " *** Negligible for this example ***" << std::endl;

  // Get the number of slot (phi(m))
  long nslots = ea.size();
  std::cout << "\nNumber of slots: " << nslots << std::endl;

  // Print DB Creation Timers
  if (debug)
  {
    helib::printNamedTimer(std::cout << std::endl, "timer_Context");
    helib::printNamedTimer(std::cout, "timer_Chain");
    helib::printNamedTimer(std::cout, "timer_SecKey");
    helib::printNamedTimer(std::cout, "timer_SKM");
    helib::printNamedTimer(std::cout, "timer_PubKey");
  }

  std::cout << "\nInitialization Completed" << std::endl;
  std::cout << "--------------------------" << std::endl;

  helib::Ptxt<helib::BGV> dummy(context);
  helib::Ctxt dummyE(public_key);
  public_key.Encrypt(dummyE, dummy);

  dumdum = &dummyE;

  bal = candidateRegistration(dummyE);
  bal->initBallot(&context, &public_key);

  std::cout << "Registering Voters" << std::endl;

  handleVoting();

  bal->done();
  std::cout << "Votes Casted" << std::endl;
  std::cout << "--------------------------" << std::endl;
  std::cout << "Extracting Result" << std::endl;
  helib::Ctxt res = bal->showResult();

  HELIB_NTIMER_START(timer_DecryptResult);
  std::cout << "Decrypting Result" << std::endl;
  helib::Ptxt<helib::BGV> plaintext_result(context);
  secret_key.Decrypt(plaintext_result, res);
  HELIB_NTIMER_STOP(timer_DecryptResult);

  // Convert from ASCII to a string
  int win{0};
  int cur{0};
  std::string string_result;
  for (long i{0}; i < plaintext_result.size(); ++i)
  {
    long num = static_cast<long>(plaintext_result[i]);
    if (num > cur)
    {
      win = i;
      cur = num;
    }
  }
  string_result = bal->getCandidate(win);
  if (debug)
  {
    helib::printNamedTimer(std::cout, "timer_DecryptResult");
    std::cout << std::endl;
  }

  std::cout << "\nWinner is: " << string_result << std::endl;

  return 0;
}
