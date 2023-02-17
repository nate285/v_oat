#include <iostream>
#include <cstdlib>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <helib/helib.h>
#include <helib/EncryptedArray.h>
#include <helib/ArgMap.h>
#include <NTL/BasicThreadPool.h>
#include <sys/socket.h>
#include <pthread.h>
#include <csignal>
#include <string>
#include <math.h>

#include "platform.hpp"
#include "vote.hpp"
#include "ballot.hpp"

#define MAX_PENDING 10
#define MAX_LINE 20

std::vector<vote *> voters;

void *imma_vote(void *arg)
{
  std::cout << "voting" << std::endl;
  int new_s = *(int *)arg;
  socklen_t len;
  char buf[MAX_LINE];
  int id[10];
  while (len = recv(new_s, buf, sizeof(buf), 0))
  {
    printf("%s", buf);
    printf("\n");
    fflush(stdout);
    break;
  }
  close(new_s);
  return 0;
}

int socket_setup()
{
  char host_addr[10] = "127.0.0.1";
  int port = 8080;
  /*setup passive open*/
  int s;
  if ((s = socket(PF_INET, SOCK_STREAM, 0)) < 0)
  {
    perror("simplex-talk: socket");
    exit(1);
  }

  /* Config the server address */
  sockaddr_in sin;
  sin.sin_family = AF_INET;
  sin.sin_addr.s_addr = inet_addr(host_addr);
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
  listen(s, MAX_PENDING);

  /* wait for connection, then receive and print text */
  int new_s;
  socklen_t len = sizeof(sin);
  char buf[20];
  pthread_t tids[10];
  int i = 0;
  while (1)
  {
    if ((new_s = accept(s, (struct sockaddr *)&sin, &len)) < 0)
    {
      perror("simplex-talk: accept");
      exit(1);
    }
    // create thread here
    pthread_create(&tids[i], NULL, imma_vote, (void *)&new_s);
    i++;
    // new_s++;
  }
  return 0;
}

int main(int argc, char *argv[])
{

  socket_setup();

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

  std::cout << "Registering Candidates" << std::endl;

  ballot bal{10, dummyE};
  bal.registerCandidate("candidate 1");
  bal.registerCandidate("candidate 2");
  bal.registerCandidate("candidate 3");
  bal.showCandidateInfo();
  bal.close();
  bal.initBallot(&context, &public_key);

  int num_voters;

  std::cout << "Registering Voters" << std::endl;

  for (int i{0}; i < num_voters; ++i)
    voters.push_back(new vote(i, 300 + i, dummyE));
  for (auto &v : voters)
    bal.registerVoter(v);

  std::cout << "Casting Votes" << std::endl;
  int ind{0};
  for (auto &v : voters)
  {
    v->cast(&context, &public_key, 2);
  }
  std::cout << "In the ballot" << std::endl;
  for (auto &v : voters)
    bal.cast(v);

  bal.done();
  std::cout << "Votes Casted" << std::endl;
  std::cout << "--------------------------" << std::endl;
  std::cout << "Extracting Result" << std::endl;
  helib::Ctxt res = bal.showResult();

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
  string_result = bal.getCandidate(win);
  if (debug)
  {
    helib::printNamedTimer(std::cout, "timer_DecryptResult");
    std::cout << std::endl;
  }

  std::cout << "\nWinner is (should be candidate 1): " << string_result << std::endl;

  return 0;
}
