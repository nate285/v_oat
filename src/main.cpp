#include <iostream>

#include <helib/helib.h>
#include <helib/EncryptedArray.h>
#include <helib/ArgMap.h>
#include <NTL/BasicThreadPool.h>

#include "platform.hpp"
#include "vote.hpp"
#include "ballot.hpp"

ballot *candidateRegistration(helib::Ctxt dum)
{
  std::cout << "Registering Candidates" << std::endl;
  std::cout << "How many canidates would you like to register?" << std::endl;
  int r;
  char str[30];
  std::cin >> r;
  ballot *bal = new ballot{r, dum};
  for (int i = 0; i < r; i++)
  {
    std::cout << "Registering candidate " << i + 1 << std::endl;
    std::cout << "Enter name " << std::endl;
    std::cin >> str;
    bal->registerCandidate(str);
  }

  bal->showCandidateInfo();
  bal->close();
  return bal;
}

int main(int argc, char *argv[])
{
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

  ballot bal = *candidateRegistration(dummyE);
  bal.initBallot(&context, &public_key);

  std::cout << "Registering Voters" << std::endl;
  std::vector<vote *> voters;

  for (int i{0}; i < 10; ++i)
    voters.push_back(new vote(i, 300 + i, dummyE));
  for (auto &v : voters)
    bal.registerVoter(v);

  std::cout << "Casting Votes" << std::endl;
  int ind{0};
  for (auto &v : voters)
  {
    v->cast(&context, &public_key, ind % 3);
    ind++;
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
