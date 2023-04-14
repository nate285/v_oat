#include "helib/helib.h"
#include <sstream>
#include <fstream>

void squareWithThinBoot(helib::PubKey& pk, helib::Ctxt& c)
{
  std::cout << ", capacity: " << c.bitCapacity() << std::endl;
  if (c.bitCapacity() <= 500) {
    std::cout << "Recrypt" << std::endl;
    pk.thinReCrypt(c);
  }
  c.square();
}

int main(int argc, char *argv[])
{
  // { p, phi(m),  m,    d, m1,  m2, m3,   g1,    g2,    g3,ord1,ord2,ord3, c_m}
  // {127, 46656, 51319, 36, 37, 1387, 0, 48546, 24976,    0,   36, -36,   0, 200}
  // {127, 31752, 32551, 14, 43,  757, 0,  7571, 28768,    0,   42,  54,   0, 100}
  // {127,   576,  1365, 12,  7,   3, 65,   976,   911,  463,    6,   2,   4, 100}, // m=3*(5)*7*{13} m/phim(m)=2.36   C=22  D=3
  // {  2, 23040, 28679, 24, 17,  7, 241, 15184,  4098,28204,   16,   6, -10, 200}, // m=7*17*(241) m/phim(m)=1.24    C=63  D=4 E=3
  unsigned long p = 2;
  unsigned long m = 28679;
  unsigned long r = 7;
  unsigned long bits = 1000;
  unsigned long c = 3;
  unsigned long t = 64;
  std::vector<long> mvec = std::vector<long>{17, 7, 241};
  std::vector<long> gens = std::vector<long>{15184, 4098, 28204};
  std::vector<long> ords = std::vector<long>{16, 6, -10};
  // unsigned long p = 131;
  // unsigned long m = 130;
  // unsigned long r = 1;
  // unsigned long bits = 1000;
  // unsigned long c = 3;

  std::cout << "---Initialising HE Environment ... ";
  // Initialize contextN
  // This object will hold information about the algebra used for this scheme.
  std::cout << "\nInitializing the Context ... ";
  helib::Context context = helib::ContextBuilder<helib::BGV>()
                               .m(m)
                               .p(p)
                               .r(r)
                               .bits(bits)
                               .c(c)
                               .gens(gens)
                               .ords(ords)
                               .mvec(mvec)
                               .bootstrappable(true)
                               .skHwt(t)
                               .build();

  // helib::Context context = helib::ContextBuilder<helib::BGV>().m(m).p(p).r(r).bits(bits).c(c).build();

  // Secret key management
  std::cout << "\nCreating Secret Key ...";
  // Create a secret key associated with the context
  helib::SecKey secret_key = helib::SecKey(context);
  // Generate the secret key
  secret_key.GenSecKey();
  std::cout << "\nGenerating key-switching matrices..." << std::endl;
  addSome1DMatrices(secret_key);
  addFrbMatrices(secret_key);

  // Generate bootstrapping data
  secret_key.genRecryptData();
  std::ofstream outSecretKeyFile;
  outSecretKeyFile.open("sk.bin", std::ios::out);
  if (outSecretKeyFile.is_open()) {
    // Write the secret key to a file
    secret_key.writeTo(outSecretKeyFile);
    // Close the ofstream
    outSecretKeyFile.close();
  } else {
    throw std::runtime_error("Could not open file 'sk.json'.");
  }

  // Public key management
  // Set the secret key (upcast: FHESecKey is a subclass of FHEPubKey)
  std::cout << "\nCreating Public Key ...";
  helib::PubKey &public_key = secret_key;

  // Get the EncryptedArray of the context
  const helib::EncryptedArray &ea = context.getEA();

  // Print the context
  std::cout << std::endl;

  // Print the security level
  // Note: This will be negligible to improve performance time.
  std::cout << "\n***Security Level: " << context.securityLevel()
            << " *** Negligible for this example ***" << std::endl;

  // Get the number of slot (phi(m))
  long nslots = ea.size();
  std::cout << "\nNumber of slots: " << nslots << std::endl;

  std::cout << "\nInitialization Completed" << std::endl;
  std::cout << "--------------------------" << std::endl;

  std::cout << "Number of slots: " << nslots << std::endl;

  std::vector<long> ptxt(nslots);
  for (int i = 0; i < nslots; ++i) {
    ptxt[i] = i; // Random 0s and 1s
  }

  std::ofstream outPublicKeyFile;
  outPublicKeyFile.open("pk2.bin", std::ios::out);
  if (outPublicKeyFile.is_open()) {
    // Write the public key to a file
    public_key.writeTo(outPublicKeyFile);
    // Close the ofstream
    outPublicKeyFile.close();
  } else {
    throw std::runtime_error("Could not open file 'pk.json'.");
  }
}