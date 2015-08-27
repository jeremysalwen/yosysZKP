#ifndef PROVEE_AGENT_H
#define PROVEE_AGENT_H
#include <kernel/yosys.h>
#include <crypto++/osrng.h>

#include "messages.pb.h"

#include "ScrambledCircuit.h"

class ProveeAgent {
 
 public:
  ProveeAgent(Yosys::Module* m);

  void set_outputs(Yosys::Const outputs);
  void set_security_param(int p);

  void save_state(std::string& out);
  void read_state(const std::string& in);

  void read_commitment(const std::string& commitment, std::string& response);
  void read_reveal(const std::string& reveal);

  bool proven();
 private:
  ScrambledCircuit circuit;

  CryptoPP::AutoSeededRandomPool rng;
 
  yosysZKP::ProveeState state;
};

#endif
