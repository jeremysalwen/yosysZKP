#ifndef PROVER_AGENT_H
#define PROVER_AGENT_H

#include <kernel/yosys.h>

#include "messages.pb.h"

#include "ScrambledCircuit.h"


class ProverAgent {

 public:
  ProverAgent(Yosys::Module* m);

  void set_data(Yosys::Const inputs, Yosys::Const outputs);
  void set_security_param(int p);

  void save_secret(std::string& out);
  void read_secret(const std::string& in);
  
  void write_commitment_packet(std::string& out);
  void write_reveal(std::string& out, const std::string& response);

 private:
  ScrambledCircuit circuit;
  Yosys::Const outputs;
  int security_param;
  yosysZKP::ProverState state;
};

#endif
