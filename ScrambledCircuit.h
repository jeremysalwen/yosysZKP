#ifndef SCRAMBLED_CIRCUIT_H
#define SCRAMBLED_CIRCUIT_H
#include <kernel/yosys.h>
#include <kernel/sigtools.h>

#include <crypto++/osrng.h>
#include <crypto++/modes.h>

#include "messages.pb.h"

#include "WireValues.h"


struct ScrambledCircuit {
  CryptoPP::OFB_Mode<CryptoPP::AES>::Encryption rand;
  
  Yosys::Module* m;

  Yosys::SigMap sigmap;
  
  /* Indexed by cell name */
  Yosys::dict<Yosys::IdString, yosysZKP::TruthTable> gatesdef;
  Yosys::dict<Yosys::IdString, yosysZKP::TruthTable> gates;

  WireValues execution;
  WireValues keys;
  
  Yosys::SigSpec allinputs;
  Yosys::SigSpec alloutputs;

  Yosys::SigSpec allwires;

  void getGatePorts(WireValues& values, const Yosys::Cell* cell, std::vector<bool>& inputs, std::vector<bool>& outputs);
  
  ScrambledCircuit(Yosys::Module* module);
 
  Yosys::Const execute(Yosys::Const inputs);
  
  yosysZKP::Commitment createProofRound();

  yosysZKP::ExecutionReveal reveal_execution();
  yosysZKP::ScramblingReveal reveal_scrambling();

  bool validate_precommitment(const yosysZKP::Commitment& commitment, const yosysZKP::ExecutionReveal& reveal);
  bool validate_precommitment(const yosysZKP::Commitment& commitment, const yosysZKP::ScramblingReveal& reveal);

private:
  void enumerateWires();

  void initializeCellTables();

};

#endif //SCRAMBLED_CIRUIT_H
