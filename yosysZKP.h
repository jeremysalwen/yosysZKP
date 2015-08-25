#ifndef YOSYS_ZKP_H
#define YOSYS_ZKP_H
#include <kernel/yosys.h>
#include <kernel/sigtools.h>
#include <kernel/consteval.h>

#include <crypto++/osrng.h>
#include <crypto++/modes.h>
#include "messages.pb.h"

#define NONCE_SIZE 16

yosysZKP::Commitment commit(const yosysZKP::FullState& hiddenState);

struct WireValues {
  Yosys::Module* m;
  
  Yosys::dict<Yosys::Wire*, unsigned char> map;

  WireValues(Yosys::Module* module);
  
  yosysZKP::WireValues serialize()  const;
  void deserialize(const yosysZKP::WireValues& ex);

};

struct ScrambledCircuit {
  CryptoPP::OFB_Mode<CryptoPP::AES>::Encryption rand;
  
  Yosys::Module* m;

  Yosys::SigMap sigmap;
  
  /* Indexed by cell name */
  Yosys::dict<Yosys::IdString, yosysZKP::TruthTable> gatesdef;
  Yosys::dict<Yosys::IdString, yosysZKP::TruthTable> gates;

  yosysZKP::FullState serializedState;

  WireValues execution;
  WireValues keys;
  
  Yosys::SigSpec allinputs;
  Yosys::SigSpec alloutputs;

  Yosys::SigSpec allwires;

  void getGatePorts(WireValues& values, const Yosys::Cell* cell, std::vector<bool>& inputs, std::vector<bool>& outputs);
  
  ScrambledCircuit(Yosys::Module* module);
  
  void enumerateWires();

  void initializeCellTables();

  void execute(Yosys::Const inputs);
  
  void createProofRound();


  yosysZKP::ExecutionReveal reveal_execution();
  yosysZKP::ScramblingReveal reveal_scrambling();

  bool validate_precommitment(const yosysZKP::Commitment& commitment, const yosysZKP::ExecutionReveal& reveal);
  bool validate_precommitment(const yosysZKP::Commitment& commitment, const yosysZKP::ScramblingReveal& reveal);


};

#endif //YOSYS_ZKP_H
