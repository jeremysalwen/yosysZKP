#ifndef YOSYS_ZKP_H
#define YOSYS_ZKP_H
#include <kernel/yosys.h>
#include <kernel/sigtools.h>
#include <kernel/consteval.h>

#include <crypto++/osrng.h>

#include "messages.pb.h"

#define NONCE_SIZE 16

yosysZKP::Commitment commit(const yosysZKP::FullState& hiddenState);

bool validate_precommitment(const yosysZKP::Commitment& commitment, const yosysZKP::ExecutionReveal& reveal);
bool validate_precommitment(const yosysZKP::Commitment& commitment, const yosysZKP::ScramblingReveal& reveal);

yosysZKP::Hash TruthTableEntry_get_commitment(const yosysZKP::TruthTableEntry& e);
bool TruthTableEntry_verify_computation(const yosysZKP::TruthTableEntry& e, const std::vector<byte>& i, const std::vector<byte>&o);
void TruthTableEntry_scramble(const CryptoPP::RandomNumberGenerator& rng, yosysZKP::TruthTableEntry& e, const std::vector<byte>& i, const std::vector<byte>& o);

yosysZKP::TruthTable TruthTable_from_gate(Yosys::Cell* cell);
yosysZKP::TableCommitment TruthTable_get_commitment(const yosysZKP::TruthTable& t);
void TruthTable_scramble(yosysZKP::TruthTable& t, CryptoPP::RandomNumberGenerator& rand, const std::vector<byte>& i, const std::vector<byte>& o);


struct WireValues {
  Yosys::Module* m;
  
  Yosys::dict<Yosys::Wire*, unsigned char> map;

  byte nonce[NONCE_SIZE];
  
  WireValues(Yosys::Module* module);
  
  yosysZKP::WireValues serialize()  const;
  void deserialize(const yosysZKP::WireValues& ex);

};

struct ScrambledCircuit {
  CryptoPP::AutoSeededRandomPool rand;
  
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
  ScrambledCircuit(Yosys::Module* module);
  
  void enumerateWires();

  void initializeCellTables();

  void execute(Yosys::Const inputs);
  
  void createProofRound();

  void serializeState();

  yosysZKP::ExecutionReveal reveal_execution();
  yosysZKP::ScramblingReveal reveal_scrambling();

};

#endif //YOSYS_ZKP_H

