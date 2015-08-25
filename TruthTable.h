#ifndef TRUTH_TABLE_H
#define TRUTH_TABLE_H

#include <kernel/yosys.h>
#include <cryptopp/cryptlib.h>
#include "messages.pb.h"

#define NONCE_SIZE 16
std::string TruthTableEntry_get_commitment(const yosysZKP::TruthTableEntry& e);
bool TruthTableEntry_verify_computation(const yosysZKP::TruthTableEntry& e, const std::vector<bool>& i, const std::vector<bool>&o);
void TruthTableEntry_scramble(const CryptoPP::RandomNumberGenerator& rng, yosysZKP::TruthTableEntry& e, const std::vector<bool>& i, const std::vector<bool>& o);

yosysZKP::TruthTable TruthTable_from_gate(Yosys::Cell* cell);
yosysZKP::TableCommitment TruthTable_get_commitment(const yosysZKP::TruthTable& t);
void TruthTable_scramble(yosysZKP::TruthTable& t, CryptoPP::RandomNumberGenerator& rand, const std::vector<bool>& i, const std::vector<bool>& o);
bool TruthTable_contains_entry(const yosysZKP::TruthTable& tt, const yosysZKP::TruthTableEntry& entry, const std::vector<bool>& inputkey, const std::vector<bool>& outputkey);
void TruthTable_check(const yosysZKP::TruthTable& t);


yosysZKP::Commitment commit(const yosysZKP::FullState& hiddenState);


#endif //TRUTH_TABLE_H
