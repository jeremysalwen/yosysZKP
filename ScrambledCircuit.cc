#include "ScrambledCircuit.h"
#include "TruthTable.h"

#include <kernel/consteval.h>
#include <kernel/celltypes.h>

USING_YOSYS_NAMESPACE
using namespace CryptoPP;

bool ScrambledCircuit::validate_precommitment(const yosysZKP::Commitment& commitment, const yosysZKP::ExecutionReveal& reveal) {

  //Validate that we are revealing a precommitted entry
  for(int i=0; i<commitment.gatehashes_size(); i++) {
    const yosysZKP::TableCommitment& com=commitment.gatehashes(i);
    std::string entryhash=TruthTableEntry_get_commitment(reveal.entries(i));
    
    bool found=false;
    for(int j=0; j<com.entryhashes_size(); j++) {
      if(com.entryhashes(j) == entryhash) {
	found=true;
      }
    }
    if(!found) {
      log_error("Found unmatched table entry hash\n");
      return false;
    }
  }
  
  //Validate that the execution trace matches the revealed gates
  WireValues scrambledexec(m);
  scrambledexec.deserialize(reveal.exec());

  
  for(int i=0; i<alloutputs.size(); i++) {
    const SigBit& s=alloutputs[i];
    bool b;
    if(s.wire!=nullptr) {
      b=scrambledexec.map[s.wire];
    } else {
      b=s.data;
    }
    if(b!=commitment.output(i)) {
      log_error("Output does not match commitment\n");
      return false;
    }
  }

    
  int i=0;
  for(Cell* cell: m->cells()) {
    const yosysZKP::TruthTableEntry& entry=reveal.entries(i);
    std::vector<bool> inputs, outputs;
    getGatePorts(scrambledexec, cell, inputs, outputs);

    if(inputs.size()!=entry.inputs_size() || outputs.size()!=entry.outputs_size()) {
      log_error("Size mismatch in truth table entry\n");
    }
    
    if(!TruthTableEntry_verify_computation(entry, inputs, outputs)) {
      log_error("Failed to find corresponding truth table entry for cell %s\n",log_id(cell->name));
      return false;
    }
    i++;
  }

  return true;
}
bool ScrambledCircuit::validate_precommitment(const yosysZKP::Commitment& commitment, const yosysZKP::ScramblingReveal& reveal) {
  for(int i=0; i<commitment.gatehashes_size(); i++) {
    const yosysZKP::TableCommitment& com=commitment.gatehashes(i);
    const yosysZKP::TableCommitment& hash=TruthTable_get_commitment(reveal.gates(i));
    for(int j=0; j<com.entryhashes_size(); j++) {
      if(com.entryhashes(j) !=hash.entryhashes(j)) {
	log_error("Hash check failed for truth table\n");
	return false;
      }
    }
  }

  keys.deserialize(reveal.keys());

  for(const SigBit& b:alloutputs) {
    if(b.wire!=nullptr && keys.map[b.wire]!=0) {
      log_error("Output key was not empty\n");
      return false;
    }
  }
  
  int i=0;
  for(Cell* cell: m->cells()) {
    const yosysZKP::TruthTable& table=reveal.gates(i);
    const yosysZKP::TruthTable& canonical=gatesdef[cell->name];
    
    std::vector<bool> inputkeys, outputkeys;
    getGatePorts(keys, cell, inputkeys, outputkeys);
    for(const yosysZKP::TruthTableEntry& entry: table.entries()) {
      if(!TruthTable_contains_entry(canonical, entry, inputkeys, outputkeys)) {
	log_error("Failed to find match truth tables for cell %s\n",log_id(cell->name));
	return false;
      }
    }
    i++;
  }
  return true;
}


void ScrambledCircuit::getGatePorts(WireValues& values, const Cell* cell, std::vector<bool>& inputs, std::vector<bool>& outputs, bool zeroconst) {
  inputs.clear();
  outputs.clear();
  for(auto& it:cell->connections()) {
    bool input=cell->input(it.first);

    for(const SigBit& b:it.second) {
      char bit=zeroconst?0:b.data;
      if(b.wire!=nullptr){
	bit=values.map[b.wire];
      }
      if(input) {
	inputs.push_back(bit);
      } else {
	outputs.push_back(bit);
      }
    }
  }
}

ScrambledCircuit::ScrambledCircuit(Module* module): rand(), m(module), sigmap(m),execution(m), keys(m) {
  SecByteBlock seed(32 + 16);
  seed.CleanNew(32+16);
  rand.SetKeyWithIV(seed, 32, seed + 32, 16);

  m->sort();
  enumerateWires();
  initializeCellTables();
}
  
void ScrambledCircuit::enumerateWires() {
  {
    pool<Wire*> wires;
    for(Wire* w:m->wires()) {
      SigBit s=sigmap(w);
      log_assert(s.wire!=nullptr);
      if(!wires.count(s.wire)) {
	wires.insert(s.wire);

	allwires.append(s.wire);
      }
    }
  }
  CellTypes ct(m->design);
  for(IdString s:m->ports) {
    if(ct.cell_input(m->name, s)) {
      allinputs.append(m->wire(s));
    }
    if(ct.cell_output(m->name,s)) {
      alloutputs.append(m->wire(s));
    }
  }

  for(Cell* cell:m->cells()) {
    for(auto& it:cell->connections()) {
      cell->setPort(it.first,sigmap(it.second));
    }
    cell->sort();
  }
}

yosysZKP::Commitment ScrambledCircuit::createProofRound() {
  yosysZKP::Commitment result;

  keys.map.clear();
  for(auto& it:execution.map) {
    keys.map[it.first]=rand.GenerateBit();
  }

  for(Cell* cell:m->cells()) {
    std::vector<bool> inputkey;
    std::vector<bool> outputkey;
    getGatePorts(keys, cell, inputkey, outputkey);
    
    gates[cell->name]=gatesdef[cell->name];
    TruthTable_scramble(gates[cell->name], rand, inputkey, outputkey);
    *result.add_gatehashes()=TruthTable_get_commitment(gates[cell->name]);
  }

  for(const SigBit& s: alloutputs) {
    bool b;
    if(s.wire!=nullptr) {
      keys.map[s.wire]=0;
      b=execution.map[s.wire];
    } else {
      b=(s.data==State::S1);
    }
    result.add_output(b);
  }

  return result;
}

  
Const ScrambledCircuit::execute(Const inputs) {
  ConstEval ce(m);
  ce.push();
  ce.set(allinputs, inputs);
  {
    SigSpec sig_wires=allwires, sig_undef;
    if(!ce.eval(sig_wires, sig_undef)) {
      log_error("Eval failed for execute: Missing value for %s\n", log_signal(sig_undef));
    }
    execution.map.clear();
    for(int i=0; i<allwires.size(); i++) {
      Wire* w=allwires[i].wire;
      execution.map[w]=(sig_wires[i]==State::S1);
    }
  }
  Const result;
  {
    SigSpec sig_out=alloutputs, sig_undef;
    if(!ce.eval(sig_out, sig_undef)) {
      log_error("Eval failed for execute: Missing value for %s\n", log_signal(sig_undef));
    }

    result=sig_out.as_const();
  }
  ce.pop();

  return result;
}

void ScrambledCircuit::initializeCellTables() {
  for(Cell* c:m->cells()) {
    gatesdef[c->name]=TruthTable_from_gate(c);
  }
}

yosysZKP::ExecutionReveal ScrambledCircuit::reveal_execution() {
  yosysZKP::ExecutionReveal exec;
  yosysZKP::WireValues* wv=exec.mutable_exec();
  for(const auto& it:execution.map) {
    bool bit=it.second ^keys.map[it.first];
    yosysZKP::WireValues_Entry* entry=wv->add_entries();
    entry->set_wirename(it.first->name.str());
    entry->set_value(bit);
  }

  for(Cell* cell: m->cells()) {
    const yosysZKP::TruthTable& g=gates[cell->name];

    std::vector<bool> inputval,  inputkey;
    std::vector<bool> outputval, outputkey; 

    getGatePorts(execution, cell, inputval, outputval);
    getGatePorts(keys, cell, inputkey, outputkey);

    int count=0;
    for(const yosysZKP::TruthTableEntry& e: g.entries()) {
      
      for(size_t i=0; i<inputval.size(); i++)
	if(e.inputs(i) !=(inputval[i]^inputkey[i])) 
	  goto loop_continue;

      for(size_t i=0; i<outputval.size(); i++)
	if(e.outputs(i) != (outputval[i]^outputkey[i]))
	  log_error("Error, truth table does not match computed execution for cell %s %s\n",log_id(cell->type), log_id(cell->name));

      *exec.add_entries()=e;
      count++;
    loop_continue: ;
    }
    if(count!=1) {
      log_error("Truth table contains multiple entries for the same inputs\n");
    }
  }
  return exec;
}

yosysZKP::ScramblingReveal ScrambledCircuit::reveal_scrambling() {
  yosysZKP::ScramblingReveal scr;
  *scr.mutable_keys()=keys.serialize();
  for(Cell* cell:m->cells()) {
    *scr.add_gates()=gates[cell->name];
  }
 
  return scr;
}

