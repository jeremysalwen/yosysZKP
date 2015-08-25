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
  int i=0;
  for(Cell* cell: m->cells()) {
    const yosysZKP::TruthTableEntry& entry=reveal.entries(i);
    std::vector<bool> inputs, outputs;
    getGatePorts(scrambledexec, cell, inputs, outputs);

    if(inputs.size()!=entry.inputs_size() || outputs.size()!=entry.outputs_size()) {
      log_error("Size mismatch in truth table entry\n");
    }
    
    if(!TruthTableEntry_verify_computation(entry, inputs, outputs)) {
      log("FAIL\n entry %s\n",entry.DebugString().c_str());
      std::vector<bool> execin,execout,keyin,keyout;
      getGatePorts(execution, cell, execin, execout);
      getGatePorts(keys, cell, keyin, keyout);
      
      log("Canonicalentry %s\n",gatesdef[cell->name].DebugString().c_str());
      log("\ninputs ");
      for(bool b:inputs)
	log("%d ",b);
      log("\noutputs ");
      for(bool b:outputs)
	log("%d ",b);

      log("\neinputs ");
      for(bool b:execin)
	log("%d ",b);
      log("\neoutputs ");
      for(bool b:execout)
	log("%d ",b);

      log("\nkinputs ");
      for(bool b:keyin)
	log("%d ",b);
      log("\nkoutputs ");
      for(bool b:keyout)
	log("%d ",b);
   
      log_error("\nFailed to find corresponding truth table entry for cell %s\n",log_id(cell->name));
      
      return false;
    }
    i++;
  }

  return true;
}
bool ScrambledCircuit::validate_precommitment(const yosysZKP::Commitment& commitment, const yosysZKP::ScramblingReveal& reveal) {
  log("done1\n");
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
  log("done2\n");

  keys.deserialize(reveal.keys());
 
  int i=0;
  for(Cell* cell: m->cells()) {
    log("donea\n");
    const yosysZKP::TruthTable& table=reveal.gates(i);
    log("done3\n");
    const yosysZKP::TruthTable& canonical=gatesdef[cell->name];
    
    std::vector<bool> inputkeys, outputkeys;
    getGatePorts(keys, cell, inputkeys, outputkeys);
    log("done4\n");
    for(const yosysZKP::TruthTableEntry& entry: table.entries()) {
      log("in1\n");
      if(!TruthTable_contains_entry(canonical, entry, inputkeys, outputkeys)) {
	
	log("def\n%s\n scrambled\n%s\n",gatesdef[cell->name].DebugString().c_str(), gates[cell->name].DebugString().c_str());
log_error("Failed to find corresponding truth table entry for cell %s\n",log_id(cell->name));
	return false;
      }
      log("in2\n");
    }
    i++;
  }
  log("done5\n");
  return true;
}


void ScrambledCircuit::getGatePorts(WireValues& values, const Cell* cell, std::vector<bool>& inputs, std::vector<bool>& outputs) {
  inputs.clear();
  outputs.clear();
  for(auto& it:cell->connections()) {
    bool input=cell->input(it.first);
    bool output=cell->output(it.first);
    log_assert(input || output);
    SigSpec con=sigmap(it.second);
    for(const SigBit& b:con) {
      char bit=0;
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

  printf("pre\n");
  enumerateWires();
  printf("enumerated\n");
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
}
yosysZKP::Commitment ScrambledCircuit::createProofRound() {
  printf("step0\n");
  keys.map.clear();
  for(auto& it:execution.map) {
    keys.map[it.first]=rand.GenerateBit();
  }
  printf("step1\n");
  serializedState.clear_gates(); 
  for(Cell* cell:m->cells()) {
    std::vector<bool> inputkey;
    std::vector<bool> outputkey;
    getGatePorts(keys, cell, inputkey, outputkey);
    
    gates[cell->name]=gatesdef[cell->name];
    log("ok1\n");
    TruthTable_check(gatesdef[cell->name]);
    log("ok2\n");
    TruthTable_scramble(gates[cell->name], rand, inputkey, outputkey);
    TruthTable_check(gates[cell->name]);
    *serializedState.add_gates()=gates[cell->name];
  }
  printf("step2\n");

  return commit(serializedState);

}

  
void ScrambledCircuit::execute(Const inputs) {
  ConstEval ce(m);
  ce.push();
  printf("setting1\n");
  printf("%d %d\n",allinputs.size(),inputs.size());
  log("%s %s\n",log_signal(allinputs),log_signal(inputs));
  ce.set(allinputs, inputs);
  printf("setting2\n");
  SigSpec sig_wires=allwires, sig_undef;
  if(!ce.eval(sig_wires, sig_undef)) {
    log("Eval failed for execute: Missing value for %s\n", log_signal(sig_undef));
  }
  execution.map.clear();
  for(int i=0; i<allwires.size(); i++) {
    Wire* w=allwires[i].wire;
    execution.map[w]=(sig_wires[i]==State::S1);
  }
  ce.pop();
}

void ScrambledCircuit::initializeCellTables() {
  for(Cell* c:m->cells()) {
    gatesdef[c->name]=TruthTable_from_gate(c);
  }
  printf("gatesdone\n");
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
     if(cell->name.str().find("$and$test_synth.v:1537$2")!=std::string::npos) {
       log("DID FIND\n");
     }
    const yosysZKP::TruthTable& g=gates[cell->name];

    std::vector<bool> inputval,  inputkey;
    std::vector<bool> outputval, outputkey; 

    getGatePorts(execution, cell, inputval, outputval);
    getGatePorts(keys, cell, inputkey, outputkey);

    int count=0;
    printf("Entries size %d\n",g.entries_size());
    for(const yosysZKP::TruthTableEntry& e: g.entries()) {
      printf("checking input \n%s\n",e.DebugString().c_str());
      
      for(size_t i=0; i<inputval.size(); i++)
	if(e.inputs(i) !=(inputval[i]^inputkey[i])) 
	  goto loop_continue;

      for(size_t i=0; i<outputval.size(); i++)
	if(e.outputs(i) != (outputval[i]^outputkey[i]))
	  log_error("Error, truth table does not match computed execution for cell %s %s\n",log_id(cell->type), log_id(cell->name));

      if(cell->name.str().find("$and$test_synth.v:1537$2")!=std::string::npos) {
	log("ENTRY IS\n %s\n",e.DebugString().c_str());
	log("inputval ");
	for(bool b:inputval)
	  log("%d ",b);
	log("\n");
	log("outputval ");
	for(bool b:outputval)
	  log("%d ",b);
	log("\n");

	log("inputkey ");
	for(bool b:inputkey)
	  log("%d ",b);
	log("\n");
	log("outputkey ");
	for(bool b:outputkey)
	  log("%d ",b);
	log("\n");

      }
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
  *scr.mutable_gates()=serializedState.gates();
  return scr;
}

