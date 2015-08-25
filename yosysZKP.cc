#include "yosysZKP.h"

#include <google/protobuf/repeated_field.h>

USING_YOSYS_NAMESPACE
using namespace CryptoPP;


void TruthTable_check(const yosysZKP::TruthTable& t) {
  for(int i=0; i<t.entries_size(); i++) {
    for(int j=0; j<t.entries_size(); j++) {
      if(j==i)
	continue;
      bool matches=true;
      for(int k=0; k<t.entries(i).inputs_size(); k++)
	if(t.entries(i).inputs(k)!=t.entries(j).inputs(k))
	  matches=false;
      if(matches)
	log_error("DUPLICATE ENTRY\n");
    }
  }
}
yosysZKP::Commitment commit(const yosysZKP::FullState& hiddenState) {
  yosysZKP::Commitment comm;

  for(int i=0; i<hiddenState.gates_size(); i++) {
    const yosysZKP::TruthTable& gate=hiddenState.gates(i);
    *comm.add_gatehashes()=TruthTable_get_commitment(gate);
  }
  return comm;
}


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


yosysZKP::TruthTable TruthTable_from_gate(Cell* cell) {
  yosysZKP::TruthTable result;

  Module mod;
  SigSpec inputs, outputs;

  Cell *c = mod.addCell("\\uut", cell);
  auto conns = cell->connections();
  conns.sort<RTLIL::sort_by_id_str>();
  for (auto &conn : conns) {
    Wire *w = mod.addWire(conn.first, GetSize(conn.second));
    if (cell->input(conn.first))
      inputs.append(w);
    if (cell->output(conn.first))
      outputs.append(w);
    c->setPort(conn.first, w);
  }
  mod.check();


  if(inputs.size()>16) {
    log_error("Gate %s has too many inputs, and so too big a truth table. Please decompose it into smaller gates\n",log_id(cell->name));
  }
    
  // print truth table header
  vector<RTLIL::SigChunk> in_chunks_r = inputs.chunks();
  vector<RTLIL::SigChunk> out_chunks_r = outputs.chunks();

  for (auto &c : in_chunks_r)
    log(" %*s", c.width, log_id(c.wire));
  log(" |");
  for (auto &c : out_chunks_r)
    log(" %*s", c.width, log_id(c.wire));
  log("\n");

  for (auto &c : in_chunks_r)
    log(" %.*s", c.width, "----------------------------");
  log(" |");
  for (auto &c : out_chunks_r)
    log(" %.*s", c.width, "----------------------------");
  log("\n");
    
  // create truth table

  ConstEval ce(&mod);
  Const invalue(0, GetSize(inputs));

  do {
    ce.push();
    ce.set(inputs, invalue);
	
    yosysZKP::TruthTableEntry* entry=result.add_entries();

    for(State st:invalue.bits) {
      entry->add_inputs(st==State::S1);
    }
	
    for (auto &c : in_chunks_r)
      {
	SigSpec s(c), u;
	bool ok = ce.eval(s, u);

	if (!ok)
	  log_error("Can't evaluate %s: Missing value for %s!\n",
		    log_signal(s), log_signal(u));

	log(" %s", s.as_const().as_string().c_str());
      }
    log(" |");


    for (auto &c : out_chunks_r)
      {
	SigSpec s(c), u;
	bool ok = ce.eval(s, u);

	if (!ok)
	  log_error("Can't evaluate %s: Missing value for %s!\n",
		    log_signal(s), log_signal(u));

	log(" %s", s.as_const().as_string().c_str());

	Const outval=s.as_const();
	for(State st: outval.bits) {
	  entry->add_outputs(st==State::S1);
	}
      }
    log("\n");

       printf("INSERTED ENTRY FOR CELL TYPE %s\n %s\n",log_id(cell->type),entry->DebugString().c_str());
    ce.pop();

    invalue = RTLIL::const_add(invalue, Const(1, 1), false, false, GetSize(invalue));
  } while (invalue.as_bool());
  return result;
}



std::string TruthTableEntry_get_commitment(const yosysZKP::TruthTableEntry& e) {
  std::string buf(SHA256::DIGESTSIZE,0);
    
  std::string serialized=e.SerializeAsString();
  SHA256().CalculateDigest((byte*)buf.data(),(byte*)serialized.data(),serialized.length());
  return buf;
}

bool TruthTableEntry_verify_computation(const yosysZKP::TruthTableEntry& e, const vector<bool>& i, const vector<bool>& o) {
  if(i.size()!=e.inputs_size() || o.size() != e.outputs_size()) {
    log_error("Tried to verify computation with wrong sized vector\n");
  }
  for(size_t n=0; n<i.size(); n++) 
    if(e.inputs(n)!=i[n])
      return false;

  for(size_t n=0; n<o.size(); n++)
    if(e.outputs(n)!=o[n])
      return false;
  
  return true;
}

void TruthTableEntry_scramble(RandomNumberGenerator& rand, yosysZKP::TruthTableEntry& e, const std::vector<bool>&i, const std::vector<bool>& o) {
  for(unsigned int n=0; n<i.size(); n++){
    e.set_inputs(n, e.inputs(n)^i[n]);
  }
  for(unsigned int n=0; n<o.size(); n++){
    e.set_outputs(n, e.outputs(n)^o[n]);
  }
  
  std::string* nonce=e.mutable_nonce();
  nonce->resize(NONCE_SIZE);
  rand.GenerateBlock((byte*)nonce->data(),NONCE_SIZE);
}


yosysZKP::TableCommitment TruthTable_get_commitment(const yosysZKP::TruthTable& t) {
  yosysZKP::TableCommitment tc;
  for(int i=0; i<t.entries_size(); i++) {
    *tc.add_entryhashes()=TruthTableEntry_get_commitment(t.entries(i));
  }
  return tc;
}
  
void TruthTable_scramble(yosysZKP::TruthTable& t, RandomNumberGenerator& rand, const std::vector<bool>& i, const std::vector<bool>& o) {
  
  for(int n=0; n<t.entries_size(); n++) {
    TruthTableEntry_scramble(rand, *t.mutable_entries(n), i, o);
  }
  rand.Shuffle(t.mutable_entries()->begin(), t.mutable_entries()->end());
}

bool TruthTable_contains_entry(const yosysZKP::TruthTable& tt, const yosysZKP::TruthTableEntry& entry, const std::vector<bool>& inputkey, const std::vector<bool>& outputkey) {

  std::vector<bool> unscrambledinp, unscrambledoutp;

  log("a1\n");
  for(int i=0; i<entry.inputs_size(); i++)
    unscrambledinp.push_back(entry.inputs(i)^inputkey[i]);
  log("a2\n");
  for(int i=0; i<entry.outputs_size(); i++)
    unscrambledoutp.push_back(entry.outputs(i)^outputkey[i]);
    log("a3\n");
  int min=0, max=tt.entries_size()-1;

  while(max>min) {
    int ave=min+(max-min)/2;
    log("ave %d %d %d\n",min,max,ave);
    const yosysZKP::TruthTableEntry& compentry=tt.entries(ave);

    bool equal=true;
    for(int i=compentry.inputs_size()-1; i>=0; i--) {
      if(compentry.inputs(i) && !unscrambledinp[i]) {
	log("smaller!\n");
	log("%s\n",compentry.DebugString().c_str());
	equal=false;
	max=ave-1;
	break;
      }
      if(!compentry.inputs(i) && unscrambledinp[i]) {
	log("bigger!\n");
	log("%s\n",compentry.DebugString().c_str());
	equal=false;
	min=ave+1;
	break;
      }
    }
    if(equal) {
      min=ave;
      max=ave;
    }
  }
  if(max!=min) {
    log("found no entry\n");
    for(bool b:unscrambledinp)
      log("%d ",b);
    log("\n");
    for(bool b:unscrambledoutp)
      log("%d ",b);
    log("\n");
    log("table\n");
    for(int i=0; i<tt.entries_size(); i++) {
      log("%s\n",tt.entries(i).DebugString().c_str());
    }
    return false;
  }
  const yosysZKP::TruthTableEntry& comp=tt.entries(min);
  log("a4\n");
  bool verified=TruthTableEntry_verify_computation(comp, unscrambledinp, unscrambledoutp);
  if(!verified) {
    log("not verified\n");
    for(bool b:unscrambledinp)
      log("%d ",b);
    log("\n");
    for(bool b:unscrambledoutp)
      log("%d ",b);
    log("\n");
    log("table\n");
    for(int i=0; i<tt.entries_size(); i++) {
      log("%s\n",tt.entries(i).DebugString().c_str());
    }
  }
  return verified;
}


WireValues::WireValues(Module* module):m(module) {

}
yosysZKP::WireValues WireValues::serialize()  const {
  yosysZKP::WireValues ex;
  for(const auto& it : map) {
    yosysZKP::WireValues_Entry* entry=ex.add_entries();
    IdString wirename=it.first->name;
    entry->set_wirename(wirename.str());
    entry->set_value(it.second);
  }

  return ex;
}
void WireValues::deserialize(const yosysZKP::WireValues& ex) {
  map.clear();
  for(const yosysZKP::WireValues_Entry& entry : ex.entries()) {
    map[m->wire(IdString(entry.wirename()))]=entry.value();
  }
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
void ScrambledCircuit::createProofRound() {
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


int main(int argc, char** argv)
{
  string filename(argv[1]);
  string modulename(argv[2]);
  Yosys::log_streams.push_back(&std::cout);
  Yosys::log_error_stderr = true;
    
  Yosys::yosys_setup();
  Yosys::yosys_banner();
  Design* design=yosys_get_design();
  Yosys::run_frontend(filename, "auto", design);
  Pass::call(design, "hierarchy -check");
  Pass::call(design, "splitnets -ports");

  design->sort();
  Module* module=design->module("\\"+modulename);
  ScrambledCircuit circuit(module);

  circuit.execute(Const(28,8));
  circuit.createProofRound();
  yosysZKP::Commitment comm=commit(circuit.serializedState);
  yosysZKP::ExecutionReveal exec=circuit.reveal_execution();

  yosysZKP::ScramblingReveal scramb=circuit.reveal_scrambling();

  ScrambledCircuit reciever(module);
  bool execval=reciever.validate_precommitment(comm, exec);
  log("execution validated? %d\n", execval);

  bool scrambval=reciever.validate_precommitment(comm, scramb);
  log("scramblind validated? %d\n",scrambval);

  Yosys::yosys_shutdown();
  return 0;
}
