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
  SHA256 sha;
  byte hash[SHA256::DIGESTSIZE];
  yosysZKP::Commitment comm;

  std::string serializedexecution=hiddenState.exec().SerializeAsString();
  sha.CalculateDigest(hash, (const byte*) serializedexecution.data(), serializedexecution.size());
  comm.mutable_executionhash()->set_hash(hash, SHA256::DIGESTSIZE);

  std::string serializedkeys=hiddenState.keys().SerializeAsString();
  sha.CalculateDigest(hash, (const byte*) serializedkeys.data(), serializedkeys.size());
  comm.mutable_keyhash()->set_hash(hash,SHA256::DIGESTSIZE);

  for(int i=0; i<hiddenState.gates_size(); i++) {
    const yosysZKP::TruthTable& gate=hiddenState.gates(i);
    *comm.add_gatehashes()=TruthTable_get_commitment(gate);
  }
  return comm;
}


bool validate_precommitment(const yosysZKP::Commitment& commitment, const yosysZKP::ExecutionReveal& reveal) {
  std::string hash(SHA256::DIGESTSIZE, '\0');
  SHA256 sha;

  std::string execserialized=reveal.exec().SerializeAsString();
  sha.CalculateDigest((byte*)hash.data(), (byte*)execserialized.data(),execserialized.size());
  if(hash != commitment.executionhash().hash()) {
    log_error("Hash check failed for execution\n");
    return false;
  }

  for(int i=0; i<commitment.gatehashes_size(); i++) {
    const yosysZKP::TableCommitment& com=commitment.gatehashes(i);
    yosysZKP::Hash tablehash=TruthTableEntry_get_commitment(reveal.entries(i));
    
    bool found=false;
    for(int j=0; j<com.entryhashes_size(); j++) {
      if(com.entryhashes(j).hash() == tablehash.hash()) {
	found=true;
      }
    }
    if(!found) {
      log_error("Found unmatched table entry hash\n");
      return false;
    }
  }

  //TODO Validate that wires match revealed truth table entries

  return true;
}
bool validate_precommitment(const yosysZKP::Commitment& commitment, const yosysZKP::ScramblingReveal& reveal) {
   std::string hash(SHA256::DIGESTSIZE, '\0');
  SHA256 sha;

  std::string execserialized=reveal.keys().SerializeAsString();
  sha.CalculateDigest((byte*)hash.data(), (byte*)execserialized.data(),execserialized.size());
  if(hash != commitment.keyhash().hash()) {
    log_error("Hash check failed for keys\n");
    return false;
  }

  for(int i=0; i<commitment.gatehashes_size(); i++) {
    const yosysZKP::TableCommitment& com=commitment.gatehashes(i);
    const yosysZKP::TableCommitment& hash=TruthTable_get_commitment(reveal.gates(i));
    for(int j=0; j<com.entryhashes_size(); j++) {
      if(com.entryhashes(j).hash()!=hash.entryhashes(j).hash()) {
	log_error("Hash check failed for truth table\n");
	return false;
      }
    }
  }
  
  //TODO Validate that gates match actual circuit
  
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



yosysZKP::Hash TruthTableEntry_get_commitment(const yosysZKP::TruthTableEntry& e) {
  yosysZKP::Hash h;
  std::string* buf=h.mutable_hash();
  buf->resize(SHA256::DIGESTSIZE);
  
  std::string serialized=e.SerializeAsString();
  SHA256().CalculateDigest((byte*)buf->data(),(byte*)serialized.data(),serialized.length());
  return h;
}

bool TruthTableEntry_verify_computation(const yosysZKP::TruthTableEntry& e, const vector<unsigned char>& i, const vector<unsigned char>& o) {
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

void TruthTableEntry_scramble(RandomNumberGenerator& rand, yosysZKP::TruthTableEntry& e, const std::vector<unsigned char>&i, const std::vector<unsigned char>& o) {
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
  
void TruthTable_scramble(yosysZKP::TruthTable& t, RandomNumberGenerator& rand, const std::vector<unsigned char>& i, const std::vector<unsigned char>& o) {
  
  for(int n=0; n<t.entries_size(); n++) {
    TruthTableEntry_scramble(rand, *t.mutable_entries(n), i, o);
  }
  rand.Shuffle(t.mutable_entries()->begin(), t.mutable_entries()->end());
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
  ex.set_nonce(nonce, NONCE_SIZE);
  return ex;
}
void WireValues::deserialize(const yosysZKP::WireValues& ex) {
  map.clear();
  for(const yosysZKP::WireValues_Entry& entry : ex.entries()) {
    map[m->wire(IdString(entry.wirename()))]=entry.value();
  }
  memmove(nonce, ex.nonce().data(), NONCE_SIZE);
}

ScrambledCircuit::ScrambledCircuit(Module* module): rand(true), m(module), sigmap(m),execution(m), keys(m) {
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
    std::vector<unsigned char> inputkey;
    std::vector<unsigned char> outputkey;
    for(auto& it:cell->connections()) {
      bool input=cell->input(it.first);
      bool output=cell->output(it.first);
      log_assert(input || output);
      SigSpec con=sigmap(it.second);
      for(const SigBit& b:con) {
	char bit=0;
	if(b.wire!=nullptr){
	  bit=keys.map[b.wire];
	}
	if(input) {
	  inputkey.push_back(bit);
	} else {
	  outputkey.push_back(bit);
	}
      }
      gates[cell->name]=gatesdef[cell->name];
      log("ok1\n");
      TruthTable_check(gatesdef[cell->name]);
      log("ok2\n");
      TruthTable_scramble(gates[cell->name], rand, inputkey, outputkey);
      TruthTable_check(gates[cell->name]);
    }
  }
  printf("step2\n");
  serializeState();
  printf("step3\n");
}

void ScrambledCircuit::serializeState() {
  *serializedState.mutable_keys()=keys.serialize();
  
  serializedState.clear_exec();
  for(const auto& it:execution.map) {
    bool bit=keys.map[it.first]^ it.second;
    yosysZKP::WireValues_Entry* e=serializedState.mutable_exec()->add_entries();
    e->set_wirename(it.first->name.str());
    e->set_value(bit);
  }
  
  *serializedState.mutable_exec()=execution.serialize();

  for(Cell * cell:m->cells()) {
    *serializedState.add_gates()=gates[cell->name];
  }
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
  *exec.mutable_exec()=serializedState.exec();

  for(Cell* cell: m->cells()) {
    const yosysZKP::TruthTable& g=gates[cell->name];

    std::vector<unsigned char> inputs;
    std::vector<unsigned char> outputs; 

    for(const auto& it: cell->connections()) {
      bool inp=cell->input(it.first);
      bool outp=cell->output(it.first);
      log_assert(inp ^ outp);
      SigSpec conns=sigmap(it.second);
      for(const SigBit& b:conns) {
	unsigned char bit;
	if(b.wire!=nullptr) {
	  log("bit %d key %d ",execution.map[b.wire], keys.map[b.wire]);
	  bit=execution.map[b.wire] ^ keys.map[b.wire];
	} else {
	  bit= (b.data==State::S1);
	}
	if(inp) {
	  log(" inp wire is %s\n",log_id(b.wire->name));
	  inputs.push_back(bit);
	}
	if(outp) {
	  log(" outp wire is %s\n",log_id(b.wire->name));
	  outputs.push_back(bit);
	}
      }
    }
    int count=0;
    printf("Entries size %d\n",g.entries_size());
    for(const yosysZKP::TruthTableEntry& e: g.entries()) {
      printf("checking input \n%s\n",e.DebugString().c_str());
      
      for(size_t i=0; i<inputs.size(); i++)
	if(e.inputs(i) !=inputs[i]) 
	  goto loop_continue;
      printf("matches outp %d\n",outputs[0]);
      for(size_t i=0; i<outputs.size(); i++)
	if(e.outputs(i) != outputs[i])
	  log_error("Error, truth table does not match computed execution for cell %s %s\n",log_id(cell->type), log_id(cell->name));
	
      *exec.add_entries()=e;
      count++;
    }
    if(count!=1) {
      log_error("Truth table contains multiple entries for the same inputs\n");
    }
  loop_continue: ;
  }
  return exec;
}

yosysZKP::ScramblingReveal ScrambledCircuit::reveal_scrambling() {
  yosysZKP::ScramblingReveal scr;
  *scr.mutable_keys()=serializedState.keys();
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
  

  printf("Execution Reveal %s \n",exec.DebugString().c_str());
  Yosys::yosys_shutdown();
  return 0;
}
