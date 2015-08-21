#include <kernel/yosys.h>
#include <kernel/sigtools.h>
#include <kernel/consteval.h>

#include <random>
#include <list>
#include <unordered_map>
#include <map>

#include <crypto++/osrng.h>

USING_YOSYS_NAMESPACE
using namespace CryptoPP;

#define NONCE_SIZE 16

struct TruthTableEntry {
  vector<unsigned char> inputs;
  vector<unsigned char> outputs;

  unsigned char nonce[NONCE_SIZE];

  TruthTableEntry(SigSpec in, SigSpec out) {
    Const inval=in.as_const();
    Const outval=out.as_const();
    inputs.resize(inval.size());
    outputs.resize(outval.size());
    for(int i=0; i<inval.size(); i++) {
      inputs[i]=inval.bits[i]==State::S1;
    }
    for(int i=0; i<outval.size(); i++) {
      outputs[i]=outval.bits[i]==State::S1;
    }
  }
  void hash(unsigned char out[SHA256::DIGESTSIZE]) {
    SHA256 sha;
    sha.Update(inputs.data(),inputs.size());
    sha.Update(inputs.data(), inputs.size());
    sha.Update(nonce, NONCE_SIZE);
    sha.Final(out);
  }
  
  bool verify_hash(unsigned char h[SHA256::DIGESTSIZE]) {
    unsigned char tmp[SHA256::DIGESTSIZE];
    hash(tmp);
    return memcmp(tmp, h, SHA256::DIGESTSIZE)==0;
  }
  bool verify_computation(const vector<unsigned char>& i, const vector<unsigned char>& o) {
    return inputs==i && outputs==o;
  }

  void scramble(const vector<unsigned char>&i, const vector<unsigned char>& o) {
    for(unsigned int n=0; n<inputs.size(); n++){
      inputs[n]^=i[n];
    }
    for(unsigned int n=0; n<outputs.size(); n++){
      outputs[n]^=o[n];
    }
  }
};

struct TruthTable {
  vector<TruthTableEntry> entries;
  void hash(unsigned char* out) {
    for(TruthTableEntry& entry:entries) {
      entry.hash(out);
      out+=SHA256::DIGESTSIZE;
    }
  }

  void scramble(RandomNumberGenerator& rand, const vector<unsigned char>& i, const vector<unsigned char>& o) {
    for(TruthTableEntry& entry: entries) {
      entry.scramble(i, o);
    }
    rand.Shuffle(entries.begin(), entries.end());
  }
};


struct ScrambledCircuit {
  AutoSeededRandomPool rand;
  
  Module* m;

  SigMap sigmap;
  
  /* Indexed by cell name */
  dict<IdString,TruthTable> cells;

  dict<IdString, TruthTable> gates;
  
  dict<Wire*, unsigned char> execution;
  dict<Wire*, unsigned char> keys;
  
  ConstEval ce;

  SigSpec allinputs;
  SigSpec allwires;
  ScrambledCircuit(Module* module): rand(true), m(module), sigmap(m), ce(m) {
    m->sort();
    enumerateWires();
    
    initializeCellTables();
  }
  void enumerateWires() {
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
    for(IdString s:m->ports) {
      allinputs.append(m->wire(s));
    }
  }
  void createProofRound() {
    keys.clear();
    for(auto& it:execution) {
      keys[it.first]=rand.GenerateBit();
    }
    
    gates.clear();
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
	    bit=keys[b.wire];
	  }
	  if(input) {
	    inputkey.push_back(bit);
	  } else {
	    outputkey.push_back(bit);
	  }
	}
	gates[cell->name]=cells[cell->type];
	gates[cell->name].scramble(rand, inputkey, outputkey);
      }
    }
  }
  void execute(Const inputs) {
    ce.push();
    ce.set(allinputs, inputs);
    SigSpec sig_wires=allwires, sig_undef;
    if(!ce.eval(sig_wires, sig_undef)) {
      	    log("Eval failed for execute: Missing value for %s\n", log_signal(sig_undef));
    }
    execution.clear();
    for(int i=0; i<allwires.size(); i++) {
      Wire* w=allwires[i].wire;
      execution[w]=(sig_wires[i]==State::S1);
    }
    ce.pop();
  }
  
  void initializeCellTables() {
    for(Cell* c:m->cells()) {
      auto cit=cells.find(c->type);
      if(cit==cells.end()) {
	TruthTable table;
	
	SigSpec cellin;
	SigSpec cellout;
	for(auto& conn: c->connections()) {
	  if(c->input(conn.first)) {
	    cellin.append(conn.second);
	  }
	  if(c->output(conn.first)) {
	    cellout.append(conn.second);
	  }
	}
	Const constin(0,cellin.size());
	
	while(true) {
	  ce.push();
	  ce.set(cellin, constin);
	  SigSpec constout=cellout, sig_undef;
	  if(ce.eval(constout,sig_undef)) {
	    table.entries.emplace_back(constin,constout);
	  } else {
	    log("Eval failed for A=%s: Missing value for %s\n", log_signal(constin), log_signal(sig_undef));
	  }
	  ce.pop();
	  constin=const_add(constin, Const(1), false, false, constin.size());
	}
	cells[c->type]=table;
      }
    }
  }

 
};


int main()
{
  string filename;
  string modulename;
    Yosys::log_streams.push_back(&std::cout);
  Yosys::log_error_stderr = true;
    
    Yosys::yosys_setup();
    Yosys::yosys_banner();
    Design* design=yosys_get_design();
    Yosys::run_frontend(filename, "auto", design);
    Pass::call(design, "splitnets -ports");
    
    Module* module=design->module(modulename);
    ScrambledCircuit circuit(module);
    
    Yosys::yosys_shutdown();
    return 0;
}
