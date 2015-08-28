#include "TruthTable.h"

#include <crypto++/sha.h>
#include <kernel/consteval.h>

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
	log_error("Truth Table integrity check failed\n");
    }
  }
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

      }

    for (auto &c : out_chunks_r)
      {
	SigSpec s(c), u;
	bool ok = ce.eval(s, u);

	if (!ok)
	  log_error("Can't evaluate %s: Missing value for %s!\n",
		    log_signal(s), log_signal(u));

	Const outval=s.as_const();
	for(State st: outval.bits) {
	  entry->add_outputs(st==State::S1);
	}
      }

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
  if(i.size()!=(unsigned)e.inputs_size() || o.size() != (unsigned)e.outputs_size()) {
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

  for(int i=0; i<entry.inputs_size(); i++)
    unscrambledinp.push_back(entry.inputs(i)^inputkey[i]);
  for(int i=0; i<entry.outputs_size(); i++)
    unscrambledoutp.push_back(entry.outputs(i)^outputkey[i]);
  int min=0, max=tt.entries_size()-1;

  while(max>min) {
    int ave=min+(max-min)/2;
    const yosysZKP::TruthTableEntry& compentry=tt.entries(ave);

    bool equal=true;
    for(int i=compentry.inputs_size()-1; i>=0; i--) {
      if(compentry.inputs(i) && !unscrambledinp[i]) {
	equal=false;
	max=ave-1;
	break;
      }
      if(!compentry.inputs(i) && unscrambledinp[i]) {
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
    return false;
  }
  const yosysZKP::TruthTableEntry& comp=tt.entries(min);
  return TruthTableEntry_verify_computation(comp, unscrambledinp, unscrambledoutp);
}
