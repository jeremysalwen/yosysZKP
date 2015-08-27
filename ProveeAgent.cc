#include "ProveeAgent.h"

USING_YOSYS_NAMESPACE;

ProveeAgent::ProveeAgent(Module* m): circuit(m) {
  state.set_security_param(128);
  state.set_confidence(0);
}

void ProveeAgent::set_outputs(Const outputs) {
  state.clear_output();
  for(State s:outputs.bits) {
    state.add_output(s==State::S1);
  }
}

void ProveeAgent::set_security_param(int p) {
  state.set_security_param(p);
}
void ProveeAgent::save_state(std::string& out) {
  state.SerializeToString(&out);
}
void ProveeAgent::read_state(const std::string& in) {
  state.ParseFromString(in);
}

void ProveeAgent::read_commitment(const std::string& commitment, std::string& response) {

  if(state.request().scrambling_size()!=0) {
    throw std::runtime_error("Attempted to read commitment without completing existing commitments\n"); 
  }
  state.clear_commitment();
  state.clear_request();
  
  state.mutable_commitment()->ParseFromString(commitment);
  int num_rounds=state.commitment().rounds_size();
  for(int i=0; i<num_rounds; i++) {
    bool b=rng.GenerateBit();
    state.mutable_request()->add_scrambling(b);
  }
  state.request().SerializeToString(&response);
}

void ProveeAgent::read_reveal(const std::string& reveal) {
  yosysZKP::ProverState rev;
  rev.ParseFromString(reveal);

  for(int i=0; i<state.request().scrambling_size(); i++) {
    bool validated;
    if(state.request().scrambling(i)) {
      validated= circuit.validate_precommitment(state.commitment().rounds(i), rev.round(i).scrambling());
    } else {
      validated= circuit.validate_precommitment(state.commitment().rounds(i), rev.round(i).scrambling());
    }
    if(!validated) {
      throw std::runtime_error("Proof round did not validate\n");
    }
  }
  state.set_confidence(state.confidence()+state.request().scrambling_size());
}

bool ProveeAgent::proven() {
  return state.confidence()>state.security_param();
}
