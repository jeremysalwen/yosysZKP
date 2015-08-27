#include "ProverAgent.h"

#include "messages.pb.h"

USING_YOSYS_NAMESPACE

ProverAgent::ProverAgent(Module* m) : circuit(m), security_param(128) {}

void ProverAgent::set_data(Const in, Const out) {
  Const o=circuit.execute(in);
  if(o!=out) {
    log("%s\n",o.as_string().c_str());
    throw std::runtime_error("Input does not produce required output\n");
  }
}

void ProverAgent::set_security_param(int p) {
  security_param=p;
}

void ProverAgent::save_secret(std::string& out) {
  state.SerializeToString(&out);
}
void ProverAgent::read_secret(const std::string& in) {
  state.ParseFromString(in);
}
  
void ProverAgent::write_commitment_packet(std::string& out) {
  yosysZKP::Commitments result;

  for(int i=0; i<security_param; i++) {
    *result.add_rounds()=circuit.createProofRound();
    
    yosysZKP::ProverSecret* round= state.add_round();
    *round->mutable_execution()=circuit.reveal_execution();
    *round->mutable_scrambling()=circuit.reveal_scrambling();
  }
  result.SerializeToString(&out);
}
void ProverAgent::write_reveal(std::string& out, const std::string& response) {
  yosysZKP::RevealRequest request;
  request.ParseFromString(response);

  if(request.scrambling_size()!=state.round_size()) {
    throw std::runtime_error("Provee request does not match security parameter of commitment\n");
  }
  
  yosysZKP::ProverState reveal;
  for(int i=0; i<request.scrambling_size(); i++) {
    yosysZKP::ProverSecret* secret=reveal.add_round();
    if(request.scrambling(i)) {
      *secret->mutable_scrambling()=state.round(i).scrambling();
    } else {
      *secret->mutable_execution()=state.round(i).execution();
    }
  }
  reveal.SerializeToString(&out);
  /* 
   * Importantly, this agent should forget anything about the rounds its already revealed
   * ideally we could delete EVERY copy of the data here, but we just have to trust
   * callers to be responsible
   */
  state.clear_round();
}
