#include "ScrambledCircuit.h"

#include <google/protobuf/repeated_field.h>


USING_YOSYS_NAMESPACE

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
  yosysZKP::Commitment comm=circuit.createProofRound();  
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
