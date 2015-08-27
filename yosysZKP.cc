#include "ScrambledCircuit.h"

#include "ProverAgent.h"
#include "ProveeAgent.h"


USING_YOSYS_NAMESPACE

Const const_from_file(std::string filename) {
  Const result;
  
  std::ifstream in(filename);
  std::string line;
  while(std::getline(in,line)) {
    for(char c:line) {
      if(c=='1') {
	result.bits.push_back(State::S1);
      }
      if(c=='0') {
	result.bits.push_back(State::S0);
      }	
    }
  }
  return result;
}


std::string get_file_contents(std::string filename)
{
  std::ifstream in(filename, std::ios::in | std::ios::binary);
  if (in)
  {
    std::string contents;
    in.seekg(0, std::ios::end);
    contents.resize(in.tellg());
    in.seekg(0, std::ios::beg);
    in.read(&contents[0], contents.size());
    in.close();
    return(contents);
  }
  throw(errno);
}

int main(int argc, char** argv)
{
  if(argc < 6) {
    printf("Usage:\n");
    printf("%s prover_create file.v module inputs.dat outputs.dat security_param out.secret out.comm \n",argv[0]);
    printf("%s provee_create file.v module outputs.dat security_param in.comm provee.state out.resp\n",argv[0]);
    printf("%s prover_reveal file.v module in.resp in.secret out.reveal\n",argv[0]);
    printf("%s provee_validate file.v module provee.state in.reveal\n",argv[0]);
    return 0;
  }
  
  string filename(argv[2]);
  string modulename(argv[3]);
  Yosys::log_streams.push_back(&std::cout);
  Yosys::log_error_stderr = true;
    
  Yosys::yosys_setup();

  Design* design=yosys_get_design();
  Yosys::run_frontend(filename, "auto", design);
  Pass::call(design, "hierarchy -check");
  Pass::call(design, "splitnets -ports");

  design->sort();
  Module* module=design->module("\\"+modulename);

  string action(argv[1]);
  if(action=="prover_create") {
    if(argc!=9) {
      printf("Wrong number of arguments\n");
      printf("%s prover_create file.v module inputs.dat outputs.dat security_param out.secret out.comm \n",argv[0]);
      return 1;
    }
    ProverAgent agent(module);
    Const inputs=const_from_file(argv[4]);
    Const outputs=const_from_file(argv[5]);
    agent.set_data(inputs, outputs);
    agent.set_security_param(std::atoi(argv[6]));

    std::string out;
    agent.write_commitment_packet(out);
    std::ofstream o(argv[8]);
    o<<out;
    o.close();

    std::string secret;
    agent.save_secret(secret);
    std::ofstream s(argv[7]);
    s<<secret;
    s.close();
  } else if(action=="provee_create") {
    if(argc!=9) {
      printf("Wrong number of arguments\n");
      printf("%s provee_create file.v module outputs.dat security_param in.comm provee.state out.resp\n",argv[0]);
      return 1;
    }
      
    ProveeAgent agent(module);
    Const outputs=const_from_file(argv[4]);
    agent.set_outputs(outputs);
    agent.set_security_param(std::atoi(argv[5]));

    std::string commitment=get_file_contents(argv[6]);
    std::string response;
    agent.read_commitment(commitment, response);

    std::ofstream o(argv[8]);
    o<<response;
    o.close();
    
    std::string state;
    agent.save_state(state);
    std::ofstream s(argv[7]);
    s<<state;
    s.close();
    
  } else if(action=="prover_reveal") {
    if(argc!=7) {
      printf("Wrong number of arguments\n");
      printf("%s prover_reveal file.v module in.resp in.secret out.reveal\n",argv[0]);
      return 1;
    }
      
    ProverAgent agent(module);
    std::string response=get_file_contents(argv[4]);
    std::string secret=get_file_contents(argv[5]);
    agent.read_secret(secret);

    std::string reveal;
    agent.write_reveal(reveal, response);
    std::ofstream o(argv[6]);
    o<<reveal;
    o.close();

    //Remove the secret because otherwise ppl will do dumb stuff with it like reveal it twice...
    std::remove(argv[5]);
  } else if(action=="provee_validate") {
    if(argc!=6) {
      printf("Wrong number of arguments\n");
      printf("%s provee_validate file.v module provee.state in.reveal\n",argv[0]);
      return 1;
    }
    ProveeAgent agent(module);
    std::string state=get_file_contents(argv[4]);
    agent.read_state(state);

    std::string reveal=get_file_contents(argv[5]);
    agent.read_reveal(reveal);

    if(agent.proven()) {
      printf("PROVEN\n");
    } else {
      printf("ERROR: NOT PROVEN\n");
    }
  } else {
    printf("unknown action\n");
  }
  Yosys::yosys_shutdown();
  return 0;
}
