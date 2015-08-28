#include "Protocol.h"

#include "ScrambledCircuit.h"


#include <google/protobuf/io/zero_copy_stream_impl.h>
#include <google/protobuf/io/coded_stream.h>

USING_YOSYS_NAMESPACE
using namespace google::protobuf::io;

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


Module* load_module(std::string filename, std::string modulename) {
  Design* design=yosys_get_design();
  Yosys::run_frontend(filename, "auto", design);
  Pass::call(design, "hierarchy -check");
  Pass::call(design, "splitnets -ports");

  design->sort();

  Module* result=design->module("\\"+modulename);
  if(result==nullptr) {
    log_error("Could not find module %s in file\n",modulename.c_str());
  }
  return result;
}



int main(int argc, char** argv)
{
  if(argc < 5) {
    printf("Usage:\n");
    printf("%s prover_create file.v module inputs.dat outputs.dat security_param out.secret out.comm \n",argv[0]);
    printf("%s provee_respond in.comm provee.state out.resp\n",argv[0]);
    printf("%s prover_reveal in.secret in.resp out.reveal\n",argv[0]);
    printf("%s provee_validate file.v module outputs.dat security_param provee.state in.reveal\n",argv[0]);
    return 0;
  }
  
  Yosys::log_streams.push_back(&std::cout);
  Yosys::log_error_stderr = true;
    
  Yosys::yosys_setup();

  string action(argv[1]);
  if(action=="prover_create") {
    if(argc!=9) {
      printf("Wrong number of arguments\n");
      printf("%s prover_create file.v module inputs.dat outputs.dat security_param out.secret out.comm \n",argv[0]);
      return 1;
    }
    Module* module=load_module(argv[2], argv[3]);
    ScrambledCircuit circuit(module);
    Const inputs=const_from_file(argv[4]);
    Const outputs=const_from_file(argv[5]);

    Const out=circuit.execute(inputs);
    if(out!=outputs) {
      log_error("Input produces output %s instead of required value\n",out.as_string().c_str());
    }

    int security_param=atoi(argv[6]);

    CodedFileWriter ss(argv[7],MAGIC_SECRET);
    CodedFileWriter cs(argv[8],MAGIC_COMMITMENT);
    
    for(int i=0; i<security_param; i++) {
      yosysZKP::Commitment comm=circuit.create_proof_round();
      cs.WriteToStream(&comm);
      
      yosysZKP::ProverSecret sec;
      *sec.mutable_execution()=circuit.reveal_execution();
      *sec.mutable_scrambling()=circuit.reveal_scrambling();

      ss.WriteToStream(&sec);
    }

  } else if(action=="provee_respond") {
    if(argc!=5) {
      printf("Wrong number of arguments\n");
      printf("%s provee_respond in.comm provee.state out.resp\n",argv[0]);
      return 1;
    }

    CryptoPP::AutoSeededRandomPool rand;

    CodedFileReader is(argv[2],MAGIC_COMMITMENT);
    CodedFileWriter os(argv[3],MAGIC_PROVEE);

    yosysZKP::RevealRequest request;
    yosysZKP::ProveeState roundstate;
    while(is.ReadFromStream(roundstate.mutable_commitment())) {
      
      bool scrambled= rand.GenerateBit();
      roundstate.set_scrambling(scrambled);

      os.WriteToStream(&roundstate);
      
      request.add_scrambling(scrambled);
    }

    CodedFileWriter ros(argv[4],MAGIC_REQUEST);

    ros.WriteToStream(&request);

  } else if(action=="prover_reveal") {
    if(argc!=5) {
      printf("Wrong number of arguments\n");
      printf("%s prover_reveal in.secret in.resp out.reveal\n",argv[0]);
      return 1;
    }
    CodedFileReader sis(argv[2],MAGIC_SECRET);
    CodedFileReader ris(argv[3],MAGIC_REQUEST);

    CodedFileWriter os(argv[4],MAGIC_REVEAL);

    yosysZKP::RevealRequest request;
    ris.ReadFromStream(&request);

    yosysZKP::ProverSecret secret;
    for(bool b:request.scrambling()) {
      sis.ReadFromStream(&secret);

      if(b) { //Clear the field we don't want to reveal
	secret.clear_execution();
      } else {
	secret.clear_scrambling();
      }
	os.WriteToStream(&secret);
    }
    
    //Remove the secret because otherwise ppl will do dumb stuff with it like reveal it twice...
    std::remove(argv[2]);
  } else if(action=="provee_validate") {
    if(argc!=8) {
      printf("Wrong number of arguments\n");
       printf("%s provee_validate file.v module outputs.dat security_param provee.state in.reveal\n",argv[0]);
      return 1;
    }
    Module* module=load_module(argv[2], argv[3]);
    ScrambledCircuit circuit(module);

    Const outputs=const_from_file(argv[4]);
    int security_param=atoi(argv[5]);

    CodedFileReader ss(argv[6],MAGIC_PROVEE);
    CodedFileReader rs(argv[7],MAGIC_REVEAL);

    int count=0;

    yosysZKP::ProveeState state;
    yosysZKP::ProverSecret secret;

    while(ss.ReadFromStream(&state)) {
      if(state.commitment().output_size()!=outputs.size()) {
	log_error("Outputs do not match requirements\n");
      }
      for(int i=0; i<outputs.size(); i++) {
	if((outputs[i]==State::S1)!=state.commitment().output(i)) {
	  log_error("Outputs do not match requirements\n");
	}
      }

      if(!rs.ReadFromStream(&secret)) {
	log_error("Mismatch between commitment and reveal!\n");
      }

      bool validated;
      if(state.scrambling()) {
	validated=circuit.validate_precommitment(state.commitment(), secret.scrambling());
      } else {
	validated=circuit.validate_precommitment(state.commitment(), secret.execution());
      }
      if(!validated) {
	log_error("Proof round did not validate\n");
      }
      count++;
    }

    if(count>=security_param) {
      log("SUCCESS: Proven with confidence 2^-%d\n",count);
    } else {
      log_error("Not enough proof rounds to satisfy security requirement\n");
    }

  } else {
    log_error("Unkown action %s\n",action.c_str());
  }

Yosys::yosys_shutdown();
  return 0;
}
