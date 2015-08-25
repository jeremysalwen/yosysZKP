all: yosysZKP

yosysZKP: yosysZKP.cc messages.pb.h ScrambledCircuit.cc WireValues.cc TruthTable.cc
	yosys-config --exec --cxx -o yosysZKP --cxxflags --ldflags -g yosysZKP.cc messages.pb.cc  ScrambledCircuit.cc WireValues.cc TruthTable.cc -lyosys -lcrypto++ -lprotobuf -lstdc++ -std=c++11

messages.pb.h: messages.proto
	protoc --cpp_out=. messages.proto
