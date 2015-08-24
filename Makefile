all: yosysZKP

yosysZKP: yosysZKP.cc messages.pb.h
	yosys-config --exec --cxx -o yosysZKP --cxxflags --ldflags yosysZKP.cc messages.pb.cc  -lyosys -lcrypto++ -lprotobuf -lstdc++ -std=c++11

messages.pb.h: messages.proto
	protoc --cpp_out=. messages.proto
