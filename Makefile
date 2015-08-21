all: yosysZKP

yosysZKP: yosysZKP.cc sha256.cpp
	yosys-config --exec --cxx -o yosysZKP --cxxflags --ldflags yosysZKP.cc  -lyosys -lcrypto++ -lstdc++ -std=c++11
