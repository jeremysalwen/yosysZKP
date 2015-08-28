#ifndef PROTOCOL_H
#define PROTOCOL_H
#include <kernel/yosys.h>
#include <fstream>
#include <string>
#include <google/protobuf/io/zero_copy_stream_impl.h>
#include <google/protobuf/io/coded_stream.h>

#define MAGIC_COMMITMENT 0x5a4b50434f4d4954
#define MAGIC_SECRET     0x5a4b505345435245
#define MAGIC_PROVEE     0x5a4b505052564545
#define MAGIC_REQUEST    0x5a4b505245515354
#define MAGIC_REVEAL     0x5a4b50525645414c

USING_YOSYS_NAMESPACE

class CodedFileReader {
 private:
  std::ifstream ifs;
  google::protobuf::io::IstreamInputStream iis;
 public:
  google::protobuf::io::CodedInputStream cis;

 CodedFileReader(std::string filename,uint64_t magic) : ifs(filename,std::iostream::binary), iis(&ifs),cis(&iis) {
      uint64_t m;
      cis.ReadLittleEndian64(&m);
      if(m!=magic) {
	log_error("Bad magic number reading file\n");
      }
  }
  template<typename T>
    void ReadFromStream(T* t) {
    uint64_t sz;
    cis.ReadLittleEndian64(&sz);
    google::protobuf::io::CodedInputStream::Limit l=cis.PushLimit(sz);
    t->ParseFromCodedStream(&cis);
    cis.PopLimit(l);
  }
  
};

class CodedFileWriter {
 private:
  std::ofstream of;
  google::protobuf::io::OstreamOutputStream oos;
 public:
  google::protobuf::io::CodedOutputStream cos;

 CodedFileWriter(std::string filename, uint64_t magic) : of(filename,std::iostream::binary), oos(&of), cos(&oos) {
    cos.WriteLittleEndian64(magic);
  }

  template<typename T>
    void WriteToStream(const T* t) {
    cos.WriteLittleEndian64(t->ByteSize());
    t->SerializeToCodedStream(&cos);
  }
};
#endif
