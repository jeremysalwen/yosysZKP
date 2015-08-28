#ifndef WIRE_VALUES_H
#define WIRE_VALUES_H

#include <kernel/yosys.h>

#include "messages.pb.h"

struct WireValues {
  Yosys::Module* m;
  
  Yosys::dict<Yosys::IdString, unsigned char> map;

  WireValues(Yosys::Module* module);
  
  yosysZKP::WireValues serialize()  const;
  void deserialize(const yosysZKP::WireValues& ex);

};

#endif //WIRE_VALUES_H
