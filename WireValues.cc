#include "WireValues.h"


USING_YOSYS_NAMESPACE

WireValues::WireValues(Module* module):m(module) {

}
yosysZKP::WireValues WireValues::serialize()  const {
  yosysZKP::WireValues ex;
  for(const auto& it : map) {
    ex.add_entries(it.second);
  }
  
  return ex;
}
void WireValues::deserialize(const yosysZKP::WireValues& ex) {
  map.clear();
  int i=0;
  for(const auto& it:m->wires()) {
    map[it->name]=ex.entries(i++);
  }
  map.sort();
}
