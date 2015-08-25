#include "WireValues.h"


USING_YOSYS_NAMESPACE

WireValues::WireValues(Module* module):m(module) {

}
yosysZKP::WireValues WireValues::serialize()  const {
  yosysZKP::WireValues ex;
  for(const auto& it : map) {
    yosysZKP::WireValues_Entry* entry=ex.add_entries();
    IdString wirename=it.first->name;
    entry->set_wirename(wirename.str());
    entry->set_value(it.second);
  }

  return ex;
}
void WireValues::deserialize(const yosysZKP::WireValues& ex) {
  map.clear();
  for(const yosysZKP::WireValues_Entry& entry : ex.entries()) {
    map[m->wire(IdString(entry.wirename()))]=entry.value();
  }
}
