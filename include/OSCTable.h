#include "keyFuncs.h"

constexpr std::pair<const char*, void(*)(OSCMessage&, int)> osc_func_table[] = {
    {"/IHW/setSeed",    &routeSetSeed},
    {"/IHW/getSeedGet", &routeGetSeed},
    {"/IHW/mnemonicToSeed", &routeMnemonicToSeed},
    {"/IHW/getPlntmntKeys", &routeGetPlntmntKeys}
};