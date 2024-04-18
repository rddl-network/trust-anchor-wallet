#include "seedFuncs.h"

constexpr std::pair<const char*, void(*)(OSCMessage&, int)> osc_func_table[] = {
    {"/IHW/seedSet", &routeSeedSet},
    {"/IHW/seedGet", &routeSeedGet},
    {"/IHW/mnemonicToSeed", &routeMnemonicToSeed}
};