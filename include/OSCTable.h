#include "keyFuncs.h"
#include "se050.h"

constexpr std::pair<const char*, void(*)(OSCMessage&, int)> osc_func_table[] = {
#ifdef DSE050
    {"/IHW/se050SetSeed", &routeSE050EncryptData},
    {"/IHW/se050GetSeed", &routeSE050DecryptData},
#endif
    {"/IHW/setSeed", &routeSetSeed},
    {"/IHW/getSeed", &routeGetSeed},
    {"/IHW/mnemonicToSeed", &routeMnemonicToSeed},
    {"/IHW/getPlntmntKeys", &routeGetPlntmntKeys},
    {"/IHW/ecdsaSignRddl", &routeSignRddlData},
    {"/IHW/ecdsaSignPlmnt", &routeSignPlmntData}
};