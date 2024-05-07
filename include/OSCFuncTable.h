#include "keyFuncs.h"
#include "se050Handler.h"
#include "optigaHandler.h"

constexpr std::pair<const char*, void(*)(OSCMessage&, int)> osc_func_table[] = {
#ifdef DSE050
    {"/IHW/se050SetSeed",               &routeSe050SetSeed},
    {"/IHW/se050GetSeed",               &routeSe050GetSeed},
    {"/IHW/se050CreateKeyPair",         &routeSe050CreateKeyPair},
    {"/IHW/se050CalculateHash",         &routeSe050CalculateHash},
    {"/IHW/se050SignData",              &routeSe050SignData},
    {"/IHW/se050VerifySignature",       &routeSe050VerifySignature},
#endif
#ifdef DOPTIGA
    {"/IHW/optigaTrustXCreateSecret",   &routeOptigaTrustXCreateSecret},
    {"/IHW/optigaTrustXSignMessage",    &routeOptigaTrustXSignMessage},
#endif
    {"/IHW/setSeed",                    &routeSetSeed},
    {"/IHW/getSeed",                    &routeGetSeed},
    {"/IHW/mnemonicToSeed",             &routeMnemonicToSeed},
    {"/IHW/getPlntmntKeys",             &routeGetPlntmntKeys},
    {"/IHW/ecdsaSignRddl",              &routeSignRddlData},
    {"/IHW/ecdsaSignPlmnt",             &routeSignPlmntData}
};