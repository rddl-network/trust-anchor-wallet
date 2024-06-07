#pragma once

#include "OSCMessage.h"
#include "wally_bip32.h"

void routeSetSeed(OSCMessage &msg, int addressOffset);
void routeGetSeed(OSCMessage &msg, int addressOffset);
void routeMnemonicToSeed(OSCMessage &msg, int addressOffset);
void routeGetPlntmntKeys(OSCMessage &msg, int addressOffset);
void routeSignRddlData(OSCMessage &msg, int addressOffset);
void routeSignPlmntData(OSCMessage &msg, int addressOffset);
void routeSe050InjectSECPKeys(OSCMessage &msg, int addressOffset);


