#pragma once

#include "OSCMessage.h"
#include "wally_bip32.h"

void routeSetSeed(OSCMessage &msg, int addressOffset);
void routeGetSeed(OSCMessage &msg, int addressOffset);
void routeMnemonicToSeed(OSCMessage &msg, int addressOffset);
void routeGetPlntmntKeys(OSCMessage &msg, int addressOffset);


