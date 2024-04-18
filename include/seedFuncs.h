#pragma once

#include "OSCMessage.h"
#include "wally_bip32.h"

void routeSeedSet(OSCMessage &msg, int addressOffset);
void routeSeedGet(OSCMessage &msg, int addressOffset);
void routeMnemonicToSeed(OSCMessage &msg, int addressOffset);


