#ifdef DSE050

#pragma once

#include <vector>
#include "OSCMessage.h"

void routeSE050EncryptData(OSCMessage &msg, int addressOffset);
void routeSE050DecryptData(OSCMessage &msg, int addressOffset);
void routeSe050SetSeed(OSCMessage &msg, int addressOffset);
void routeSe050GetSeed(OSCMessage &msg, int addressOffset);
void routeSe050CreateKeyPair(OSCMessage &msg, int addressOffset);
void routeSe050CalculateHash(OSCMessage &msg, int addressOffset);
void routeSe050SignData(OSCMessage &msg, int addressOffset);
void routeSe050VerifySignature(OSCMessage &msg, int addressOffset);

#endif