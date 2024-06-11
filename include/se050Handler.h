#ifdef DSE050

#pragma once

#include <vector>
#include "OSCMessage.h"


#define SE050_USED_SLOT     100

constexpr int SEED_SLOT             = SE050_USED_SLOT;
constexpr int NISTP_KEY_1_SLOT      = SE050_USED_SLOT + 1;
constexpr int NISTP_KEY_2_SLOT      = SE050_USED_SLOT + 2;
constexpr int SECP256_KEY_1_SLOT    = SE050_USED_SLOT + 3;
constexpr int SECP256_KEY_2_SLOT    = SE050_USED_SLOT + 4;
constexpr int BINARY_RW_1_SLOT      = SE050_USED_SLOT + 5;
constexpr int BINARY_RW_2_SLOT      = SE050_USED_SLOT + 6;
constexpr int BINARY_READ_SIZE      = 64;
constexpr int DEFAULT_DELETABLE_FLAG = 1; // 0: Permanent, 1: Transient

void routeSE050EncryptData(OSCMessage &msg, int addressOffset);
void routeSE050DecryptData(OSCMessage &msg, int addressOffset);
void routeSe050SetSeed(OSCMessage &msg, int addressOffset);
void routeSe050GetSeed(OSCMessage &msg, int addressOffset);
void routeSe050CreateKeyPair(OSCMessage &msg, int addressOffset);
void routeSe050GetPublicKey(OSCMessage &msg, int addressOffset);
void routeSe050CalculateHash(OSCMessage &msg, int addressOffset);
void routeSe050SignData(OSCMessage &msg, int addressOffset);
void routeSe050VerifySignature(OSCMessage &msg, int addressOffset);
int se050InjectSECPKeys(int keyID, std::vector<uint8_t>& privKey, std::vector<uint8_t>& pubKey);
int se050SetSeed(const char* seedStr, int seedLen, int deletable, char* errMsg);
std::vector<uint8_t> se050GetSeed();

class Se050Middleware;
extern Se050Middleware se050_handler_o; 

#endif