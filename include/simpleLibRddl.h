#pragma once

#define PUB_KEY_SIZE 33
#define ADDRESS_HASH_SIZE 20
#define ADDRESS_TAIL 20
#define EXT_PUB_KEY_SIZE 112 

#define PLANETMINT_PMPB 0x03E14247
#define PLANETMINT_PMPR 0x03E142B0

#define VERSION_PUBLIC 0x0488b21e
#define VERSION_PRIVATE 0x0488ade4

bool getPlntmntKeys();

constexpr uint32_t planetmint_path[] = {
    BIP32_INITIAL_HARDENED_CHILD+44,
    BIP32_INITIAL_HARDENED_CHILD+8680,
    BIP32_INITIAL_HARDENED_CHILD+0,
    0,
    0
};

constexpr uint32_t rddl_path[] = {
    BIP32_INITIAL_HARDENED_CHILD+44,
    BIP32_INITIAL_HARDENED_CHILD+1776,
    BIP32_INITIAL_HARDENED_CHILD+0,
    0,
    0
};


extern uint8_t sdk_priv_key_planetmint[32+1];
extern uint8_t sdk_priv_key_liquid[32+1];
extern uint8_t sdk_pub_key_planetmint[33+1];
extern uint8_t sdk_pub_key_liquid[33+1];
extern uint8_t sdk_machineid_public_key[33+1]; 

extern char sdk_address[128];
extern char sdk_ext_pub_key_planetmint[EXT_PUB_KEY_SIZE+1];
extern char sdk_ext_pub_key_liquid[EXT_PUB_KEY_SIZE+1];
extern char sdk_machineid_public_key_hex[33*2+1];
extern char tempSeed[64];