#include "secp256k1.h"
#include "wally_bip32.h"
#include "wally_bip39.h"
#include "wally_crypto.h"
#include "wally_address.h"
#include "simpleLibRddl.h"
#include "utils.h"

extern "C"{
    #include "ccan/ccan/crypto/sha256/sha256.h"
    #include "ccan/ccan/crypto/ripemd160/ripemd160.h"
}


uint8_t sdk_priv_key_planetmint[32+1] = {0};
uint8_t sdk_priv_key_liquid[32+1] = {0};
uint8_t sdk_pub_key_planetmint[33+1] = {0};
uint8_t sdk_pub_key_liquid[33+1] = {0};
uint8_t sdk_machineid_public_key[33+1]={0}; 

char sdk_address[64] = {0};
char sdk_ext_pub_key_planetmint[EXT_PUB_KEY_SIZE+1] = {0};
char sdk_ext_pub_key_liquid[EXT_PUB_KEY_SIZE+1] = {0};
char sdk_machineid_public_key_hex[33*2+1] = {0};

char tempSeed[64] = {0};

ext_key *node_root;
ext_key *node_planetmint;
ext_key *node_rddl;


void printHexVal(OSCMessage& resp_msg, char* data, int len){
    String hexStrPrivKey;
    hexStrPrivKey = toHex((const uint8_t *)data, len);
    
    resp_msg.add(hexStrPrivKey.c_str());
    sendOSCMessage(resp_msg);
}


void pubkey2address(const uint8_t *pubkey, size_t key_length, uint8_t *address){
    unsigned char out[32];
    struct sha256 sha;
    memset(&sha, 0, sizeof(struct sha256));
    sha256(&sha, pubkey, key_length);
    struct ripemd160 hash160;
    ripemd160(&hash160, &sha, sizeof(sha));
    memcpy(address, hash160.u.u8, 20);
}


int getAddressString(const uint8_t *address, char *stringbuffer)
{
    return 0;
}


inline void write_be(uint8_t *data, uint32_t x) {
  data[0] = x >> 24;
  data[1] = x >> 16;
  data[2] = x >> 8;
  data[3] = x;
}


void hdnode_serialize_public(const ext_key *node, uint32_t fingerprint,
                            uint32_t version, char use_public, char *str,
                            int strsize){
    uint8_t node_data[78];
    memzero(node_data, sizeof(node_data));
    write_be(node_data, version);
    node_data[4] = node->depth;
    //write_be(node_data + 5, fingerprint);
    memcpy(node_data + 5, (char*)&fingerprint, FINGERPRINT_LEN);
    write_be(node_data + 9, node->child_num);
    memcpy(node_data + 13, node->chain_code, 32);
    if (use_public) {
        memcpy(node_data + 45, node->pub_key, 33);
    } else {
        node_data[45] = 0;
        memcpy(node_data + 46, &node->priv_key[1], 32);
    }
    char *out;
    wally_base58_from_bytes(node_data, sizeof(node_data), BASE58_FLAG_CHECKSUM, &out);
    strcpy(str, out);
    wally_free_string(out);
    return;
}


uint8_t private_key_machine_id[32] = { 0x52, 0x44, 0x44, 0x4c, 0x52, 0x44, 0x44, 0x4c, 0x52, 0x44, 0x44, 0x4c,\
                                       0x52, 0x44, 0x44, 0x4c, 0x52, 0x44, 0x44, 0x4c, 0x52, 0x44, 0x44, 0x4c,\
                                       0x52, 0x44, 0x44, 0x4c, 0x52, 0x44, 0x44, 0x4c };


bool getPlntmntKeys(){
    OSCMessage resp_msg("/seedGet");

    uint8_t bytes_out[BIP39_SEED_LEN_512];
    int res = bip32_key_from_seed_alloc((const unsigned char*)tempSeed, 64, BIP32_VER_MAIN_PRIVATE, 0, &node_root);

    bip32_key_from_parent_path_alloc(node_root, planetmint_path, 5, BIP32_FLAG_KEY_PRIVATE, &node_planetmint);
    bip32_key_from_parent_path_alloc(node_root, rddl_path, 5, BIP32_FLAG_KEY_PRIVATE, &node_rddl);
    memcpy(sdk_priv_key_planetmint, &node_planetmint->priv_key[1], 32);
    memcpy(sdk_pub_key_planetmint,   node_planetmint->pub_key,     33);
    memcpy(sdk_priv_key_liquid,     &node_rddl->priv_key[1],       32);
    memcpy(sdk_pub_key_liquid,       node_rddl->pub_key,           33);

    uint8_t address_bytes[ADDRESS_TAIL] = {0};
    pubkey2address( sdk_pub_key_planetmint, PUB_KEY_SIZE, address_bytes );
    getAddressString( address_bytes, sdk_address);

    uint32_t fingerprint;
    res = bip32_key_get_fingerprint(node_planetmint, (unsigned char*)&fingerprint, FINGERPRINT_LEN);
    hdnode_serialize_public(node_planetmint, fingerprint, PLANETMINT_PMPB, 1, sdk_ext_pub_key_planetmint, EXT_PUB_KEY_SIZE);
    hdnode_serialize_public(node_rddl, fingerprint, VERSION_PUBLIC, 1, sdk_ext_pub_key_liquid, EXT_PUB_KEY_SIZE);

    secp256k1_context *ctx = NULL;
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN);
    secp256k1_pubkey pubkey = {0};
    char create_pubkey = 0;
    create_pubkey = secp256k1_ec_pubkey_create(ctx, &pubkey, private_key_machine_id);

    printHexVal(resp_msg, (char *)pubkey.data, 64);

    return true;
}