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

char sdk_address[128] = {0};
char sdk_ext_pub_key_planetmint[EXT_PUB_KEY_SIZE+1] = {0};
char sdk_ext_pub_key_liquid[EXT_PUB_KEY_SIZE+1] = {0};
char sdk_machineid_public_key_hex[33*2+1] = {0};

char tempSeed[64] = {0};

ext_key *node_root;
ext_key *node_planetmint;
ext_key *node_rddl;


uint8_t private_key_machine_id[32] = { 0x52, 0x44, 0x44, 0x4c, 0x52, 0x44, 0x44, 0x4c, 0x52, 0x44, 0x44, 0x4c,\
                                       0x52, 0x44, 0x44, 0x4c, 0x52, 0x44, 0x44, 0x4c, 0x52, 0x44, 0x44, 0x4c,\
                                       0x52, 0x44, 0x44, 0x4c, 0x52, 0x44, 0x44, 0x4c };


void printHexVal(OSCMessage& resp_msg, char* data, int len){
    String hexStrPrivKey;
    hexStrPrivKey = toHex((const uint8_t *)data, len);
    
    resp_msg.add(hexStrPrivKey.c_str());
    sendOSCMessage(resp_msg);
}


void base32_5to8(const uint8_t *in, uint8_t length, uint8_t *out) {
  if (length >= 1) {
    out[0] = (in[0] >> 3);
    out[1] = (in[0] & 7) << 2;
  }

  if (length >= 2) {
    out[1] |= (in[1] >> 6);
    out[2] = (in[1] >> 1) & 31;
    out[3] = (in[1] & 1) << 4;
  }

  if (length >= 3) {
    out[3] |= (in[2] >> 4);
    out[4] = (in[2] & 15) << 1;
  }

  if (length >= 4) {
    out[4] |= (in[3] >> 7);
    out[5] = (in[3] >> 2) & 31;
    out[6] = (in[3] & 3) << 3;
  }

  if (length >= 5) {
    out[6] |= (in[4] >> 5);
    out[7] = (in[4] & 31);
  }
}


void base32_encode_unsafe(const uint8_t *in, size_t inlen, uint8_t *out) {
  uint8_t remainder = inlen % 5;
  size_t limit = inlen - remainder;

  size_t i, j;
  for (i = 0, j = 0; i < limit; i += 5, j += 8) {
    base32_5to8(&in[i], 5, &out[j]);
  }

  if (remainder) base32_5to8(&in[i], remainder, &out[j]);
}


uint32_t bech32_polymod_step(uint32_t pre) {
    uint8_t b = pre >> 25;
    return ((pre & 0x1FFFFFF) << 5) ^
        (-((b >> 0) & 1) & 0x3b6a57b2UL) ^
        (-((b >> 1) & 1) & 0x26508e6dUL) ^
        (-((b >> 2) & 1) & 0x1ea119faUL) ^
        (-((b >> 3) & 1) & 0x3d4233ddUL) ^
        (-((b >> 4) & 1) & 0x2a1462b3UL);
}

static const char* charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
int bech32_encode(char *output, const char *hrp, const uint8_t *data, size_t data_len) {
    uint32_t chk = 1;
    size_t i = 0;
    while (hrp[i] != 0) {
        int ch = hrp[i];
        if (ch < 33 || ch > 126) {
            return 0;
        }

        if (ch >= 'A' && ch <= 'Z') return 0;
        chk = bech32_polymod_step(chk) ^ (ch >> 5);
        ++i;
    }
    if (i + 7 + data_len > 90) return 0;
    chk = bech32_polymod_step(chk);
    while (*hrp != 0) {
        chk = bech32_polymod_step(chk) ^ (*hrp & 0x1f);
        *(output++) = *(hrp++);
    }
    *(output++) = '1';
    for (i = 0; i < data_len; ++i) {
        if (*data >> 5) return 0;
        chk = bech32_polymod_step(chk) ^ (*data);
        *(output++) = charset[*(data++)];
    }
    for (i = 0; i < 6; ++i) {
        chk = bech32_polymod_step(chk);
    }
    chk ^= 1;
    for (i = 0; i < 6; ++i) {
        *(output++) = charset[(chk >> ((5 - i) * 5)) & 0x1f];
    }
    *output = 0;
    return 1;
}


inline void write_be(uint8_t *data, uint32_t x) {
  data[0] = x >> 24;
  data[1] = x >> 16;
  data[2] = x >> 8;
  data[3] = x;
}


void getAddressString(const uint8_t *address, char *stringbuffer)
{
     const char *hrp = "plmnt";
    size_t data_len = 32;
    uint8_t paddingbuffer[32] = {0};
    uint8_t base32_enc[100] = {0};
    base32_encode_unsafe(address, 20, base32_enc);

    size_t len = strlen((const char*)base32_enc);
    bech32_encode(stringbuffer, hrp, base32_enc, data_len);
}


void hdnode_serialize_public(const ext_key *node, uint32_t fingerprint,
                            uint32_t version, char use_public, char *str,
                            int strsize){
    uint8_t node_data[78];
    memzero(node_data, sizeof(node_data));
    write_be(node_data, version);
    node_data[4] = node->depth;
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


void pubkey2address(const uint8_t *pubkey, size_t key_length, uint8_t *address){
    unsigned char out[32];
    struct sha256 sha;
    memset(&sha, 0, sizeof(struct sha256));
    sha256(&sha, pubkey, key_length);
    struct ripemd160 hash160;
    ripemd160(&hash160, &sha, sizeof(sha));
    memcpy(address, hash160.u.u8, 20);
}


bool getPlntmntKeys(){
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

    // secp256k1_context *ctx = NULL;
    // ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN);
    // secp256k1_pubkey pubkey = {0};
    // char create_pubkey = 0;
    // create_pubkey = secp256k1_ec_pubkey_create(ctx, &pubkey, private_key_machine_id);

    //printHexVal(resp_msg, (char *)pubkey.data, 64);
    // resp_msg.add(sdk_address);
    // sendOSCMessage(resp_msg);

    bip32_key_free(node_root);
    bip32_key_free(node_planetmint);
    bip32_key_free(node_rddl);

    return true;
}