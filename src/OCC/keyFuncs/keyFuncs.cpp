#include <Preferences.h>
#include "secp256k1.h"
#include "wally_bip32.h"
#include "wally_bip39.h"
#include "wally_crypto.h"
#include "wally_address.h"

extern "C"{
    #include "ccan/ccan/crypto/sha256/sha256.h"
    #include "ccan/ccan/crypto/ripemd160/ripemd160.h"
}

#include "simpleLibRddl.h"
#include "keyFuncs.h"
#include "utils.h"

void valiseSetSeed(const char* seed){
    Preferences valise;

    valise.begin("vault", false);
    valise.putString("seed", (const char *)seed);
    valise.end();
}


String valiseGetSeed(){
    Preferences valise; 

    valise.begin("vault", false);
    String seed = valise.getString("seed", "");
    valise.end();

    return seed;
}

/**
 * Store the base seed inside the trust anchor's memory
 *
 * @param String(0) The base seed.
 * @param String(1) empty string for future use
 * @return  Generated '0' or '1' string for failure or success. Sending over OSC as string

 */
void routeSetSeed(OSCMessage &msg, int addressOffset)
{
    
    char char_seed[129];

    if (msg.isString(0)){
        int length = msg.getDataLength(0);
        msg.getString(0, char_seed, length);
    }

    valiseSetSeed(char_seed);

    OSCMessage resp_msg("/setSeed");
    resp_msg.add("1");

    sendOSCMessage(resp_msg);
}


/**
 * Get the base seed from the trust anchor's memory
 *
 * @param String(0) empty string for future use
 * @return The stored base seed. Sending over OSC as string
.
 */
void routeGetSeed(OSCMessage &msg, int addressOffset)
{
    OSCMessage resp_msg("/getSeed");

    String seed = valiseGetSeed();
    resp_msg.add(seed.c_str());
    sendOSCMessage(resp_msg);
}


/**
 * Get the base seed from the trust anchor's memory
 *
 * @param String(0) <optional> Mnemonic. If it is NULL, the function generate one
 * @param String(1) <optional> Passphrase. 
 * @return Mnemonic as a string
.
 */
void routeMnemonicToSeed(OSCMessage &msg, int addressOffset)
{
    int res;
    size_t len;
    uint8_t bytes_out[BIP39_SEED_LEN_512];
    char mnemonic[256];
    char passPhrase[64] = "";

    if (msg.isString(0))
    {
        int length = msg.getDataLength(0);
        msg.getString(0, mnemonic, length);

        if(msg.isString(1))
            msg.getString(1, passPhrase, msg.getDataLength(1));
    }else{
        char *phrase = NULL;
        uint8_t se_rnd[32] = {0};
        esp_fill_random(se_rnd, 32);
        res = bip39_mnemonic_from_bytes(NULL, se_rnd, sizeof(se_rnd), &phrase);
        strcpy(mnemonic, phrase);
    }

    res = bip39_mnemonic_to_seed(mnemonic, passPhrase, bytes_out, sizeof(bytes_out), &len);
    valiseSetSeed((const char*)bytes_out);
    OSCMessage resp_msg("/mnemonicToSeed");

    // String hexStr;
    // hexStr = toHex(bytes_out, 64);
    // resp_msg.add(hexStr.c_str());
    resp_msg.add(mnemonic);

    sendOSCMessage(resp_msg);
}


/**
 * Get the base seed from the trust anchor's memory
 *
 * @return The stored base seed. Sending over OSC as string
 */
void routeGetPlntmntKeys(OSCMessage &msg, int addressOffset)
{
    OSCMessage resp_msg("/getPlntmntKeys");

    String seed = valiseGetSeed();
    getPlntmntKeys(seed.c_str());

    resp_msg.add(sdk_address);
    resp_msg.add(sdk_ext_pub_key_planetmint);
    resp_msg.add(sdk_ext_pub_key_liquid);
    //printHexVal(resp_msg, (char *)pubkey.data, 64);
    sendOSCMessage(resp_msg);
}


/**
 * Sign the hash of given data with liquid priv key
 *
 * @param String(0) Data to be signed
 * @return The signature and signature result 
 */
void routeSignRddlData(OSCMessage &msg, int addressOffset)
{
    OSCMessage resp_msg("/ecdsaSignRddl");
    
    char data[512];
    int length = 0;

    if (msg.isString(0))
    {
        length = msg.getDataLength(0);
        msg.getString(0, data, length);
    }

    String seed = valiseGetSeed();
    getPlntmntKeys(seed.c_str());

    struct sha256 sha;
    sha256(&sha, data, length - 1);

    uint8_t bytes_out[EC_SIGNATURE_LEN];
    int res = wally_ec_sig_from_bytes( sdk_priv_key_liquid, 32,
                                        sha.u.u8, 32, EC_FLAG_ECDSA,
                                        bytes_out, EC_SIGNATURE_LEN);

    if(res == WALLY_OK)
        res = wally_ec_sig_verify(sdk_pub_key_liquid, 33, sha.u.u8, 32, EC_FLAG_ECDSA, bytes_out, EC_SIGNATURE_LEN);

    String hexStr;
    hexStr = toHex(bytes_out, EC_SIGNATURE_LEN/2);

    resp_msg.add(hexStr.c_str());
    resp_msg.add(String(res).c_str());
    sendOSCMessage(resp_msg);
} 


/**
 * Sign the hash of given data with planetmint priv key
 *
 * @param String(0) Data to be signed
 * @return The signature and signature result 
 */
void routeSignPlmntData(OSCMessage &msg, int addressOffset)
{
    OSCMessage resp_msg("/ecdsaSignPlmnt");
    
    char data[512];
    int length = 0;

    if (msg.isString(0))
    {
        length = msg.getDataLength(0);
        msg.getString(0, data, length);
    }

    String seed = valiseGetSeed();
    getPlntmntKeys(seed.c_str());

    struct sha256 sha;
    sha256(&sha, data, length - 1);

    uint8_t bytes_out[EC_SIGNATURE_LEN];
    int res = wally_ec_sig_from_bytes( sdk_priv_key_planetmint, 32,
                                        sha.u.u8, 32, EC_FLAG_ECDSA,
                                        bytes_out, EC_SIGNATURE_LEN);

    if(res == WALLY_OK)
        res = wally_ec_sig_verify(sdk_pub_key_planetmint, 33, sha.u.u8, 32, EC_FLAG_ECDSA, bytes_out, EC_SIGNATURE_LEN);
        
    String hexStr;
    hexStr = toHex(bytes_out, EC_SIGNATURE_LEN/2);

    resp_msg.add(hexStr.c_str());
    resp_msg.add(String(res).c_str());
    sendOSCMessage(resp_msg);
} 