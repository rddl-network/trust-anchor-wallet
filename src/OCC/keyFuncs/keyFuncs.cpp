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


/**
 * Store the base seed inside the trust anchor's memory
 *
 * @param String(0) The base seed.
 * @param String(1) empty string for future use
 * @return  Generated '0' or '1' string for failure or success. Sending over OSC as string

 */
void routeSetSeed(OSCMessage &msg, int addressOffset)
{
    if (msg.isString(0)){
        int length = msg.getDataLength(0);
        msg.getString(0, tempSeed, length);

    }

    OSCMessage resp_msg("/setSeed");
    resp_msg.add(tempSeed);

    sendOSCMessage(resp_msg);
    delay(20);
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
    resp_msg.add(tempSeed);

    sendOSCMessage(resp_msg);
    getPlntmntKeys();
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
    OSCMessage resp_msg("/mnemonicToSeed");

    String hexStr;
    hexStr = toHex(bytes_out, 64);
    resp_msg.add(hexStr.c_str());

    sendOSCMessage(resp_msg);
}


/**
 * Get the base seed from the trust anchor's memory
 *
 * @return The stored base seed. Sending over OSC as string
.
 */
void routeGetPlntmntKeys(OSCMessage &msg, int addressOffset)
{
    OSCMessage resp_msg("/getPlntmntKeys");

    getPlntmntKeys();

    resp_msg.add(sdk_address);
    resp_msg.add(sdk_ext_pub_key_planetmint);
    resp_msg.add(sdk_ext_pub_key_liquid);
    sendOSCMessage(resp_msg);
}
