#include <iostream>
#include <string>
#include <vector>
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
#include "se050Handler.h"

int valiseSetSeed(const char* seed){
    Preferences valise;

    valise.begin("vault", false);
    valise.putString("seed", seed);
    valise.end();

    return BIP39_SEED_LEN_512;
}


String valiseGetSeed(){
    Preferences valise; 

    valise.begin("vault", false);
    String seedStr = valise.getString("seed", "");
    valise.end();

    return seedStr;
}


int GenericSetSeed(const char* seed, int seedLen, int deletable, char* errMsg){
    auto writtenLen{0};

#ifdef DSE050
    writtenLen = se050SetSeed(seed, seedLen, deletable, errMsg);
#else
    if(seedLen != (BIP39_SEED_LEN_512*2 + 1)){
        strcpy(errMsg, "ERROR! Seed size must be 64! Seed String size must be 128");
        return 0;
    }

    writtenLen = valiseSetSeed(seed);
#endif

    return writtenLen;
}


std::vector<uint8_t> GenericGetSeed(){

#ifdef DSE050
    auto seed = se050GetSeed();
#else
    auto seedPtr = fromhex(valiseGetSeed().c_str());
    std::vector<uint8_t> seed( seedPtr, seedPtr + BIP39_SEED_LEN_512);
    if(std::all_of(seed.begin(), seed.end(), [](int i) { return i==0; })){
        seed.resize(0);
    }
#endif
    return seed;
}


/**
 * Store the base seed inside the trust anchor's memory
 *
 * @param string(0) String type data in Hex format
 * @param string(1) <optional> Deletable Flag for SE050 only. 0: Permanent Seed  
 *                                                            1: Transient Seed
 * 
 * @return(0) written data size as string
 * @return(1) Error message if any 
 */
void routeSetSeed(OSCMessage &msg, int addressOffset)
{
    OSCMessage resp_msg("/setSeed");
    char seed[256];
    int seedLen{0}, writtenSize{0};
    int deletable = 1;
    char errMsg[100] = {0};
 
    if (msg.isString(0))
    {
        seedLen = msg.getDataLength(0);
        msg.getString(0, seed, seedLen);

        if (msg.isInt(1))
        {
           deletable = msg.getInt(1);
        }

        writtenSize = GenericSetSeed(seed, seedLen, deletable, errMsg);
    }

    resp_msg.add(String(writtenSize).c_str());
    resp_msg.add(errMsg);
    sendOSCMessage(resp_msg);
}


/**
 * Get the base seed from the trust anchor's memory
 *
 * @param String(0) empty string for future use
 * @return The stored base seed. Sending over OSC as string
 */
void routeGetSeed(OSCMessage &msg, int addressOffset)
{
    OSCMessage resp_msg("/getSeed");
    
    auto readData = GenericGetSeed();

    String hexStr;
    hexStr = toHex(readData.data(), readData.size());
    resp_msg.add(hexStr.c_str());
    sendOSCMessage(resp_msg);
}


/**
 * Get the base seed from the trust anchor's memory
 * @param int(0) <optional> Deletable Flag for SE050 only. 0: Permanent Seed
 *                                                         1: Transient Seed
 * @param String(1) <optional> Mnemonic. If it is NULL, the function generate one
 * @param String(2) <optional> Passphrase. 
 * 
 * @return(0) Mnemonic as a string
 * @return(1) Error message if any
 */
void routeMnemonicToSeed(OSCMessage &msg, int addressOffset)
{
    int res; 
    size_t len;
    uint8_t bytes_out[BIP39_SEED_LEN_512];
    char mnemonic[256];
    char passPhrase[64] = "";
    int deletable = 1;  
    char errMsg[100] = {0};
    OSCMessage resp_msg("/mnemonicToSeed");


    if (msg.isInt(0))
    {
        deletable = msg.getInt(0);
    }

    if (msg.isString(1))
    {
        int length = msg.getDataLength(1);
        msg.getString(1, mnemonic, length);

        if(msg.isString(2))
            msg.getString(2, passPhrase, msg.getDataLength(2));
    }else{
        char *phrase = NULL;
        uint8_t se_rnd[32] = {0};
        esp_fill_random(se_rnd, 32);
        res = bip39_mnemonic_from_bytes(NULL, se_rnd, sizeof(se_rnd), &phrase);
        strcpy(mnemonic, phrase); 
    }

    res = bip39_mnemonic_to_seed(mnemonic, passPhrase, bytes_out, sizeof(bytes_out), &len);
    String hexStr;
    hexStr = toHex(bytes_out, 64);
    valiseSetSeed(hexStr.c_str());
    auto writtenSize = GenericSetSeed(hexStr.c_str(), hexStr.length()+1, deletable, errMsg);
    
    resp_msg.add(mnemonic);
    resp_msg.add(errMsg);

    sendOSCMessage(resp_msg);
}


/**
 * Generates and return Planetmint and Liquid addresses by using Seed
 *
 * @return(0) String sdk_address
 * @return(1) String liquid public key
 * @return(2) String planetmint public key
 * @return(3) String of raw planetmint public key as hex string
 */
void routeGetPlntmntKeys(OSCMessage &msg, int addressOffset)
{
    OSCMessage resp_msg("/getPlntmntKeys");

    auto seed = GenericGetSeed();
    if(seed.size() != BIP39_SEED_LEN_512){
        resp_msg.add("");
        resp_msg.add("");
        resp_msg.add("");
        resp_msg.add("");
    }else{
        getPlntmntKeys(reinterpret_cast<char*>(seed.data()));

        String hexStrPubKey;
        hexStrPubKey = toHex((const uint8_t *)sdk_pub_key_planetmint, 33);

        resp_msg.add(sdk_address);
        resp_msg.add(sdk_ext_pub_key_liquid);
        resp_msg.add(sdk_ext_pub_key_planetmint);
        resp_msg.add(hexStrPubKey.c_str());
    }
    sendOSCMessage(resp_msg);
}


/**
 * Sign the hash of given data with liquid priv key
 *
 * @param String(0) Data to be signed in hex format
 * 
 * @return The signature in string format and signature result 0 means successfull verification.
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

    char* t = (char*)fromhex(data);
    unsigned char hash[32] = {0};
    memcpy( hash, t, 32);

    auto seed = GenericGetSeed();
    if(seed.size() != BIP39_SEED_LEN_512){
        resp_msg.add("");
        resp_msg.add("");
    }else{
        getPlntmntKeys(reinterpret_cast<char*>(seed.data()));

        uint8_t bytes_out[EC_SIGNATURE_LEN];
        int res = wally_ec_sig_from_bytes( sdk_priv_key_liquid, 32,
                                            hash, 32, EC_FLAG_ECDSA,
                                            bytes_out, EC_SIGNATURE_LEN);

        if(res == WALLY_OK)
            res = wally_ec_sig_verify(sdk_pub_key_liquid, 33, hash, 32, EC_FLAG_ECDSA, bytes_out, EC_SIGNATURE_LEN);

        String hexStr;
        hexStr = toHex(bytes_out, EC_SIGNATURE_LEN);

        resp_msg.add(hexStr.c_str());
        resp_msg.add(String(res).c_str());
    }
    sendOSCMessage(resp_msg);
} 


/**
 * Sign the hash of given data with planetmint priv key
 *
 * @param String(0) Data to be signed in hex format
 * 
 * @return The signature in string format and signature result 0 means successfull verification.
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


    char* t = (char*)fromhex(data);
    unsigned char hash[32] = {0};
    memcpy( hash, t, 32);
    auto seed = GenericGetSeed();
    if(seed.size() != BIP39_SEED_LEN_512){
        resp_msg.add("");
        resp_msg.add("");
    }else{
        getPlntmntKeys(reinterpret_cast<char*>(seed.data()));


        uint8_t bytes_out[EC_SIGNATURE_LEN];
        int res = wally_ec_sig_from_bytes( sdk_priv_key_planetmint, 32,
                                            hash, 32, EC_FLAG_ECDSA,
                                            bytes_out, EC_SIGNATURE_LEN);

        if(res == WALLY_OK)
            res = wally_ec_sig_verify(sdk_pub_key_planetmint, 33, hash, 32, EC_FLAG_ECDSA, bytes_out, EC_SIGNATURE_LEN);
            
        String hexStr;
        hexStr = toHex(bytes_out, EC_SIGNATURE_LEN);

        resp_msg.add(hexStr.c_str());
        resp_msg.add(String(res).c_str());
    }
    sendOSCMessage(resp_msg);
} 

#ifdef DSE050
/**
 * Inject planetmint and liqud keys into se050. 
 * 
 * @param int(0) Slot id of plmnt Key. The liquid key's slot id will be one more than this value. 
 * Ex: if given slot id is 120, planetmint key slot will be 120 and liquid slot will be 121
 * 
 * @return(0) 0 means success. 1 means there is no seed
 *                             2 means fail on planetmint injection
 *                             3 means fail on liquid injection
 */
void routeSe050InjectSECPKeys(OSCMessage &msg, int addressOffset){
    int keyID{-1};
    OSCMessage resp_msg("/se050InjectSECPKeys");

    if (msg.isInt(0)){
        keyID = msg.getInt(0);
    }

    auto seed = GenericGetSeed();
    if(seed.size() != BIP39_SEED_LEN_512){
        resp_msg.add("1");
    }else{
        getPlntmntKeys(reinterpret_cast<char*>(seed.data()));

        std::vector <uint8_t>plmnt_pub_key (sdk_pub_key_planetmint_ext, sdk_pub_key_planetmint_ext + 65);
        std::vector <uint8_t>plmnt_priv_key(sdk_priv_key_planetmint, sdk_priv_key_planetmint + 32);    

        if(se050InjectSECPKeys(keyID, plmnt_priv_key, plmnt_pub_key) == -1){
            resp_msg.add("2");
            sendOSCMessage(resp_msg);
            return;
        }

        std::vector <uint8_t>liquid_pub_key (sdk_pub_key_liquid_ext, sdk_pub_key_liquid_ext + 65);
        std::vector <uint8_t>liquid_priv_key(sdk_priv_key_liquid, sdk_priv_key_liquid + 32);    

        if(se050InjectSECPKeys(keyID + 1, liquid_priv_key, liquid_pub_key) == -1){
            resp_msg.add("3");
            sendOSCMessage(resp_msg);
            return;
        }

        resp_msg.add("0");
    }
    sendOSCMessage(resp_msg);
}
#endif