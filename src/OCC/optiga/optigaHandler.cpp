#ifdef DOPTIGA

#include <sstream>
#include "utils.h"
#include "OPTIGATrustX.h"
#include "optigaHandler.h"


/**
 * Creates key pair in Optiga Trust X
 *
 * @param int(0) Object ID defines which slot will be used. Should be between 0-3
 * 
 * @return Public Key in string type
 */
void routeOptigaTrustXCreateSecret(OSCMessage &msg, int addressOffset)
{
    OSCMessage resp_msg("/optigaTrustXCreateSecret");
    String hexStr{"0"};
    int32_t ctx{4};
    uint16_t pubKeyLen = 68;
    uint8_t pubKey [68] = {0};

    if(msg.isInt(0))
    {
        ctx = msg.getInt(0);
    }

    switch(ctx){
        case 0: 
            ctx = eFIRST_DEVICE_PRIKEY_1; 
            break;
        case 1: 
            ctx = eFIRST_DEVICE_PRIKEY_2; 
            break;
        case 2: 
            ctx = eFIRST_DEVICE_PRIKEY_3; 
            break;
        case 3: 
            ctx = eFIRST_DEVICE_PRIKEY_4; 
            break;
        default: 
            resp_msg.add("Non valid secret key register");
            sendOSCMessage(resp_msg);
            return;
    }
    
    /*
    * Generate a keypair#1
    */
    if(trustX.generateKeypair(pubKey, pubKeyLen, ctx) == 0)
        hexStr = toHex(pubKey, pubKeyLen);

    /* Requirement by Arduino to stream strings back to requestor */
    resp_msg.add(hexStr.c_str());
    sendOSCMessage(resp_msg);
}


/**
 * Sign given data 
 *
 * @param int(0) Object ID defines which slot will be used. Should be between 0-3
 * @param string(1) String type data to be signed in Hex format
 * @param string(2) Public key to verify signature in Hex format
 * 
 * @return(0) String type signature in Hex format
 * @return(1) Integer Signature Len
 * @return(2) String Verify Result
 */
void routeOptigaTrustXSignMessage(OSCMessage &msg, int addressOffset)
{
    OSCMessage resp_msg("/optigaTrustXSignMessage");
    std::ostringstream resp; 
    uint32_t ret = 0;
    uint32_t ts = 0;  /* OPTIGA Trust X support up to 4 contexts to store you private key  */

    char str_hash[65];
    uint8_t hash[32];
    uint16_t hashLen = HASH_LENGTH;

    char str_pubkey[137]; 
    uint8_t pubkey[68];
    uint16_t pubkeyLen = 68; 

    uint8_t signature[SIGN_LENGTH];
    uint16_t sigLen = SIGN_LENGTH;
    uint16_t ctx = 0;
    uint16_t ctx_s = eFIRST_DEVICE_PRIKEY_1;
    uint16_t ctx_v = eDEVICE_PUBKEY_CERT_IFX;

    uint8_t  ifxPublicKey[68];
    trustX.getPublicKey(ifxPublicKey);

    if(msg.isInt(0))
    {
        ctx = msg.getInt(0);
        switch(ctx)
        {
            case 0: 
                ctx_s = eFIRST_DEVICE_PRIKEY_1; 
                ctx_v = eDEVICE_PUBKEY_CERT_IFX;
                break;
            case 1: 
                ctx_s = eFIRST_DEVICE_PRIKEY_2; 
                ctx_v = eDEVICE_PUBKEY_CERT_PRJSPC_1;
                break;
            case 2: 
                ctx_s = eFIRST_DEVICE_PRIKEY_3;
                ctx_v = eDEVICE_PUBKEY_CERT_PRJSPC_2; 
                break;
            case 3: 
                ctx_s = eFIRST_DEVICE_PRIKEY_4;
                ctx_v = eDEVICE_PUBKEY_CERT_PRJSPC_3; 
                break;
            default: 
                resp_msg.add("Non valid secret key register");
                sendOSCMessage(resp_msg);
                return;
        }
    }

    if (msg.isString(1)) 
    {
        int length=msg.getDataLength(1);
        msg.getString(1, str_hash, length);
    };
    memcpy(hash, fromhex(str_hash), 32);

    if (msg.isString(2)) 
    {
        int length=msg.getDataLength(2);
        msg.getString(2, str_pubkey, length);
    };
    memcpy(pubkey, fromhex(str_pubkey), 68);

    /*
    * Get the public key
    */
    trustX.calculateSignature(hash, hashLen, ctx_s, signature, sigLen);

    /* Verify the signature */
    if(trustX.verifySignature(hash, hashLen, signature, sigLen, pubkey, sizeof(pubkey)) == 0)
        resp << "true";
    else
        resp << "false";

    /* Requirement by Arduino to stream strings back to requestor */
    String hexStr;
    hexStr = toHex(signature, sigLen);

    
    resp_msg.add(hexStr.c_str());
    resp_msg.add(int32_t(sigLen));
    resp_msg.add(resp.str().c_str());
    sendOSCMessage(resp_msg);    
}


#endif