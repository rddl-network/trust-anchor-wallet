#ifdef DOPTIGA

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
    uint32_t ret = 0;
    uint32_t ts = 0;

    /* OPTIGA Trust X support up to 4 contexts to store you private key  */
    uint16_t ctx = 4;
    uint16_t pubKeyLen = 68;
    uint8_t pubKey [68];


    if(msg.isInt(0))
    {
        ctx = msg.getInt(0);
        switch(ctx)
        {
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
                break;
        }
    }

    if(ctx >= 4){
        resp_msg.add("Non valid secret key register\n");
        sendOSCMessage(resp_msg);
        return;
    }

    /*
    * Generate a keypair#1
    */
    ts = millis();
    ret = trustX.generateKeypair(pubKey, pubKeyLen, ctx);
    ts = millis() - ts;


    /* Requirement by Arduino to stream strings back to requestor */
    String hexStr;
    hexStr = toHex(pubKey, pubKeyLen);

    resp_msg.add(hexStr.c_str());
    sendOSCMessage(resp_msg);
}


void routeOptigaTrustXSignMessage(OSCMessage &msg, int addressOffset)
{
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
                Serial.println("\nNon valid secret key register\n");
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

    ts = millis();
    ret = trustX.calculateSignature(hash, hashLen, ctx_s, signature, sigLen);
    //ret = trustX.calculateSignature(hash, hashLen, signature, sigLen);
    ts = millis() - ts;

    /* Verify the signature */
    ts = millis();
    ret = trustX.verifySignature(hash, hashLen, signature, sigLen, pubkey, sizeof(pubkey));
    //ret = trustX.verifySignature(hash, hashLen, signature, sigLen, ifxPublicKey, sizeof(ifxPublicKey));
    ts = millis() - ts;

    char *resp = "true";
    if (ret) {
        resp = "false";
    }

    /* Requirement by Arduino to stream strings back to requestor */
    String hexStr;
    hexStr = toHex(signature, sigLen);

    OSCMessage resp_msg("/optigaTrustXSignMessage");
    resp_msg.add(hexStr.c_str());
    //resp_msg.add(str_hash);
    resp_msg.add(int32_t(sigLen));

    //resp_msg.add(int32_t(response));
    resp_msg.add(resp);
    sendOSCMessage(resp_msg);
}


#endif