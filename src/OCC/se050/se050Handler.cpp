#ifdef DSE050

#include "se050_middleware.h"
#include "se050Handler.h"
#include "utils.h"

extern "C"{
    #include "wally_crypto.h"
    #include "ccan/ccan/crypto/sha256/sha256.h"
}

Se050Middleware se050_handler_o{}; 


int se050SetSeed(const char* seedStr, int seedLen, int deletableFlag, char* errMsg){

    if(seedLen != (BINARY_READ_SIZE*2 + 1)){
        strcpy(errMsg, "ERROR! Seed size must be 64! Seed String size must be 128");
        return 0;
    }

    if(se050_handler_o.check_obj_exist(SEED_SLOT)){
        if(!se050_handler_o.delete_obj(SEED_SLOT)){
            strcpy(errMsg, "ERROR! Cannot delete object on the slot!");
            return -1;
        }
    }

    auto seedPtr = fromhex(seedStr);
    std::vector<uint8_t> data( seedPtr, seedPtr + BINARY_READ_SIZE);
    int writtenSize = se050_handler_o.write_binary_data(SEED_SLOT, data, deletableFlag);
    se050_handler_o.read_error_msg(errMsg);

    return writtenSize;
}



/**
 * Write data into SE050
 *
 * @param string(0) Seed in Hex format
 * @param string(1) <optional> Deletable Flag. 0: Permanent Seed
 *                                             1: Transient Seed 
 * @return(0) written data size as string
 * @return(1) Error message if any 
 */
void routeSe050SetSeed(OSCMessage &msg, int addressOffset)
{
    OSCMessage resp_msg("/se050SetSeed");
    char seed[256];
    int seedLen{0}, writtenSize{0};
    int deletableFlag = DEFAULT_DELETABLE_FLAG;
    char errMsg[100];
 
    if (msg.isString(0))
    {
        seedLen = msg.getDataLength(0);
        msg.getString(0, seed, seedLen);

        if (msg.isInt(1))
        {
           deletableFlag = msg.getInt(1);
        }

        writtenSize = se050SetSeed(seed, seedLen, deletableFlag, errMsg);
    }


    resp_msg.add(String(writtenSize).c_str());
    resp_msg.add(errMsg);
    sendOSCMessage(resp_msg);
}


std::vector<uint8_t> se050GetSeed(){
    return se050_handler_o.read_binary_data(SEED_SLOT, BINARY_READ_SIZE);
}


/**
 * Read data from se050
 *
 * @return The stored data. Sending over OSC as string
 */
void routeSe050GetSeed(OSCMessage &msg, int addressOffset)
{
    OSCMessage resp_msg("/se050GetSeed");
    
    auto readData = se050GetSeed();

    String hexStr;
    hexStr = toHex(readData.data(), readData.size());
    resp_msg.add(hexStr.c_str());
    sendOSCMessage(resp_msg);
}


/**
 * Creates key pair in se050
 * 
 * @param int(0) slot id
 * @param int(1) <optional> Deletable Flag. 0: Permanent Key
 *                                          1: Transient Key (Default)
 * 
 * @return(0) Public Key in string type
 * @return(1) Error message if any
 */
void routeSe050CreateKeyPair(OSCMessage &msg, int addressOffset)
{
    OSCMessage resp_msg("/se050CreateKeyPair");
    char errMsg[100];
    String hexStr;
    int deletableFlag = DEFAULT_DELETABLE_FLAG;
    int keyID{NISTP_KEY_1_SLOT};

    if (msg.isInt(0)){
        keyID = msg.getInt(0);
    }

    if (msg.isInt(1)){
        deletableFlag = msg.getInt(1);
    }

    if(se050_handler_o.check_obj_exist(keyID)){
        if(!se050_handler_o.delete_obj(keyID)){
            resp_msg.add(hexStr.c_str());
            resp_msg.add("ERROR! There is an object on the slot!");
            sendOSCMessage(resp_msg);
            return;
        }
    }

    se050_handler_o.generate_key_pair_nistp256(keyID, deletableFlag);
    se050_handler_o.read_error_msg(errMsg);

    if(strlen(errMsg) == 0){ 
        auto pubKey = se050_handler_o.get_public_key(keyID);
        se050_handler_o.read_error_msg(errMsg);
        hexStr = toHex(pubKey.data(), pubKey.size());
    }
    
    resp_msg.add(hexStr.c_str());
    resp_msg.add(errMsg);

    sendOSCMessage(resp_msg);
}


/**
 * Getting public key from given slot
 * 
 * @param int(0)    Slot id of Key
 * 
 * @return(0) String type public key in Hex format
 * @return(1) Error message if any 
 */
void routeSe050GetPublicKey(OSCMessage &msg, int addressOffset)
{
    OSCMessage resp_msg("/se050GetPublicKey");
    
    String hexStr;
    char errMsg[100] = {0};
    int keyID{NISTP_KEY_1_SLOT};
 
    if (msg.isInt(0))
    {
        keyID = msg.getInt(0);

        auto pubKey = se050_handler_o.get_public_key(keyID);
        se050_handler_o.read_error_msg(errMsg);

        hexStr = toHex(pubKey.data(), pubKey.size());
    }

    resp_msg.add(hexStr.c_str());
    resp_msg.add(errMsg);
    sendOSCMessage(resp_msg);
}


/**
 * Calculate hash of message 
 * 
 * @param string(0) Data to be hashed
 * 
 * @return(0) String type hashed data in Hex format
 * @return(1) Error message if any
 */
void routeSe050CalculateHash(OSCMessage &msg, int addressOffset)
{
    OSCMessage resp_msg("/se050CalculateHash");
    
    String hexStr;
    char data[512] = {0};
    char errMsg[100] = {0};
    int dataLen{0};
 
    if (msg.isString(0))
    {
        dataLen = msg.getDataLength(0);
        msg.getString(0, data, dataLen);

        std::vector<uint8_t> hashInput(data, data + (dataLen-1));
        auto hashVec = se050_handler_o.calculate_sha256(hashInput);
        se050_handler_o.read_error_msg(errMsg);

        hexStr = toHex(hashVec.data(), hashVec.size());
    }

    resp_msg.add(hexStr.c_str());
    resp_msg.add(errMsg);
    sendOSCMessage(resp_msg);
}


/**
 * Sign given data 
 * 
 * @param string(0) Data to be signed in Hex format
 * @param int(1)    Slot id of Key
 * 
 * @return(0) String type signature in Hex format
 * @return(1) Error message if any
 */
void routeSe050SignData(OSCMessage &msg, int addressOffset)
{
    OSCMessage resp_msg("/se050SignData");
    
    String hexStr;
    char data[512] = {0};
    char errMsg[100] = {0};
    int dataLen{0};
    int keyID{NISTP_KEY_1_SLOT};
 
    if (msg.isString(0))
    {
        dataLen = msg.getDataLength(0);
        msg.getString(0, data, dataLen);

        if (msg.isInt(1)){
            keyID = msg.getInt(1);
        }

        auto t = fromhex(data);
        std::vector<uint8_t> signInput(t, t + ((dataLen-1)/2));
        auto signature = se050_handler_o.sign_sha256_digest(keyID, signInput);
        se050_handler_o.read_error_msg(errMsg);

        hexStr = toHex(signature.data(), signature.size());

        if(strlen(errMsg) == 0){
            auto verifyRes = se050_handler_o.verify_sha256_digest(keyID, signInput, signature);
            se050_handler_o.read_error_msg(errMsg);
        }
    }

    resp_msg.add(hexStr.c_str());
    resp_msg.add(errMsg);
    sendOSCMessage(resp_msg);
}


/**
 * Verify given signature 
 * 
 * @param string(0) String type data to be signed in Hex format
 * @param string(1) Signature
 * @param int(2)    Slot id of Key
 * 
 * @return(0) String type signature in Hex format
 * @return(1) Error message if any
 */
void routeSe050VerifySignature(OSCMessage &msg, int addressOffset)
{
    OSCMessage resp_msg("/se050VerifySignature");
    
    bool result{false};
    char data[512] = {0};
    char errMsg[100] = {0};
    int dataLen{0};
    int keyID{NISTP_KEY_1_SLOT};
 
    if (msg.isString(0))
    {
        dataLen = msg.getDataLength(0);
        msg.getString(0, data, dataLen);

        auto t = fromhex(data);
        std::vector<uint8_t> digest(t, t + ((dataLen-1)/2));

        if (msg.isString(1))
        {
            memset(data, 0, sizeof(data));
            dataLen = msg.getDataLength(1);
            msg.getString(1, data, dataLen);

            t = fromhex(data);
            std::vector<uint8_t> signature(t, t + ((dataLen-1)/2));

            if (msg.isInt(2)){
                keyID = msg.getInt(2);
            }

            result = se050_handler_o.verify_sha256_digest(keyID, digest, signature);
            se050_handler_o.read_error_msg(errMsg);
        }
    }

    resp_msg.add(result);
    resp_msg.add(errMsg);
    sendOSCMessage(resp_msg);
}


/**
 * Store private and public key in SE050, using secp256k1 curve
 * 
 * @param keyID(0)      Slot id of Key
 * @param privKey(1)    Private key in std vector type
 * @param pubKey(2)     Public key in std vector type
 * 
 * @return(0) 0: Success, -1: Failure
 */
int se050InjectSECPKeys(int keyID, std::vector<uint8_t>& privKey, std::vector<uint8_t>& pubKey){
    char errMsg[100] = {0};
    int result{-1};

    if(keyID == -1)
        keyID = SECP256_KEY_1_SLOT;

    if(se050_handler_o.check_obj_exist(keyID))
        se050_handler_o.delete_obj(keyID);

    se050_handler_o.generate_key_pair_secp256k1(keyID, privKey, pubKey);
    se050_handler_o.read_error_msg(errMsg);
    if(strlen(errMsg) == 0)
        result = 0;

    return result;
}


#endif