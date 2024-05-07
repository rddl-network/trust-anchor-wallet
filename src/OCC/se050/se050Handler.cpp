#ifdef DSE050

#include "se050_middleware.h"
#include "se050Handler.h"
#include "utils.h"

extern "C"{
    #include "wally_crypto.h"
    #include "ccan/ccan/crypto/sha256/sha256.h"
}

#define SE050_USED_SLOT     200

constexpr int BINARY_RW_SLOT    = SE050_USED_SLOT + 1;
constexpr int BINARY_READ_SIZE  = 64;
constexpr int DEFAULT_OVERRIDE_FLAG = 0; // 0: Dont override se050 slot, 1: Override

Se050Middleware se050_handler_o{SE050_USED_SLOT}; 

std::vector<uint8_t> getAESEncrypt(const std::string plainp, const uint8_t* key){
    int plainTextLen = plainp.length()-1;
    std::vector<uint8_t> result(plainTextLen/2);
    uint8_t ibuf[16];

    wally_aes(key, 32,  fromhex(plainp.data()), plainTextLen/2, AES_FLAG_ENCRYPT, &result[0], plainTextLen/2);

    return result;
}


std::vector<uint8_t> getAESDecrypt(const std::vector<uint8_t>cipherp, const uint8_t* key){
    int chiperTextLen = cipherp.size();
    std::vector<uint8_t> result(chiperTextLen);
    uint8_t ibuf[16];

    wally_aes(key, 32, cipherp.data(), cipherp.size(), AES_FLAG_DECRYPT, &result[0], cipherp.size());

    return result;
}


/**
 * Write AES Encrypted data of given Seed into SE050
 *
 * @param string(0) Seed in String type
 * @param string(1) <optional> Override Flag. 0: Dont write, if there is any data on SE050
 *                                            1: Write anyway 
 * @param string(2) <optional> Key in String type
 * @return Status in string type
 */
void routeSE050EncryptData(OSCMessage &msg, int addressOffset) 
{
    OSCMessage resp_msg("/se050SetEncryptSeed");
    std::string key, plainTxt;
    struct sha256 sha;
    int overrideFlash = DEFAULT_OVERRIDE_FLAG;
    memset(&sha, 0, sizeof(struct sha256));
 
    if (msg.isString(0))
    {
        int kyLen = 0;
        int len = msg.getDataLength(0);
        char plainText[len];
        plainTxt.resize(len);
        msg.getString(0, &plainTxt[0], len);

        if (msg.isInt(1))
        {
           overrideFlash = msg.getInt(1);
        }

        if (msg.isString(2))
        {
            kyLen = msg.getDataLength(2);
            key.resize(kyLen);
            msg.getString(2, &key[0], kyLen);

            sha256(&sha, fromhex(key.data()), (key.size()-1)/2);
        }

        if(overrideFlash != 0)
            se050_handler_o.delete_obj(BINARY_RW_SLOT);

        std::vector<uint8_t> cipherArr = getAESEncrypt(plainTxt, sha.u.u8);

        if(se050_handler_o.write_binary_data(BINARY_RW_SLOT, cipherArr) == cipherArr.size())
            resp_msg.add("Binary Data Written");
        else
            resp_msg.add("ERROR! Write Binary Data");
    }

    sendOSCMessage(resp_msg);
}


/**
 * Read Seed from SE050. 
 * Always read BINARY_READ_SIZE bytes from se050.
 * 
 * @param string(0) <optional> Key in String type
 * @return Seed in string type
 */
void routeSE050DecryptData(OSCMessage &msg, int addressOffset) 
{
    OSCMessage resp_msg("/se050GetEncryptedSeed");
    std::string key;
    struct sha256 sha;
    memset(&sha, 0, sizeof(struct sha256));

    if (msg.isString(0))
    {
        int kyLen = msg.getDataLength(0);
        key.resize(kyLen);
        msg.getString(0, &key[0], kyLen);

        sha256(&sha, fromhex(key.data()), (key.size()-1)/2);
    }

    auto cipherp = se050_handler_o.read_binary_data(BINARY_RW_SLOT, BINARY_READ_SIZE);
    auto plainArr = getAESDecrypt(cipherp, sha.u.u8);

    String hexStr;
    hexStr = toHex(plainArr.data(), plainArr.size());
    resp_msg.add(hexStr.c_str());
    resp_msg.add(se050_handler_o.oss.str().c_str());

    sendOSCMessage(resp_msg);
}


int se050SetSeed(const char* seedStr, int seedLen, int overrideFlag, char* errMsg){

    if(seedLen != (BINARY_READ_SIZE*2 + 1)){
        strcpy(errMsg, "ERROR! Seed size must be 64! Seed String size must be 128");
        return 0;
    }

    if(se050_handler_o.check_obj_exist(BINARY_RW_SLOT)){
        if(overrideFlag != 0)
            se050_handler_o.delete_obj(BINARY_RW_SLOT);
        else{
            strcpy(errMsg, "ERROR! There is an object on the slot!");
            return -1;
        }
    }

    auto seedPtr = fromhex(seedStr);
    std::vector<uint8_t> data( seedPtr, seedPtr + BINARY_READ_SIZE);
    int writtenSize = se050_handler_o.write_binary_data(BINARY_RW_SLOT, data);
    se050_handler_o.read_error_msg(errMsg);

    return writtenSize;
}



/**
 * Write data into SE050
 *
 * @param string(0) String type data in Hex format
 * @param string(1) <optional> Override Flag. 0: Dont write, if there is any data on SE050
 *                                            1: Write anyway 
 * @return(0) written data size as string
 * @return(1) Error message if any 
 */
void routeSe050SetSeed(OSCMessage &msg, int addressOffset)
{
    OSCMessage resp_msg("/se050SetSeed");
    char seed[256];
    int seedLen{0}, writtenSize{0};
    int overrideFlag = DEFAULT_OVERRIDE_FLAG;
    char errMsg[100];
 
    if (msg.isString(0))
    {
        seedLen = msg.getDataLength(0);
        msg.getString(0, seed, seedLen);

        if (msg.isInt(1))
        {
           overrideFlag = msg.getInt(1);
        }

        writtenSize = se050SetSeed(seed, seedLen, overrideFlag, errMsg);
    }


    resp_msg.add(String(writtenSize).c_str());
    resp_msg.add(errMsg);
    sendOSCMessage(resp_msg);
}


std::vector<uint8_t> se050GetSeed(){
    return se050_handler_o.read_binary_data(BINARY_RW_SLOT, BINARY_READ_SIZE);
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
 * @param int(0) <optional> Override Flag. 0: Dont create, if there is key on SE050 slot
 *                                         1: Delete previous one and create new.
 * 
 * @return(0) Public Key in string type
 * @return(1) Error message if any
 */
void routeSe050CreateKeyPair(OSCMessage &msg, int addressOffset)
{
    OSCMessage resp_msg("/se050CreateKeyPair");
    char errMsg[100];
    String hexStr;
    int overrideFlash = DEFAULT_OVERRIDE_FLAG;

    if (msg.isInt(0))
    {
        overrideFlash = msg.getInt(0);
    }

    if(overrideFlash == 1)
        se050_handler_o.delete_obj(se050_handler_o.get_key_id());

    if(se050_handler_o.check_obj_exist(se050_handler_o.get_key_id())){
        resp_msg.add(hexStr.c_str());
        resp_msg.add("ERROR! There is an object on the slot!");
    }else{
        se050_handler_o.generate_key_pair_nistp256();
        se050_handler_o.read_error_msg(errMsg);

        if(strlen(errMsg) == 0){ 
            auto pubKey = se050_handler_o.get_public_key();
            se050_handler_o.read_error_msg(errMsg);
            hexStr = toHex(pubKey.data(), pubKey.size());
        }
        
        resp_msg.add(hexStr.c_str());
        resp_msg.add(errMsg);
    }

    sendOSCMessage(resp_msg);
}


/**
 * Calculate hash of message 
 * 
 * @param string(0) String type data to be hashed
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
 * @param string(0) String type data to be signed in Hex format
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
 
    if (msg.isString(0))
    {
        dataLen = msg.getDataLength(0);
        msg.getString(0, data, dataLen);

        auto t = fromhex(data);
        std::vector<uint8_t> signInput(t, t + ((dataLen-1)/2));
        auto signature = se050_handler_o.sign_sha256_digest(signInput);
        se050_handler_o.read_error_msg(errMsg);

        hexStr = toHex(signature.data(), signature.size());

        if(strlen(errMsg) == 0){
            auto verifyRes = se050_obj.verify_sha256_digest(signInput, signature);
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
 * @param string(1) String type signature to be signed in Hex format
 * 
 * @return(0) String type signature in Hex format
 * @return(1) Error message if any
 */
void routeSe050VerifySignature(OSCMessage &msg, int addressOffset)
{
    OSCMessage resp_msg("/se050SignData");
    
    bool result{false};
    char data[512] = {0};
    char errMsg[100] = {0};
    int dataLen{0};
 
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

            result = se050_handler_o.verify_sha256_digest(digest, signature);
            se050_handler_o.read_error_msg(errMsg);
        }


    }

    resp_msg.add(result);
    resp_msg.add(errMsg);
    sendOSCMessage(resp_msg);
}


#endif