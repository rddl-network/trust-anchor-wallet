#define KEY_MAXLENGTH   70
#define DATA_LENGTH		10
#define HASH_LENGTH		32
#define SIGN_LENGTH		80
#define PUBKEY_LENGTH	70

#define SUPPRESSCOLLORS

void routeOptigaTrustXCreateSecret(OSCMessage &msg, int addressOffset);
void routeOptigaTrustXSignMessage(OSCMessage &msg, int addressOffset);
