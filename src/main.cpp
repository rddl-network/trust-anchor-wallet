#include <Arduino.h>
#include <OSCBundle.h>
#include <SLIPEncodedSerial.h>
#include "OSCTable.h"

#ifdef DOPTIGA
    #include "OPTIGATrustX.h"
#endif

HWCDC SerialESP;
SLIPEncodedSerial SLIPSerial(SerialESP); // for XIAO ESP32C3

void setup()
{
    SLIPSerial.begin(115200);
    SerialESP.setRxBufferSize(1024);
    SerialESP.setTxBufferSize(1024);
    delay(2);

    #ifdef DSE050
        se050_obj.init_interface(6, 7);
    #endif

    #ifdef DOPTIGA
        trustX.begin();
    #endif
}

void loop()
{
    OSCMessage msg;
    int size;
    // receive a bundle
    while (!SLIPSerial.endofPacket())
        if ((size = SLIPSerial.available()) > 0)
        {
            while (size--)
                msg.fill(SLIPSerial.read());
        }

    if (!msg.hasError())
    {
        for(const auto& p : osc_func_table){
            msg.route(p.first, p.second);
        }
    }
}
