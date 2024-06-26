#include <Arduino.h>
#include <OSCBundle.h>
#include <SLIPEncodedSerial.h>

#ifdef DOPTIGA
    #include "OPTIGATrustX.h"
#endif

#ifdef DSE050
    #include "se050_middleware.h"
    #include "se050Handler.h"
#endif

#include "OSCFuncTable.h"

HWCDC SerialESP;
SLIPEncodedSerial SLIPSerial(SerialESP); // for XIAO ESP32C3

void setup()
{
    SLIPSerial.begin(115200);
    SerialESP.setRxBufferSize(1024);
    SerialESP.setTxBufferSize(1024);

    #ifdef DOPTIGA
        trustX.begin();
    #endif

    #ifdef DSE050
        se050_handler_o.init_interface(6, 7);
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
