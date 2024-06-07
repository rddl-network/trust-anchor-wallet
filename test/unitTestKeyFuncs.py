import threading
import serial
import serial.tools.list_ports
from time import sleep 
import time
from osc4py3.oscbuildparse import *
from osc4py3.as_eventloop import *
import sliplib
import unittest
from unittest.mock import MagicMock


def find_esp_port():
    # List all available serial ports
    ports = serial.tools.list_ports.comports()
    
    for port in ports:
        # Print port details for debugging purposes
        #print(f"Port: {port.device}, Description: {port.description}, HWID: {port.hwid}")
        
        # Check if the port description contains 'USB' or 'UART' which are common for ESP devices
        if 'USB' in port.description or 'UART' in port.description:
            return port.device
    
    return None

esp_port = find_esp_port()

if esp_port:
	print(f"ESP device detected on port: {esp_port}")
else:
	print("Couldnt find ESP Device!")
	exit()

ser = serial.Serial(
        # Serial Port to read the data from
        port= esp_port,

        #Rate at which the information is shared to the communication channel
        baudrate = 115200,
   
        #Applying Parity Checking (none in this case)
        parity=serial.PARITY_NONE,
 
       # Pattern of Bits to be read
        stopbits=serial.STOPBITS_ONE,
     
        # Total number of bits to be read
        bytesize=serial.EIGHTBITS,
 
        # Number of serial commands to accept before timing out
        timeout=1
)


def map(pattern, handler, decoded_data):
	if decoded_data.addrpattern == pattern:
		return decoded_data.arguments


def read_from_port(ser, cmd, timeout=10):
    start_time = time.time()
    data = ""

    while (time.time() - start_time) < timeout:
        if ser.inWaiting():
            serline = ser.readline()
            line = sliplib.decode(serline)
            try:
                decoded_data = decode_packet(line)
                data = map(cmd, print, decoded_data)
                break
            except Exception as e:
                try:
                    print(line.decode("utf-8"), end=" ")
                except Exception:
                    continue
        else:
            # Wait for a short duration before checking again
            time.sleep(0.1)  # Adjust the sleep duration as needed

    return data


def send_osc_message(msg, cmd):
	raw = encode_packet(msg)
	slipMsg = sliplib.encode(raw)
	ser.write(slipMsg)
	sleep(5)
	return read_from_port(ser, cmd)


class TestTWFunctions(unittest.TestCase):
	testSeed  = "e7d2d8a252100826db0ea6b2796428408a6671cedfbb11825bce809951593cf9eaa3d61a53e687e812261bf72fbaf54a173aa1c46c124fb50365f05dab40438d"

	def test_01_set_seed(self):
		# Mock OSC message
		msg = OSCMessage('/IHW/setSeed',',si',[self.__class__.testSeed, 1])

		# Mock response
		expected_response = str(int(len(self.__class__.testSeed)/2))

		# Call the function with the mocked OSC message
		response = send_osc_message(msg, "/setSeed")

		# Assert that the response matches the expected response
		self.assertEqual(response[0], expected_response)

	def test_02_get_seed(self):
		# Mock OSC message
		msg = OSCMessage('/IHW/getSeed',',',[])

		# Mock response
		expected_response = self.__class__.testSeed

		# Call the function with the mocked OSC message
		response = send_osc_message(msg, "/getSeed")

		# Assert that the response matches the expected response
		self.assertEqual(response[0], expected_response)

	def test_03_get_rddl_keys(self):
		# Mock OSC message
		msg = OSCMessage('/IHW/getPlntmntKeys',',',[])

		# Mock response
		Address 	= "plmnt1r7uzw23ux4ewy0c9q2f46uw33sjqjr7hr8dkuu"
		Liquid		= "xpub6FeZZGmr9fYMY8YtMQKPfVc2MzEtcn1mNri7gLU4NnaWXTs61iGdakWFuxD5CK4KUWhUWQrbL38P5AC4gL4TCu9QetpDwqsWL2j8SfZyrZW"
		Planetmint	= "pmpb7uRiJgAVHHkGHitARxzy1rcXXuRVtjk79STZCuS17bNYQX3oi6c4Xi4Sr1X4FobGDzZxtdnAgtg1tQhcdYTu2Min5GCM2ZXeNrmojAaaKSC"

		# Call the function with the mocked OSC message
		response = send_osc_message(msg, "/getPlntmntKeys")

		# Assert that the response matches the expected response
		self.assertEqual(response[0], Address)
		self.assertEqual(response[1], Liquid)
		self.assertEqual(response[2], Planetmint)

	def test_04_sign_rddl(self):
		# Mock OSC message
		msg = OSCMessage('/IHW/ecdsaSignRddl',',s',["testData"])

		# Mock response
		expected_response = "0"
		
		# Call the function with the mocked OSC message
		response = send_osc_message(msg, "/ecdsaSignRddl")

		# Assert that the response matches the expected response
		self.assertEqual(len(response[0]), 128)
		self.assertEqual(response[1], expected_response)

	def test_05_sign_rddl(self):
		# Mock OSC message
		msg = OSCMessage('/IHW/ecdsaSignPlmnt',',s',["testData"])
		
		# Mock response
		expected_response = "0"
		
		# Call the function with the mocked OSC message
		response = send_osc_message(msg, "/ecdsaSignPlmnt")

		# Assert that the response matches the expected response
		self.assertEqual(len(response[0]), 128)
		self.assertEqual(response[1], expected_response)

	def test_06_mnemonic_to_seed_inject(self):
		tMnemonic = "bonus acid virtual banner mansion waste student fade faint burst sister any"

		# Mock OSC message
		msg = OSCMessage('/IHW/mnemonicToSeed',',is',[1, tMnemonic])

		# Mock response
		expected_response = tMnemonic

		# Call the function with the mocked OSC message
		response = send_osc_message(msg, "/mnemonicToSeed")

		# Assert that the response matches the expected response
		self.assertEqual(response[0], expected_response)

	def test_07_mnemonic_to_seed_check(self):
		# Mock OSC message
		msg = OSCMessage('/IHW/getSeed',',',[])

		# Mock response
		expected_response = "2737a74501ce93311921f4d57dc893263ae16277db2e5204afe2dedef5af1f40e920387bd9c0988d9716c9332f6e309cd66746ecb771f1dcb4d3b6a1f4dbc293"

		# Call the function with the mocked OSC message
		response = send_osc_message(msg, "/getSeed")

		# Assert that the response matches the expected response
		self.assertEqual(response[0], expected_response)


	def test_08_sign_plmnt(self):
		tMnemonic = "penalty police pool orphan snack faith educate syrup skill picnic prepare mystery dune control near nation report evolve ethics genius elite tool rigid crane"

		# Mock OSC message
		msg = OSCMessage('/IHW/mnemonicToSeed',',is',[1, tMnemonic])

		# Mock response
		expected_response = tMnemonic

		# Call the function with the mocked OSC message
		response = send_osc_message(msg, "/mnemonicToSeed")

		# Assert that the response matches the expected response
		self.assertEqual(response[0], expected_response)
		hash_digest = "c890f865f3b05f7827034aae6ac25cd5cbca5d25eb0f0c35df5d33903e08fabe"
		msg2 = OSCMessage("/IHW/ecdsaSignPlmnt", ",s", [hash_digest])
		occ_message = send_osc_message(msg2, "/ecdsaSignPlmnt")
		self.assertEqual( "b5af3756630c182dc238e553e23d287de7123b9c3dfd346924b58373eb92a236027dbb49d131b7afd4f9ab4575db4376b6c3ee4cb0c3b8a079d76fc28028f842", occ_message[0])

	def test_09_sign_plmnt2(self):
		tMnemonic = "penalty police pool orphan snack faith educate syrup skill picnic prepare mystery dune control near nation report evolve ethics genius elite tool rigid crane"

		# Mock OSC message
		msg = OSCMessage('/IHW/mnemonicToSeed',',is',[1, tMnemonic])

		# Mock response
		expected_response = tMnemonic

		# Call the function with the mocked OSC message
		response = send_osc_message(msg, "/mnemonicToSeed")

		# Assert that the response matches the expected response
		self.assertEqual(response[0], expected_response)
		hash_digest = "6bc7f47039987062ffbeb1accd12f723056fe92e37aa92cc433660d13f562d99"
		msg2 = OSCMessage("/IHW/ecdsaSignPlmnt", ",s", [hash_digest])
		occ_message = send_osc_message(msg2, "/ecdsaSignPlmnt")
		self.assertEqual( "464c3ed2749a6a07beea0ef04ac638c1d51a9f11bca5f8ece75c79c8bcee94346e04a264528f3ecd1144be28dcb4f06c5d5c74c18cf1644b09830f5331551d51", occ_message[0])


if __name__ == "__main__":
    unittest.main()
