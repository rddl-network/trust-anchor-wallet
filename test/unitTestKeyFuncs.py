import threading
import serial
from time import sleep 
import time
from osc4py3.oscbuildparse import *
from osc4py3.as_eventloop import *
import sliplib
import unittest
from unittest.mock import MagicMock


ser = serial.Serial(
        # Serial Port to read the data from
        port='/dev/ttyACM1',

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
	return read_from_port(ser, cmd)


class TestTWFunctions(unittest.TestCase):
	def test_01_set_seed(self):
		# Mock OSC message
		msg = OSCMessage('/IHW/setSeed',',si',["e7d2d8a252100826db0ea6b2796428408a6671cedfbb11825bce809951593cf9eaa3d61a53e687e812261bf72fbaf54a173aa1c46c124fb50365f05dab40438d", 0])

		# Mock response
		expected_response = "64"

		# Call the function with the mocked OSC message
		response = send_osc_message(msg, "/setSeed")

		# Assert that the response matches the expected response
		self.assertEqual(response[0], expected_response)

	def test_02_get_seed(self):
		# Mock OSC message
		msg = OSCMessage('/IHW/getSeed',',',[])

		# Mock response
		expected_response = "e7d2d8a252100826db0ea6b2796428408a6671cedfbb11825bce809951593cf9eaa3d61a53e687e812261bf72fbaf54a173aa1c46c124fb50365f05dab40438d"

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
		self.assertEqual(len(response[0]), 64)
		self.assertEqual(response[1], expected_response)

	def test_05_sign_rddl(self):
		# Mock OSC message
		msg = OSCMessage('/IHW/ecdsaSignPlmnt',',s',["testData"])
		
		# Mock response
		expected_response = "0"
		
		# Call the function with the mocked OSC message
		response = send_osc_message(msg, "/ecdsaSignPlmnt")

		# Assert that the response matches the expected response
		self.assertEqual(len(response[0]), 64)
		self.assertEqual(response[1], expected_response)

	def test_06_mnemonic_to_seed_inject(self):
		tMnemonic = "bonus acid virtual banner mansion waste student fade faint burst sister any"

		# Mock OSC message
		msg = OSCMessage('/IHW/mnemonicToSeed',',is',[0, tMnemonic])

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


if __name__ == "__main__":
    unittest.main()
