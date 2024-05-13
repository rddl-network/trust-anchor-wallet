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
	testSeed  = "e7d2d8a252100826db0ea6b2796428408a6671cedfbb11825bce809951593cf9eaa3d61a53e687e812261bf72fbaf54a173aa1c46c124fb50365f05dab40438d"
	testData  = None
	tSignature = None

	def test_01_set_seed_override(self):
		# Mock OSC message
		msg = OSCMessage('/IHW/se050SetSeed',',si',[self.__class__.testSeed, 1])

		# Mock response
		expected_response = str(int(len(self.__class__.testSeed)/2))

		# Call the function with the mocked OSC message
		response = send_osc_message(msg, "/se050SetSeed")

		# Assert that the response matches the expected response
		self.assertEqual(response[0], expected_response)

	def test_02_get_seed(self):
		# Mock OSC message
		msg = OSCMessage('/IHW/se050GetSeed',',',[])

		# Mock response
		expected_response = self.__class__.testSeed

		# Call the function with the mocked OSC message
		response = send_osc_message(msg, "/se050GetSeed")

		# Assert that the response matches the expected response
		self.assertEqual(response[0], expected_response)

	def test_03_set_seed_protection(self):
		# Mock OSC message
		msg = OSCMessage('/IHW/se050SetSeed',',si',[self.__class__.testSeed, 0])

		# Mock response
		expected_response = "-1"

		# Call the function with the mocked OSC message
		response = send_osc_message(msg, "/se050SetSeed")

		# Assert that the response matches the expected response
		self.assertEqual(response[0], expected_response)

	def test_04_create_key_pair(self):
		# Mock OSC message
		msg = OSCMessage('/IHW/se050CreateKeyPair',',i',[1])

		# Mock response
		expected_response = 130

		# Call the function with the mocked OSC message
		response = send_osc_message(msg, "/se050CreateKeyPair")

		# Assert that the response matches the expected response
		self.assertEqual(len(response[0]), expected_response)

	def test_05_create_key_pair_protection(self):
		# Mock OSC message
		msg = OSCMessage('/IHW/se050CreateKeyPair',',i',[0])

		# Mock response
		expected_response = 0

		# Call the function with the mocked OSC message
		response = send_osc_message(msg, "/se050CreateKeyPair")

		# Assert that the response matches the expected response
		self.assertEqual(len(response[0]), expected_response)

	def test_06_calculate_hash(self):
		# Mock OSC message
		msg = OSCMessage('/IHW/se050CalculateHash',',s',["testData"])

		# Mock response
		expected_response = "ba477a0ac57e10dd90bb5bf0289c5990fe839c619b26fde7c2aac62f526d4113"

		# Call the function with the mocked OSC message
		response = send_osc_message(msg, "/se050CalculateHash")

		# Assert that the response matches the expected response
		self.assertEqual(response[0], expected_response)
		self.__class__.testData = response[0]

	def test_07_sign_data(self):
		# Mock OSC message
		msg = OSCMessage('/IHW/se050SignData',',s',[self.__class__.testData])

		# Mock response
		expected_responseL = 138
		expected_responseH = 150

		# Call the function with the mocked OSC message
		response = send_osc_message(msg, "/se050SignData")

		# Assert that the response matches the expected response
		self.assertGreater(len(response[0]), expected_responseL)
		self.assertLess(len(response[0]), expected_responseH)
		self.__class__.tSignature = response[0]

	def test_08_verify_signature(self):
		# Mock OSC message
		msg = OSCMessage('/IHW/se050VerifySignature',',ss',[self.__class__.testData, self.__class__.tSignature])
		
		# Mock response
		expected_response = bool(1)

		# Call the function with the mocked OSC message
		response = send_osc_message(msg, "/se050VerifySignature")

		# Assert that the response matches the expected response
		self.assertEqual(response[0], expected_response)



if __name__ == "__main__":
    unittest.main()
