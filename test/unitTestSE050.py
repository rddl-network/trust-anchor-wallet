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


def read_from_port(ser, cmd, timeout=13):
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
	testData  = "ba477a0ac57e10dd90bb5bf0289c5990fe839c619b26fde7c2aac62f526d4113"
	tSignature = None
	tSignaturePlmnt = "304502201e31f97e8169e31cdb5f36fca198df88bf51391887cbc4379856564f61a1d99d022100e3b0a3a8040d2468ed69855774d6da98a3ce574a64f7d6bfef0cb198ce690c51"
	tSignatureLiquid = "304402200a6c57274d38c8978849a413912adbe5fe6177e744b5f20eda017e076f3492f002205e4d4267e8f1555bc3ae28885d6b53cad0b6da0f7e7e5b3ba84e2e95fe6d9638"
	nistpKeySlot = 123
	plmntKeySlot = 124
	liquidKeySlot = 125

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

	def test_03_create_key_pair(self):
		# Mock OSC message
		msg = OSCMessage('/IHW/se050CreateKeyPair',',ii',[self.__class__.nistpKeySlot, 1])

		# Mock response
		expected_response = 130

		# Call the function with the mocked OSC message
		response = send_osc_message(msg, "/se050CreateKeyPair")

		# Assert that the response matches the expected response
		self.assertEqual(len(response[0]), expected_response)

	def test_04_calculate_hash(self):
		# Mock OSC message
		msg = OSCMessage('/IHW/se050CalculateHash',',s',["testData"])

		# Mock response
		expected_response = "ba477a0ac57e10dd90bb5bf0289c5990fe839c619b26fde7c2aac62f526d4113"

		# Call the function with the mocked OSC message
		response = send_osc_message(msg, "/se050CalculateHash")

		# Assert that the response matches the expected response
		self.assertEqual(response[0], expected_response)
		self.__class__.testData = response[0]

	def test_05_sign_data(self):
		# Mock OSC message
		msg = OSCMessage('/IHW/se050SignData',',si',[self.__class__.testData, self.__class__.nistpKeySlot])

		# Mock response
		expected_responseL = 138
		expected_responseH = 150

		# Call the function with the mocked OSC message
		response = send_osc_message(msg, "/se050SignData")

		# Assert that the response matches the expected response
		self.assertGreater(len(response[0]), expected_responseL)
		self.assertLess(len(response[0]), expected_responseH)
		self.__class__.tSignature = response[0]

	def test_06_verify_signature(self):
		# Mock OSC message
		msg = OSCMessage('/IHW/se050VerifySignature',',ssi',[self.__class__.testData, self.__class__.tSignature, self.__class__.nistpKeySlot])
		
		# Mock response
		expected_response = bool(1)

		# Call the function with the mocked OSC message
		response = send_osc_message(msg, "/se050VerifySignature")

		# Assert that the response matches the expected response
		self.assertEqual(response[0], expected_response)

	def test_07_inject_plmnt_keys(self):
		# Mock OSC message
		msg = OSCMessage('/IHW/se050InjectSECPKeys',',i',[self.__class__.plmntKeySlot])
		
		# Mock response
		expected_response = "0"

		# Call the function with the mocked OSC message
		response = send_osc_message(msg, "/se050InjectSECPKeys")

		# Assert that the response matches the expected response
		self.assertEqual(response[0], expected_response)

	def test_08_plmnt_sign_data(self):
		# Mock OSC message
		msg = OSCMessage('/IHW/se050SignData',',si',[self.__class__.testData, self.__class__.plmntKeySlot])

		# Mock response
		expected_responseL = 138
		expected_responseH = 150

		# Call the function with the mocked OSC message
		response = send_osc_message(msg, "/se050SignData")

		# Assert that the response matches the expected response
		self.assertGreater(len(response[0]), expected_responseL)
		self.assertLess(len(response[0]), expected_responseH)
		self.__class__.tSignaturePlmnt = response[0]

	def test_09_plmnt_verify_signature(self):
		# Mock OSC message
		msg = OSCMessage('/IHW/se050VerifySignature',',ssi',[self.__class__.testData, self.__class__.tSignaturePlmnt, self.__class__.plmntKeySlot])
		
		# Mock response
		expected_response = bool(1)

		# Call the function with the mocked OSC message
		response = send_osc_message(msg, "/se050VerifySignature")

		# Assert that the response matches the expected response
		self.assertEqual(response[0], expected_response)

	def test_10_liquid_sign_data(self):
		# Mock OSC message
		msg = OSCMessage('/IHW/se050SignData',',si',[self.__class__.testData, self.__class__.liquidKeySlot])

		# Mock response
		expected_responseL = 138
		expected_responseH = 150

		# Call the function with the mocked OSC message
		response = send_osc_message(msg, "/se050SignData")

		# Assert that the response matches the expected response
		self.assertGreater(len(response[0]), expected_responseL)
		self.assertLess(len(response[0]), expected_responseH)
		self.__class__.tSignatureLiquid = response[0]

	def test_11_liquid_verify_signature(self):
		# Mock OSC message
		msg = OSCMessage('/IHW/se050VerifySignature',',ssi',[self.__class__.testData, self.__class__.tSignatureLiquid, self.__class__.liquidKeySlot])
		
		# Mock response
		expected_response = bool(1)

		# Call the function with the mocked OSC message
		response = send_osc_message(msg, "/se050VerifySignature")

		# Assert that the response matches the expected response
		self.assertEqual(response[0], expected_response)

	def test_12_verify_signature_of_libwally_w_se050(self):
		# Mock OSC message
		msg = OSCMessage('/IHW/ecdsaSignPlmnt',',s',[self.__class__.testData])

		# Mock response
		expected_response = "0"
		
		# Call the function with the mocked OSC message
		response = send_osc_message(msg, "/ecdsaSignPlmnt")
		plmntSignature = "3044" + "0220" + response[0][0:64] + "0220" + response[0][64:]

		# Mock OSC message
		msg = OSCMessage('/IHW/se050VerifySignature',',ssi',[self.__class__.testData, plmntSignature, self.__class__.plmntKeySlot])
		
		# Mock response
		expected_response = bool(1)

		# Call the function with the mocked OSC message
		response = send_osc_message(msg, "/se050VerifySignature")

		# Assert that the response matches the expected response
		self.assertEqual(response[0], expected_response)

	# def test_12_set_seed_permanent(self):
	# 	# Mock OSC message
	# 	msg = OSCMessage('/IHW/se050SetSeed',',si',["ffd2d8a252100826db0ea6b2796428408a6671cedfbb11825bce809951593cf9eaa3d61a53e687e812261bf72fbaf54a173aa1c46c124fb50365f05dab40438d", 0])

	# 	# Mock response
	# 	expected_response = str(int(len(self.__class__.testSeed)/2))

	# 	# Call the function with the mocked OSC message
	# 	response = send_osc_message(msg, "/se050SetSeed")

	# 	# Assert that the response matches the expected response
	# 	self.assertEqual(response[0], expected_response)

	# def test_13_set_seed_permanent_override(self):
	# 	# Mock OSC message
	# 	msg = OSCMessage('/IHW/se050SetSeed',',si',[self.__class__.testSeed, 0])

	# 	# Mock response
	# 	expected_response = str(int(len(self.__class__.testSeed)/2))

	# 	# Call the function with the mocked OSC message
	# 	response = send_osc_message(msg, "/se050SetSeed")

	# 	# Assert that the response matches the expected response
	# 	self.assertNotEqual(response[0], expected_response)

	# def test_14_get_seed_permanent(self):
	# 	# Mock OSC message
	# 	msg = OSCMessage('/IHW/se050GetSeed',',',[])

	# 	# Mock response
	# 	expected_response = "ffd2d8a252100826db0ea6b2796428408a6671cedfbb11825bce809951593cf9eaa3d61a53e687e812261bf72fbaf54a173aa1c46c124fb50365f05dab40438d"

	# 	# Call the function with the mocked OSC message
	# 	response = send_osc_message(msg, "/se050GetSeed")

	# 	# Assert that the response matches the expected response
	# 	self.assertEqual(response[0], expected_response)

if __name__ == "__main__":
    unittest.main()
