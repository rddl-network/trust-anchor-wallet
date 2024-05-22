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
	sleep(5)	
	return read_from_port(ser, cmd)


class TestTWFunctions(unittest.TestCase):
	pubKey = None

	def test_01_optiga_create_keys(self):
		# Mock OSC message
		msg = OSCMessage('/IHW/optigaTrustXCreateSecret', ',i',[2])

		# Mock response
		expected_response = 136

		# Call the function with the mocked OSC message
		response = send_osc_message(msg, "/optigaTrustXCreateSecret")

		# Assert that the response matches the expected response
		self.__class__.pubKey = response[0]
		self.assertEqual(len(response[0]), expected_response)
		
	def test_02_optiga_sign_data(self):
		# Mock OSC message
		msg = OSCMessage('/IHW/optigaTrustXSignMessage', ',iss',[2, "83b4d002202d94269f70dd9f2b73bcaf4e8ee6083b2f71d946e1f4dc01234567", self.__class__.pubKey])

		# Mock response
		expected_response = "true"

		# Call the function with the mocked OSC message
		response = send_osc_message(msg, "/optigaTrustXSignMessage")

		# Assert that the response matches the expected response
		self.assertEqual(response[2], expected_response)

	def test_03_optiga_sign_data_fail(self):
		# Mock OSC message
		msg = OSCMessage('/IHW/optigaTrustXSignMessage', ',iss',[2, "83b4d002202d94269f70dd9f2b73bcaf4e8ee6083b2f71d946e1f4dc01234567", "83b4d002202d94269f70dd9f2b73bcaf4e8ee6083b2f71d946e1f4dc01234567"])

		# Mock response
		expected_response = "false"

		# Call the function with the mocked OSC message
		response = send_osc_message(msg, "/optigaTrustXSignMessage")

		# Assert that the response matches the expected response
		self.assertEqual(response[2], expected_response)


if __name__ == "__main__":
    unittest.main()
