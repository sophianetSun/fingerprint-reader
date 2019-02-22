import fingerprint as fp
import unittest
import serial

PORT = '/dev/ttyAMA0'
BAUDRATE = 19200

HEAD = 0xF5
TAIL = 0xF5

class TestFPProcess(unittest.TestCase):

    def setUp(self):
        self.ser = serial.Serial(PORT, BAUDRATE)

    def tearDown(self):
        self.ser.close()

    def test_set_dormant(self):
        self.ser.write(fp.set_dormant_state())
        self.assertEqual(self.ser.read(8),
            [HEAD, 0x2C, 0, 0, 0, 0, 0x2C^0, TAIL],
            'should dormant be set')

    def test_add_read_mode(self):
        self.ser.write(fp.fingerprint_mode('read'))
        self.assertEqual(self.ser.read(8),
            [HEAD, 0x2D, 0, 1, fp.ACK_SUCCESS, 0, 0x2D^0, TAIL],
            'should read add mode success')

    def test_del_all_users(self):
        self.ser.write(fp.del_all_users())
        self.assertEqual(self.ser.read(8),
            [HEAD, 0x05, 0, 0, fp.ACK_SUCCESS, 0, 0x05^0, TAIL])
    