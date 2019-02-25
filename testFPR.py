import unittest, serial
import fpController

PORT = '/dev/ttyUSB0'
BAUDRATE = 19200
TIMEOUT = 0.1

class TestFPProcess(unittest.TestCase):
    """
    fingerprint reader module unittest
    """

    def setUp(self):
        self.fpr = fpController(PORT, BAUDRATE, TIMEOUT)

    def tearDown(self):
        pass


# if __name__ == '__main__':
#     unittest.main()