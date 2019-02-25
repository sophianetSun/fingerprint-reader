import unittest, serial
import fpController

class TestFPProcess(unittest.TestCase):
    """
    fingerprint reader module unittest
    """

    def setUp(self):
        self.fpr = fpController()

    def tearDown(self):
        pass


# if __name__ == '__main__':
#     unittest.main()