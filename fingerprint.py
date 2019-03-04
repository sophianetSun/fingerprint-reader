#!/usr/bin/env python3
# This is WaveShare UART Fingerprint Reader Module

import serial, time, threading, sys

TRUE = 1
FALSE = 0

# Basic response message definition
ACK_SUCCESS = 0x00      # Operation successfully
ACK_FAIL = 0x01         # Operation failed
ACK_FULL = 0x04         # Fingerprint database is full
ACK_NO_USER = 0x05      # No such user
ACK_USER_EXIST = 0x06   # User already exists
ACK_FIN_EXIST = 0x07    # Fingerprint already exists
ACK_TIMEOUT = 0x08      # Acquistion timeout

# User privilege

ACK_HIGH_PRI = 0x01
ACK_MID_PRI = 0x02
ACK_LOW_PRI = 0x03

USER_MAX_CNT = 4095 # Range of user number is 1 - 0xFFF

# Command definition
CMD_HEAD = 0xF5
CMD_TAIL = 0xF5
CMD_ADD_1 = 0x01
CMD_ADD_2 = 0x02
CMD_ADD_3 = 0x03
CMD_DEL = 0x04
CMD_DEL_ALL = 0x05
CMD_USER_CNT = 0x09
CMD_COMP_LEV = 0x28
CMD_LP_MODE = 0x2C
CMD_ADD_MODE = 0x2D
CMD_TIMEOUT = 0x2E

CMD_VERSION = 0x26

CMD_USER_PRI = 0x0A
CMD_COMP_ONE = 0x0B
CMD_COMP_MANY = 0x0C

CMD_ALL_USR = 0x2B

CMD_EXT_EGV = 0x23
CMD_UP_IMG = 0x24
CMD_UP_ONE_DB = 0x31

CMD_DOWN_ONE_DB = 0x41
CMD_DOWN_COMP_ONE = 0x42
CMD_DOWN_COMP_MANY = 0x43
CMD_DOWN_COMP = 0x44

class User:
    def __init__(self, high, low, privilege):
        self.high = high
        self.low = low
        self.privilege = privilege

    def __repr__(self):
        uid = bytes([self.high, self.low]).decode()
        pri = self.privilege
        return 'id: ' + uid + ', privilege: ' + pri


class FingerPrintReader:

    def __init__(self, port='/dev/ttyS0', baudrate=19200, timeout=None):
        self.rx_buf = []
        self.pc_cmd_rxbuf = []

        self.rLock = threading.RLock()
        self.ser = serial.Serial(port, baudrate, timeout=timeout)

    def __del__(self):
        self.ser.close()

    def tx_rx_cmd(self, cmd_buf, rx_bytes_need, timeout):
        """
        send a command, and wait for the response of module
        :param cmd_buf:
        :param rx_bytes_need:
        :param timeout:
        :return:
        """
        chksum = 0
        tx_buf = []

        tx_buf.append(CMD_HEAD)
        for byte in cmd_buf:
            tx_buf.append(byte)
            chksum ^= byte

        tx_buf.append(chksum)
        tx_buf.append(CMD_TAIL)

        self.ser.flushInput()
        self.ser.write(tx_buf)

        self.rx_buf = []
        time_before = time.time()
        time_after = time.time()
        while time_after - time_before < timeout and len(self.rx_buf) < rx_bytes_need:
            bytes_can_recv = self.ser.inWaiting()
            if bytes_can_recv != 0:
                self.rx_buf += self.ser.read(bytes_can_recv)
            time_after = time.time()

        if len(self.rx_buf) != rx_bytes_need:
            return ACK_TIMEOUT
        elif self.rx_buf[0] != CMD_HEAD:
            return ACK_FAIL
        elif self.rx_buf[rx_bytes_need - 1] != CMD_TAIL:
            return ACK_FAIL
        elif self.rx_buf[1] != tx_buf[1]:
            return ACK_FAIL

        chksum = 0
        for i, b in enumerate(self.rx_buf):
            if i == 0:
                continue
            elif i == 6:
                if chksum != b:
                    return ACK_FAIL
            else:
                chksum ^= b

        return ACK_SUCCESS

    def get_compare_level(self):
        """
        Get Compare Level
        :return:
        """
        cmd_buf = [CMD_COMP_LEV, 0, 0, 1, 0]
        res = self.tx_rx_cmd(cmd_buf, 8, 0.1)

        if res == ACK_SUCCESS and self.rx_buf[4] == ACK_SUCCESS:
            return self.rx_buf[3]
        else:
            return ACK_FAIL

    def set_compare_level(self, level):
        """
        Set Compare Level, the default value is 5, can be set to 0-9, the bigger, the stricter
        :param level: int 0-9
        :return: int
        """
        if level < 0 or level > 9:
            level = 5
        cmd_buf = [CMD_COMP_LEV, 0, level, 0, 0]
        res = self.tx_rx_cmd(cmd_buf, 8, 0.1)

        if res == ACK_SUCCESS and self.rx_buf == ACK_SUCCESS:
            return self.rx_buf[3]
        else:
            return ACK_FAIL

    def get_user_count(self):
        """
        Query the number of existing fingerprints
        :return: int
        """
        cmd_buf = [CMD_USER_CNT, 0, 0, 0, 0]
        res = self.tx_rx_cmd(cmd_buf, 8, 0.1)
        if res == ACK_SUCCESS and self.rx_buf[4] == ACK_SUCCESS:
            cnt = int.from_bytes(self.rx_buf[2:4], 'big')
            return cnt
        else:
            return ACK_FAIL

    def get_timeout(self):
        """
        Get the time that fingerprint collection wait timeout
        :return: timeout value of 0-255 is approximately val * 0.2~0.3s
        """
        cmd_buf = [CMD_TIMEOUT, 0, 0, 1, 0]
        res = self.tx_rx_cmd(cmd_buf, 8, 0.1)

        if res == ACK_SUCCESS and self.rx_buf[4] == ACK_SUCCESS:
            return self.rx_buf[3]
        else:
            return ACK_FAIL

    def add_user(self, user_id=None, user_pri=2):
        """
        Register fingerprint, 3 times attemps
        :return:
        """
        user_cnt = self.get_user_count()
        if user_cnt >= USER_MAX_CNT:
            return ACK_FULL

        if not user_id:
            user_id = user_cnt

        res = self.finger_add(user_id, user_pri, CMD_ADD_1)
        if res == ACK_SUCCESS:
            res = self.finger_add(user_id, user_pri, CMD_ADD_2)
        if res == ACK_SUCCESS:
            res = self.finger_add(user_id, user_pri, CMD_ADD_3)
        return res

    def finger_add(self, user_id, user_pri, cmd):
        byte_id = self.id_to_byte(user_id)
        cmd_buf = [cmd, byte_id[0], byte_id[1], user_pri, 0]
        res = self.tx_rx_cmd(cmd_buf, 8, 6)
        if res == ACK_TIMEOUT:
            return ACK_TIMEOUT
        elif res == ACK_USER_EXIST and self.rx_buf[4] == ACK_USER_EXIST:
            return ACK_USER_EXIST
        elif res == ACK_SUCCESS and self.rx_buf[4] == ACK_SUCCESS:
            return ACK_SUCCESS
        else:
            return ACK_FAIL

    def id_to_byte(self, user_id):
        if type(user_id) == int:
            return bytes(int(user_id).to_bytes(2, 'big'))
        else:
            if len(user_id) > 2:
                return bytes(user_id[-2:].encode())
            elif len(user_id) == 2:
                return bytes(user_id.encode())

    def del_specified_user(self, user_id):
        """
        delete specified user by id
        :param user_id: str or int
        :return:
        """
        byte_id = self.id_to_byte(user_id)
        cmd_buf = [CMD_DEL, byte_id[0], byte_id[1], 0, 0]
        res = self.tx_rx_cmd(cmd_buf, 8, 0.1)
        if res == ACK_SUCCESS:
            return ACK_SUCCESS
        else:
            return ACK_FAIL

    def clear_all_users(self):
        """
        Clear fingerprints
        :return:
        """
        cmd_buf = [CMD_DEL_ALL, 0, 0, 0, 0]
        res = self.tx_rx_cmd(cmd_buf, 8, 5)
        if res == ACK_FAIL:
            return ACK_TIMEOUT
        elif res == ACK_SUCCESS and self.rx_buf[4] == ACK_SUCCESS:
            return ACK_SUCCESS

    def get_user_privilege(self, user_id):
        """
        Get user privilege by user_id
        :param user_id: str or int
        :return: int
        """
        byte_id = self.id_to_byte(user_id)
        cmd_buf = [CMD_USER_PRI, byte_id[0], byte_id[1], 0, 0]
        res = self.tx_rx_cmd(cmd_buf, 8, 0.1)
        if res == ACK_NO_USER:
            return ACK_NO_USER
        else:
            return self.rx_buf[4]

    def compare_many(self):
        cmd_buf = [CMD_COMP_MANY, 0, 0, 0, 0]
        res = self.tx_rx_cmd(cmd_buf, 8, 5)

        if res == ACK_TIMEOUT:
            return ACK_TIMEOUT
        elif res == ACK_NO_USER and self.rx_buf[4] == ACK_NO_USER:
            return ACK_NO_USER
        else:
            return User(self.rx_buf[2], self.rx_buf[3], self.rx_buf[4])

    def compare_by_id(self, user_id):
        byte_id = self.id_to_byte(user_id)
        cmd_buf = [CMD_COMP_ONE, byte_id[0], byte_id[1], 0, 0]
        res = self.rx_buf(cmd_buf, 8, 5)
        if res == ACK_TIMEOUT:
            return ACK_TIMEOUT
        elif res == ACK_SUCCESS and self.rx_buf[4] == ACK_SUCCESS:
            return ACK_SUCCESS
        else:
            return ACK_FAIL

    def set_dormant(self):
        """
        fingerprint module will be sleep. for wake up send Reset signal or power on
        :return: None
        """
        cmd_buf = [CMD_LP_MODE, 0, 0, 0, 0]
        self.tx_rx_cmd(cmd_buf, 8, 0.1)

    def get_add_mode(self):
        """
        Get fingerprint add mode
        :return: 0 is allow repeat, 1 is prohibit repeat
        """
        cmd_buf = [CMD_ADD_MODE, 0, 0, 1, 0]
        res = self.tx_rx_cmd(cmd_buf, 8, 0.1)
        if res == ACK_SUCCESS and self.rx_buf[4] == ACK_SUCCESS:
            return self.rx_buf[3]
        else:
            return ACK_FAIL

    def set_add_mode(self, repeat=1):
        """
        Set fingerprint add mode
        :param repeat: allow repeat 0 or 1
        :return:
        """
        cmd_buf = [CMD_ADD_MODE, 0, repeat, 0, 0]
        res = self.tx_rx_cmd(cmd_buf, 8, 0.1)
        if res == ACK_SUCCESS and self.rx_buf[4] == ACK_SUCCESS:
            return self.rx_buf[3]
        else:
            return ACK_FAIL

    def set_comp_level(self, level=5):
        if 0 > level or 9 < level:
            raise ValueError('out of argument level range, 0 <= level <= 9')
        cmd_buf = [CMD_COMP_LEV, 0, level, 0, 0]
        res = self.tx_rx_cmd(cmd_buf, 8, 0.1)
        if res == ACK_SUCCESS and self.rx_buf[4] == ACK_SUCCESS:
            return self.rx_buf[3]
        else:
            return ACK_FAIL

    def get_comp_level(self):
        cmd_buf = [CMD_COMP_LEV, 0, 0, 1, 0]
        res = self.tx_rx_cmd(cmd_buf, 8, 0.1)
        if res == ACK_SUCCESS and self.rx_buf[4] == ACK_SUCCESS:
            return self.rx_buf[3]
        else:
            return ACK_FAIL

    def download_fp_imgs(self):
        """
        :return: Image binary data
        """
        cmd_buf = [CMD_UP_IMG, 0, 0, 0, 0]
        header = self.tx_rx_cmd(cmd_buf, 8, 6)
        if header == ACK_TIMEOUT:
            return ACK_TIMEOUT
        elif header == ACK_SUCCESS and self.rx_buf[4] == ACK_SUCCESS:
            data_len = int.from_bytes(header[2:4], 'big')
            packet = self.ser.read(data_len + 3)
            if check_packet(packet) == ACK_SUCCESS:
                return packet[1:-2]
        else:
            return ACK_FAIL

    def download_eigenvalue(self):
        cmd_buf = [CMD_EXT_EGV, 0, 0, 0, 0]



def check_packet(packet):
    if packet[0] == CMD_HEAD and packet[-1] == CMD_TAIL:
        chk = 0
        for byte in packet[1:-2]:
            chk ^= byte
        if chk == packet[-2]:
            return ACK_SUCCESS
        else:
            return ACK_FAIL
    else:
        return ACK_FAIL

def upload_extract_eigenvalue():
    return bytes([CMD_HEAD, CMD_UP_EXT, 0, 0,
                  0, 0, CMD_UP_EXT^0, CMD_TAIL])


def download_eigenvalues_comp_fingerprint(eigenvalues):
    egval_length = len(eigenvalues).to_bytes(2, 'big')
    header = bytes([CMD_HEAD, CMD_DOWN_ACQ, egval_length[0], egval_length[1],
              0, 0, CMD_DOWN_ACQ^0, CMD_TAIL])
    packet = bytes[CMD_HEAD, 0, 0, 0] + eigenvalues + 0^eigenvalues[1] + b'0xF5'
    return header + packet


def download_eigenvalues_comp_db_by_id(user_id, eigenvalues):
    id_high, id_low = id_to_byte(user_id)
    egval_length = len(eigenvalues).to_bytes(2, 'big')

    header = bytes([CMD_HEAD, CMD_DOWN_COMP, egval_length[0], egval_length[1],
                    0, 0, CMD_DOWN_COMP^0, CMD_TAIL])
    packet = bytes([CMD_HEAD, id_high, id_low, 0]) + eigenvalues + bytes([id_high^eigenvalues[1], CMD_TAIL])

    return header + packet


def download_eigenvalues_comp_db_many(eigenvalues):
    egval_length = len(eigenvalues).to_bytes(2, 'big')

    header = bytes([CMD_HEAD, CMD_DOWN_COMP_N, egval_length[0], egval_length[1],
                    0, 0, CMD_DOWN_COMP_N^0, CMD_TAIL])
    packet = bytes([CMD_HEAD, 0, 0, 0]) + eigenvalues + bytes([0^eigenvalues[1], CMD_TAIL])

    return header + packet


def upload_dsp_by_id(user_id):
    id_high, id_low = id_to_byte(user_id)

    return bytes([CMD_HEAD, CMD_UP_EGV, id_high, id_low, 0, 0, CMD_UP_EGV^0, CMD_TAIL])


def download_eigenvalue_save_by_id(user_id, eigenvalues, user_privilege=1):
    id_high, id_low = id_to_byte(user_id)
    egval_length = len(eigenvalues).to_bytes(2, 'big')

    header = bytes([CMD_HEAD, CMD_DOWN_SAVE, egval_length[0], egval_length[1],
                    0, 0, CMD_DOWN_SAVE^0, CMD_TAIL])
    packet = bytes([CMD_HEAD, id_high, id_low, user_privilege]) + \
             eigenvalues + bytes([id_high^eigenvalues[1], CMD_TAIL])

    return header + packet


def all_user_id_privilege():
    return bytes([CMD_HEAD, CMD_ALL_USR, 0, 0,
                  0, 0, 0^CMD_ALL_USR, CMD_TAIL])


def set_timeout(value):
    """
    If the value is 0, fingerprint acquisition process will keep continue, if no fingerprint prees on.
    otherwise timeout set be value * (0.2~0.3)s
    :param value: 0-255
    :return: 8 bytes
    """
    if value < 0 or 255 < value:
        raise AttributeError('argument value out of range')
    return bytes([CMD_HEAD, CMD_TIMEOUT, 0, value,
                  0, 0, CMD_TIMEOUT^0, CMD_TAIL])


def get_timeout():
    return bytes([CMD_HEAD, CMD_TIMEOUT, 0, 1])


#assert bytes([0xF5, 0x2C, 0, 0, 0, 0, 0x2C^0, 0xF5]) == set_dormant_state(), 'Dormant State Response Error!'
assert bytes([0xF5, 0x2D, 0, 0, 0, 0, 0x2D^0, 0xF5]) == fingerprint_mode('set', True), 'Set Fingerprint add mode allow repeat'
assert bytes([0xF5, 0x2D, 0, 0x01, 0, 0, 0x2D^0, 0xF5]) == fingerprint_mode('set', False), 'Set Fingerprint add mode prohibit repeat'
assert bytes([0xF5, 0x2D, 0, 0, 0x01, 0, 0x2D^0, 0xF5]) == fingerprint_mode('read'), 'Read Fingerprint add mode'
assert bytes([0xF5, 0x01, 0, 0, 0x01, 0, 0x01^0, 0xF5]) == add_fingerprint_first('0'), 'Add first Fingerprint should be correct'
assert bytes([0xF5, 0x02, 0, 0, 0x01, 0, 0x02^0, 0xF5]) == add_fingerprint_second('0'), 'Add second Fingerprint should be correct'
assert bytes([0xF5, 0x03, 0, 0, 0x01, 0, 0x03^0, 0xF5]) == add_fingerprint_third('0'), 'Add third Fingerprint should be correct'
assert bytes([0xF5, 0x04, 0, 0, 0, 0, 0x04^0, 0xF5]) == del_specified_user('0'), 'Delete specified user by user id'
assert bytes([0xF5, 0x05, 0, 0, 0, 0, 0x05^0, 0xF5]) == del_all_users(), 'Del all users'
assert bytes([0xF5, 0x0B, 0, 0, 0, 0, 0x0B^0, 0xF5]) == compare_by_id('0'), 'compare with 0 should be correct'

