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
    def __init__(self, high, low, privilege=None):
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
        res = self.tx_rx_cmd(cmd_buf, 8, 0.1)
        if res == ACK_TIMEOUT:
            return  ACK_TIMEOUT
        elif res == ACK_SUCCESS and self.rx_buf[4] == ACK_SUCCESS:
            data_len = int.from_bytes(self.rx_buf[2:4], 'big')
            packet = self.ser.read(data_len + 3)
            if check_packet(packet) == ACK_SUCCESS:
                eigenvalues = packet[4:-2]
                return eigenvalues
            else:
                return ACK_FAIL

        else:
            return ACK_FAIL

    def get_moudle_version(self):
        cmd_buf = [CMD_VERSION, 0, 0, 0, 0]
        header = self.tx_rx_cmd(cmd_buf, 8, 0.1)
        if header == ACK_SUCCESS:
            data_len = int.from_bytes(self.rx_buf[2:4], 'big')
            packet = self.ser.read(data_len + 3)
            if check_packet(packet) == ACK_SUCCESS:
                version = packet[1:-2].decode()
                return version
        else:
            return ACK_FAIL

    def up_comp_fingerprint(self, eigenval):
        """
        module download eigenvalues and comparison
        :param eigenval: binary data
        :return:
        """
        byte_len = len(eigenval).to_bytes(2, 'big')
        cmd_header = [CMD_DOWN_COMP, byte_len[0], byte_len[1], 0, 0]
        self.tx_rx_cmd(cmd_header, 8, 0.1)
        packet = bytes([CMD_HEAD, 0, 0, 0]) + eigenval
        chk = get_chksum(packet[1:])
        packet += bytes([chk, CMD_TAIL])

        res = self.ser.write(packet)
        if res[4] == ACK_SUCCESS:
            return ACK_SUCCESS
        elif res[4] == ACK_TIMEOUT:
            return ACK_TIMEOUT
        else:
            return ACK_FAIL

    def up_comp_by_id(self, eigenval, user_id):
        byte_len = int(len(eigenval)).to_bytes(2, 'big')
        header_buf = [CMD_HEAD, CMD_DOWN_COMP_ONE, byte_len[0], byte_len[1], 0, 0]
        chk = get_chksum(header_buf[1:])
        header_buf.append(chk)
        header_buf.append(CMD_TAIL)
        self.ser.write(header_buf)
        byte_id = self.id_to_byte(user_id)
        packet_buf = bytes([CMD_HEAD, byte_id[0], byte_id[1], 0]) + eigenval
        chk = get_chksum(packet_buf[1:])
        packet_buf += bytes([chk, CMD_TAIL])
        self.ser.write(packet_buf)
        res = self.ser.read(8)
        if res[4] == ACK_SUCCESS:
            return ACK_SUCCESS
        else:
            return ACK_FAIL

    def up_comp_many(self, eigenval):
        byte_len = int(len(eigenval)).to_bytes(2, 'big')
        cmd_header = [CMD_HEAD, CMD_DOWN_COMP_MANY, byte_len[0], byte_len[1], 0, 0]
        chk = get_chksum(cmd_header[1:])
        cmd_header += [chk, CMD_TAIL]
        self.ser.write(cmd_header)
        packet_buf = bytes([CMD_HEAD, 0, 0, 0]) + eigenval
        chk = get_chksum(packet_buf[1:])
        packet_buf += bytes([chk, CMD_TAIL])
        self.ser.write(packet_buf)
        res = self.ser.read(8)
        if res[4] == ACK_NO_USER:
            return ACK_NO_USER
        else:
            return User(res[2], res[3], res[4])

    def down_db_by_id(self, user_id):
        byte_id = self.id_to_byte(user_id)
        cmd_buf = [CMD_HEAD, CMD_UP_ONE_DB, byte_id[0], byte_id[1], 0, 0]
        chk = get_chksum(cmd_buf[1:])
        cmd_buf += [chk, CMD_TAIL]
        self.ser.write(cmd_buf)
        header = self.ser.read(8)
        if header[4] == ACK_SUCCESS:
            data_len = int.from_bytes(header[2:4], 'big')
            res = self.ser.read(data_len + 3)
            user = User(res[1], res[2], res[3])
            user.eigenvalue = res[4:-2]
            return user
        elif header[4] == ACK_NO_USER:
            return ACK_NO_USER
        else:
            return ACK_FAIL

    def up_eigen_save_by_id(self, user_id, eigenval):
        byte_len = int(len(eigenval)).to_bytes(2, 'big')
        header_buf = [CMD_HEAD, CMD_DOWN_ONE_DB, byte_len[0], byte_len[1], 0]
        chk = get_chksum(header_buf[1:])
        header_buf += [chk, CMD_TAIL]
        self.ser.write(header_buf)
        byte_id = self.id_to_byte(user_id)
        packet = bytes([CMD_HEAD, byte_id[0], byte_id[1], 2]) + eigenval
        chk = get_chksum(packet[1:])
        packet += ([chk, CMD_TAIL])
        self.ser.write(packet)
        res = self.ser.read(8)
        if res[4] == ACK_SUCCESS:
            return User(res[2], res[3])
        else:
            return ACK_FAIL

    def get_all_user_info(self):
        cmd_buf = [CMD_ALL_USR, 0, 0, 0, 0]
        header = self.tx_rx_cmd(cmd_buf, 8, 0.1)
        if header == ACK_SUCCESS:
            data_len = int.from_bytes(self.rx_buf[2:4], 'big')
            packet = self.ser.read(data_len + 3)
            if check_packet(packet) == ACK_SUCCESS:
                user_num = int.from_bytes(packet[2:4], 'big')
                users = []
                for i in range(user_num):
                    idx = i * 3
                    high = packet[idx]
                    low = packet[idx + 1]
                    pri = packet[idx + 2]
                    users.append(User(high, low, pri))
                return users
            else:
                return ACK_FAIL
        else:
            return ACK_FAIL


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


def get_chksum(data):
    chk = 0
    for byte in data:
        chk ^= byte
    return chk