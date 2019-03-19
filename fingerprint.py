#!/usr/bin/env python3
# This is WaveShare UART Fingerprint Reader Module

import serial
import time
from enum import Enum

USER_MAX_CNT = 4095     # Range of user number is 1 - 0xFFF


class Privilege(Enum):
    """
    User privilege
    """
    HIGH = 0x01
    MID = 0x02
    LOW = 0x03


class Command:
    """
    Command definition
    """
    CHK = 0
    CMD_LEN = 8

    HEAD = 0xF5
    TAIL = 0xF5
    ADD_1 = 0x01
    ADD_2 = 0x02
    ADD_3 = 0x03
    DEL = 0x04
    DEL_ALL = 0x05
    USER_CNT = 0x09
    COMP_LEV = 0x28
    SLEEP = 0x2C
    ADD_MODE = 0x2D
    TIMEOUT = 0x2E

    USER_PRI = 0x0A
    COMP_ONE = 0x0B
    COMP_MANY = 0x0C

    ALL_USR = 0x2B

    EXT_EGV = 0x23
    UP_IMG = 0x24
    VERSION = 0x26

    UP_ONE_DB = 0x31

    DOWN_ONE_DB = 0x41
    DOWN_COMP_ONE = 0x42
    DOWN_COMP_MANY = 0x43
    DOWN_COMP = 0x44


class Ack(Enum):
    """
    Fingerprint module response
    """
    SUCCESS = 0x00  # Operation successfully
    FAIL = 0x01  # Operation failed
    FULL = 0x04  # Fingerprint database is full
    NO_USER = 0x05  # No such user
    USER_EXIST = 0x06  # User already exists
    FINGER_EXIST = 0x07  # Fingerprint already exists
    TIMEOUT = 0x08  # Acquistion timeout


class Response:
    def __init__(self, ack, val=None):
        self.ack = ack
        self.value = val

    def __repr__(self):
        return 'Ack: {}, Value: {}'.format(self.ack, self.value)


class User:
    def __init__(self, high, low, privilege=None, eigenvalue=None):
        self.id = int.from_bytes([high, low], 'big')
        self.privilege = privilege
        self.eigenvalue = eigenvalue

    def __repr__(self):
        return 'Id: {}, Privilege: {}'.format(self.id, self.privilege)


class FingerPrintReader:
    def __init__(self, port='/dev/ttyS0', baudrate=19200, timeout=None):
        self.ser = serial.Serial(port, baudrate, timeout=timeout)

    def __del__(self):
        self.ser.close()

    def send_command(self, cmd_buf, rx_bytes_need, timeout):
        """
        send a command, and wait for the response of module
        :param cmd_buf:
        :param rx_bytes_need:
        :param timeout:
        :return: response bytes
        """
        assert cmd_buf[0] == Command.HEAD and cmd_buf[-1] == Command.TAIL, \
            'Request command 1st and last byte is 0xF5'

        cmd_buf[-2] = get_chksum(cmd_buf[1:-2])

        self.ser.flushInput()
        self.ser.write(cmd_buf)

        rx_buf = []
        time_before = time.time()
        time_after = time.time()
        while time_after - time_before < timeout and len(rx_buf) < rx_bytes_need:
            rx_buf += self.ser.read(rx_bytes_need)
            time_after = time.time()

        assert len(rx_buf) == rx_bytes_need and rx_buf[1] == cmd_buf[1], 'Response is error!'

        return rx_buf

    def send_command_response(self, cmd):
        assert cmd[0] == Command.HEAD and cmd[-1] == Command.TAIL
        cmd = calc_chksum(cmd)
        self.ser.flushInput()
        self.ser.write(cmd)
        rx_buf = []
        rx_buf += self.ser.read(8)
        if self.ser.in_waiting > 0 and Ack(rx_buf[4]) == Ack.SUCCESS :
            data_len = int.from_bytes(rx_buf[2:4], 'big')
            packet_buf = self.ser.read(data_len + 3)
            assert packet_buf[-2] == get_chksum(packet_buf[1:-2])
            return Response(Ack.SUCCESS, packet_buf)
        elif Ack(rx_buf[4]) == Ack.SUCCESS or rx_buf[4] in (1, 2, 3):
            return Response(Ack.SUCCESS, rx_buf)
        else:
            return Response(Ack(rx_buf[4]))

    def send_cmd_packet(self, header, packet, rx_bytes_need):
        """
        send header and packet bytes
        :param header: bytes
        :param packet: bytes
        :param rx_bytes_need: int
        :return: bytes
        """
        assert (Command(header[0]) == Command.HEAD and
            Command(header[-1]) == Command.TAIL), 'Data header error'
        header[-2] = get_chksum(header[1:-2])
        self.ser.flushInput()
        self.ser.write(header+packet)
        rx_buf = []
        while len(rx_buf) < rx_bytes_need:
            rx_buf += self.ser.read(rx_bytes_need)

        return rx_buf

    def get_compare_level(self):
        """
        Get Compare Level
        :return: int level value (1 - 9) default 5
        """
        cmd_buf = [Command.HEAD, Command.COMP_LEV, 0, 0,
                   1, 0, Command.CHK, Command.TAIL]
        res = self.send_command(cmd_buf, Command.CMD_LEN, 0.1)

        if Ack(res[4]) == Ack.SUCCESS:
            return res[3]
        else:
            return Ack.FAIL

    def set_compare_level(self, level):
        """
        Set Compare Level, the default value is 5, can be set to 0-9, the bigger, the stricter
        :param level: int 0-9
        :return: int
        """
        if level < 0 or level > 9:
            level = 5
        cmd_buf = [Command.TAIL, Command.COMP_LEV, 0, level,
                   0, 0, Command.CHK, Command.TAIL]
        res = self.send_command(cmd_buf, Command.CMD_LEN, 0.1)

        if Ack(res[4]) == Ack.SUCCESS:
            return res[3]
        else:
            return Ack.FAIL

    def get_user_count(self):
        """
        Query the number of existing fingerprints
        :return: int user count number
        """
        cmd_buf = [Command.HEAD, Command.USER_CNT, 0, 0,
                   0, 0, Command.CHK, Command.TAIL]
        res = self.send_command(cmd_buf, Command.CMD_LEN, 0.1)
        if Ack(res[4]) == Ack.SUCCESS:
            return int.from_bytes(res[2:4], 'big')
        else:
            return Ack(res[4])

    def get_timeout(self):
        """
        Get the time that fingerprint collection wait timeout
        :return: timeout value of 0-255 is approximately val * 0.2~0.3s
        """
        cmd_buf = [Command.HEAD, Command.TIMEOUT, 0, 0,
                   1, 0, Command.CHK, Command.TAIL]
        res = self.send_command(cmd_buf, Command.CMD_LEN, 0.1)

        if Ack(res[4]) == Ack.SUCCESS:
            return res[3]
        else:
            return Ack(res[4])

    def add_user(self, user_id=None, user_pri=Privilege.MID):
        """
        Register fingerprint, 3 times attemps
        :return: Response
        """
        adds = [Command.ADD_1, Command.ADD_2, Command.ADD_3]
        res = None
        for add in adds:
            res = self.finger_add(user_id, user_pri, add)
            if Ack(res[4]) != Ack.SUCCESS:
                return Ack(res[4])

        return Ack(res[4])

    def finger_add(self, user_id, user_pri, cmd2th):
        byte_id = text_to_byte(user_id)
        cmd_buf = [Command.HEAD, cmd2th, byte_id[0], byte_id[1],
                   user_pri, 0, Command.CHK, Command.TAIL]
        res = self.send_command(cmd_buf, Command.CMD_LEN, 6)
        return res

    def del_specified_user(self, user_id):
        """
        delete specified user by id
        :param user_id: str or int
        :return: Response result
        """
        byte_id = text_to_byte(user_id)
        cmd_buf = [Command.HEAD, Command.DEL, byte_id[0], byte_id[1],
                   0, 0, Command.CHK, Command.TAIL]
        res = self.send_command(cmd_buf, 8, 0.1)
        return Ack(res[4])

    def clear_all_users(self):
        """
        Clear fingerprints
        :return: Response Result
        """
        cmd_buf = [Command.HEAD, Command.DEL_ALL, 0, 0,
                   0, 0, Command.CHK, Command.TAIL]
        res = self.send_command(cmd_buf, Command.CMD_LEN, 5)
        return Ack(res[4])

    def get_user_privilege(self, user_id):
        """
        Get user privilege by user_id
        :param user_id: str or int
        :return: privilege or Response
        """
        byte_id = text_to_byte(user_id)
        cmd_buf = [Command.HEAD, Command.USER_PRI, byte_id[0], byte_id[1],
                   0, 0, Command.CHK, Command.TAIL]
        res = self.send_command(cmd_buf, 8, 0.1)
        if res[4] in (1, 2, 3):
            return Privilege(res[4])
        else:
            return Ack(res[4])

    def compare_many(self):
        """
        normal authroize user fingerprint
        :return: User Info or Response
        """
        cmd_buf = [Command.HEAD, Command.COMP_MANY, 0, 0,
                   0, 0, Command.CHK, Command.TAIL]
        res = self.send_command(cmd_buf, Command.CMD_LEN, 6)

        if res[4] in (1, 2, 3):
            return User(res[2], res[3], res[4])
        else:
            return Ack(res[4])

    def compare_by_id(self, user_id):
        """
        authorize specified user
        :param user_id: int or str
        :return: Response
        """
        byte_id = text_to_byte(user_id)
        cmd_buf = [Command.HEAD, Command.COMP_ONE, byte_id[0], byte_id[1],
                   0, 0, Command.CHK, Command.TAIL]
        res = self.send_command(cmd_buf, Command.CMD_LEN, 5)
        return Ack(res[4])

    def set_dormant(self):
        """
        fingerprint module will be sleep. for wake up send Reset signal or power on
        :return: Response
        """
        cmd_buf = [Command.HEAD, Command.SLEEP, 0, 0,
                   0, 0, Command.CHK, Command.TAIL]
        res = self.send_command(cmd_buf, Command.CMD_LEN, 0.1)
        return Ack(res[4])

    def get_add_mode(self):
        """
        Get fingerprint add mode
        :return: 0 is allow repeat, 1 is prohibit repeat or Response
        """
        cmd_buf = [Command.HEAD, Command.ADD_MODE, 0, 0,
                   1, 0, Command.CHK, Command.TAIL]
        res = self.send_command(cmd_buf, Command.CMD_LEN, 0.1)
        if Ack(res[4]) == Ack.SUCCESS:
            return res[3]
        else:
            return Ack(res[4])

    def set_add_mode(self, repeat=1):
        """
        Set fingerprint add mode
        :param repeat: allow repeat is 0 or prohibit is 1
        :return: Response
        """
        cmd_buf = [Command.HEAD, Command.ADD_MODE, 0, repeat,
                   0, 0, Command.CHK, Command.TAIL]
        res = self.send_command(cmd_buf, Command.CMD_LEN, 0.1)
        if Ack(res[4]) == Ack.SUCCESS:
            return res[3]
        else:
            return Ack(res[4])

    def set_comp_level(self, level=5):
        """
        set comparison level 0 - 9
        :param level: int
        :return: comparison value or Response
        """
        if 0 > level or 9 < level:
            level = 5
        cmd_buf = [Command.HEAD, Command.COMP_LEV, 0, level,
                   0, 0, Command.CHK, Command.TAIL]
        res = self.send_command(cmd_buf, Command.CMD_LEN, 0.1)
        if Ack(res[4]) == Ack.SUCCESS:
            return res[3]
        else:
            return Ack(res[4])

    def get_comp_level(self):
        """
        get comparison value 0 - 9
        :return: int or Response
        """
        cmd_buf = [Command.HEAD, Command.COMP_LEV, 0, 0,
                   1, 0, Command.CHK, Command.TAIL]
        res = self.send_command(cmd_buf, Command.CMD_LEN, 0.1)
        if Ack(res[4]) == Ack.SUCCESS:
            return res[3]
        else:
            return Ack(res[4])

    def download_fp_imgs(self):
        """
        :return: Image binary data or Response
        """
        cmd_buf = [Command.HEAD, Command.UP_IMG, 0, 0,
                   0, 0, Command.CHK, Command.TAIL]
        head = self.send_command(cmd_buf, Command.CMD_LEN, 6)
        if Ack(head[4]) == Ack.SUCCESS:
            data_len = int.from_bytes(head[2:4], 'big')
            body = self.ser.read(data_len + 3)
            return receive_packet(body, 1, -2)
        else:
            return Ack(head[4])

    def download_eigenvalue(self):
        """
        read fingerprint eigenvalue
        :return: binary or Response
        """
        cmd_buf = [Command.HEAD, Command.EXT_EGV, 0, 0,
                   0, 0, Command.CHK, Command.TAIL]
        head = self.send_command(cmd_buf, Command.CMD_LEN, 0.1)
        if Ack(head[4]) == Ack.SUCCESS:
            data_len = int.from_bytes(head[2:4], 'big')
            body = self.ser.read(data_len + 3)
            return receive_packet(body, 4, -2)
        else:
            return Ack(head[4])

    def get_module_version(self):
        """
        get module version data
        :return: version str or Response
        """
        cmd_buf = [Command.HEAD, Command.VERSION, 0, 0,
                   0, 0, Command.CHK, Command.TAIL]
        head = self.send_command(cmd_buf, Command.CMD_LEN, 0.1)
        if Ack(head[4]) == Ack.SUCCESS:
            data_len = int.from_bytes(head[2:4], 'big')
            body = self.ser.read(data_len + 3)
            return receive_packet(body, 1, -2)
        else:
            return Ack(head[4])

    def up_comp_fingerprint(self, eigenval):
        """
        module download eigenvalues and comparison
        :param eigenval: binary data
        :return: Response
        """
        byte_len = len(eigenval).to_bytes(2, 'big')
        head = bytes([Command.HEAD, Command.DOWN_COMP, byte_len[0], byte_len[1],
                          0, 0, Command.CHK, Command.TAIL])
        packet = bytes([Command.HEAD, 0, 0, 0])
        packet += eigenval
        packet += bytes([Command.CHK, Command.TAIL])
        packet[-2] = get_chksum(packet[1:-2])

        res = self.send_cmd_packet(head, packet, 8)

        return Ack(res[4])

    def up_comp_by_id(self, eigenval, user_id):
        byte_len = len(eigenval).to_bytes(2, 'big')
        head = [Command.HEAD, Command.DOWN_COMP_ONE, byte_len[0], byte_len[1],
                    0, 0, Command.CHK, Command.TAIL]
        byte_id = text_to_byte(user_id)
        packet = bytes([Command.HEAD, byte_id[0], byte_id[1], 0])
        packet += eigenval
        packet += bytes([Command.CHK, Command.TAIL])
        packet[-2] = get_chksum(packet[1:-2])
        res = self.send_cmd_packet(head, packet, 8)

        return Ack(res[4])

    def up_comp_many(self, eigenval):
        byte_len = len(eigenval).to_bytes(2, 'big')
        header = [Command.HEAD, Command.DOWN_COMP_MANY, byte_len[0], byte_len[1],
                      0, 0, Command.CHK, Command.TAIL]
        packet = [Command.HEAD, 0, 0, 0]
        packet += eigenval
        packet += [Command.CHK, Command.TAIL]
        packet[-2] = get_chksum(packet[1:-2])

        res = self.send_cmd_packet(header, packet, 8)

        if Ack(res[4]) == Ack.NO_USER:
            return Ack(res[4])
        else:
            return User(res[2], res[3], res[4])

    def download_user_eigenvalue(self, user_id):
        id_high, id_low = text_to_byte(user_id)
        cmd = [Command.HEAD, Command.UP_ONE_DB, id_high, id_low,
               0, 0, Command.CHK, Command.TAIL]
        head = self.send_command(cmd, Command.CMD_LEN, 0.1)
        if Ack(head[4]) == Ack.SUCCESS:
            data_len = int.from_bytes(head[2:4], 'big')
            packet = self.ser.read(data_len + 3)
            return receive_packet(packet, 1, -2)
        else:
            return Ack(head[4])

    def add_fingerprint_by_data(self, user_id, user_pri, eigenvalue):
        id_high, id_low = text_to_byte(user_id)
        high_len, low_len = int.to_bytes(len(eigenvalue), 2, 'big')
        cmd_header = [Command.HEAD, Command.DOWN_ONE_DB, high_len, low_len,
                      0, 0, Command.CHK, Command.TAIL]
        cmd_packet = [Command.HEAD, id_high, id_low, user_pri]
        cmd_packet += eigenvalue
        cmd_packet += [Command.CHK, Command.TAIL]
        cmd_packet[-2] = get_chksum(cmd_packet[1:-2])
        res = self.send_cmd_packet(cmd_header, cmd_packet, 8)
        if Ack(res[4]) == Ack.SUCCESS:
            return User(id_high, id_low, user_pri)
        else:
            return Ack(res[4])

    def get_all_user_info(self):
        cmd_buf = [Command.HEAD, Command.ALL_USR, 0, 0,
                   0, 0, Command.CHK, Command.TAIL]
        header = self.send_command(cmd_buf, Command.CMD_LEN, 0.1)
        if Ack(header[4]) == Ack.SUCCESS:
            data_len = int.from_bytes(header[2:4], 'big')
            packet = self.ser.read(data_len + 3)
            packet = receive_packet(packet, 1, -2)
            if packet is not Ack.FAIL:
                return get_users(packet)
            else:
                return Ack.FAIL
        else:
            return Ack(header[4])


def receive_packet(packet, start, end):
    if not ((packet[0] == Command.HEAD and packet[-1] == Command.TAIL)
            and (packet[-2] == get_chksum(packet[1:-2]))):
        return Ack.FAIL
    else:
        return packet[start:end]


def get_chksum(data):
    chk = 0
    for b in data:
        chk ^= b
    return chk


def text_to_byte(user_id):
    if type(user_id) == int:
        return bytes(int(user_id).to_bytes(2, 'big'))
    else:
        return bytes(user_id[:2].encode())


def get_users(packet):
    user_num = int.from_bytes(packet[:2], 'big')
    user_packet = packet[2:]
    users = []
    for i in range(user_num):
        idx = i * 3
        id_high, id_low, pri = user_packet[idx], user_packet[idx+1], user_packet[idx+2]
        user = User(id_high, id_low, pri)
        users.append(user)
    return users


def calc_chksum(data):
    """
    calculate checksum data
    :param data: bytes
    :return: bytes
    """
    data[-2] = get_chksum(data[1:-2])
    return data
