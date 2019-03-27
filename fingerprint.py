#!/usr/bin/env python3
# This is WaveShare UART Fingerprint Reader Module

import serial
import time
from enum import Enum, IntEnum

USER_MAX_CNT = 4095     # Range of user number is 1 - 0xFFF


class Privilege(IntEnum):
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
        self.val = val

    def __repr__(self):
        return 'Ack: {}, Value: {}'.format(self.ack, self.val)


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

    def read_reader(self, bytes_need, timeout):
        time_before = time.time()
        time_after = time.time()
        res = []
        while time_after - time_before < timeout and len(res) < bytes_need:
            res += self.ser.read(bytes_need)
            time_after = time.time()
        return res

    def send_command_response(self, cmd):
        assert cmd[0] == Command.HEAD and cmd[-1] == Command.TAIL
        cmd = calc_chksum(cmd)
        self.ser.flushInput()
        self.ser.write(cmd)
        rx_buf = self.read_reader(8, 1)
        print(rx_buf)

        if self.ser.in_waiting > 0 and Ack(rx_buf[4]) == Ack.SUCCESS:
            data_len = int.from_bytes(rx_buf[2:4], 'big')
            packet_buf = self.read_reader(data_len + 3, 2)
            assert packet_buf[-2] == get_chksum(packet_buf[1:-2])
            return Response(Ack.SUCCESS, packet_buf)
        elif (rx_buf[1] in (Command.COMP_MANY, Command.USER_PRI, Command.DOWN_COMP_MANY)
              and rx_buf[4] in (1, 2, 3)) or Ack(rx_buf[4]) == Ack.SUCCESS:
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
        rx_buf = self.read_reader(rx_bytes_need, 1)

        if Ack(rx_buf[4]) == Ack.SUCCESS:
            return Response(Ack.SUCCESS, rx_buf)
        else:
            return Response(Ack(rx_buf[4]))

    def get_compare_level(self):
        """
        Get Compare Level
        :return: int level value (1 - 9) default 5
        """
        cmd_buf = [Command.HEAD, Command.COMP_LEV, 0, 0,
                   1, 0, Command.CHK, Command.TAIL]
        res = self.send_command_response(cmd_buf)
        return res

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
        self.send_command_response(cmd_buf)
        time.sleep(2)
        res = self.get_compare_level()
        res.val = res.val[3]
        return res

    def get_user_count(self):
        """
        Query the number of existing fingerprints
        :return: int user count number
        """
        cmd_buf = [Command.HEAD, Command.USER_CNT, 0, 0,
                   0, 0, Command.CHK, Command.TAIL]
        res = self.send_command_response(cmd_buf)
        if res.ack == Ack.SUCCESS:
            res.val = int.from_bytes(res.val[2:4], 'big')
        return res

    def get_timeout(self):
        """
        Get the time that fingerprint collection wait timeout
        :return: timeout value of 0-255 is approximately val * 0.2~0.3s
        """
        cmd_buf = [Command.HEAD, Command.TIMEOUT, 0, 0,
                   1, 0, Command.CHK, Command.TAIL]
        res = self.send_command_response(cmd_buf)

        if res.ack == Ack.SUCCESS:
            res.val = res.val[3]
        return res

    def add_user(self, user_id=None, user_pri=Privilege.MID):
        """
        Register fingerprint, 3 times attemps
        :return: Response
        """
        adds = [Command.ADD_1, Command.ADD_2, Command.ADD_3]
        res = None
        for add in adds:
            res = self.finger_add(user_id, Privilege(user_pri), add)
            if res.ack != Ack.SUCCESS:
                res.val = None
                return res
        res.val = None
        return res

    def finger_add(self, user_id, user_pri, cmd2th):
        """
        subroutine of add_user method
        :param user_id: number use for user identification
        :param user_pri: user privilege in 1, 2, 3. high, mid, low
        :param cmd2th: command byte
        :return: Response of command
        """
        byte_id = text_to_byte(user_id)
        cmd_buf = [Command.HEAD, cmd2th, byte_id[0], byte_id[1],
                   user_pri, 0, Command.CHK, Command.TAIL]
        res = self.send_command_response(cmd_buf)
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
        res = self.send_command_response(cmd_buf)
        res.val = None
        return res

    def clear_all_users(self):
        """
        Clear fingerprints
        :return: Response Result
        """
        cmd_buf = [Command.HEAD, Command.DEL_ALL, 0, 0,
                   0, 0, Command.CHK, Command.TAIL]
        res = self.send_command_response(cmd_buf)
        res.val = None
        return res

    def get_user_privilege(self, user_id):
        """
        Get user privilege by user_id
        :param user_id: str or int
        :return: privilege or Response
        """
        byte_id = text_to_byte(user_id)
        cmd_buf = [Command.HEAD, Command.USER_PRI, byte_id[0], byte_id[1],
                   0, 0, Command.CHK, Command.TAIL]
        res = self.send_command_response(cmd_buf)
        if res.ack == Ack.SUCCESS:
            res.val = Privilege(res.val[4])
        return res

    def compare_many(self):
        """
        normal authroize user fingerprint
        :return: User Info or Response
        """
        cmd_buf = [Command.HEAD, Command.COMP_MANY, 0, 0,
                   0, 0, Command.CHK, Command.TAIL]
        res = self.send_command_response(cmd_buf)

        if res.ack == Ack.SUCCESS:
            res.val = User(res.val[2], res.val[3], res.val[4])
        return res

    def compare_by_id(self, user_id):
        """
        authorize specified user
        :param user_id: int or str
        :return: Response
        """
        byte_id = text_to_byte(user_id)
        cmd_buf = [Command.HEAD, Command.COMP_ONE, byte_id[0], byte_id[1],
                   0, 0, Command.CHK, Command.TAIL]
        res = self.send_command_response(cmd_buf)
        res.val = None
        return res

    def set_dormant(self):
        """
        fingerprint module will be sleep. for wake up send Reset signal or power on
        :return: Response
        """
        cmd_buf = [Command.HEAD, Command.SLEEP, 0, 0,
                   0, 0, Command.CHK, Command.TAIL]
        res = self.send_command_response(cmd_buf)
        res.val = None
        return res

    def get_add_mode(self):
        """
        Get fingerprint add mode
        :return: 0 is allow repeat, 1 is prohibit repeat or Response
        """
        cmd_buf = [Command.HEAD, Command.ADD_MODE, 0, 0,
                   1, 0, Command.CHK, Command.TAIL]
        res = self.send_command_response(cmd_buf)
        if res.ack == Ack.SUCCESS:
            res.val = res.val[3]
        return res

    def set_add_mode(self, repeat=1):
        """
        Set fingerprint add mode
        :param repeat: allow repeat is 0 or prohibit is 1
        :return: Response
        """
        cmd_buf = [Command.HEAD, Command.ADD_MODE, 0, repeat,
                   0, 0, Command.CHK, Command.TAIL]
        res = self.send_command_response(cmd_buf)
        if res.ack == Ack.SUCCESS:
            res.val = res.val[3]
        return res

    def download_fp_imgs(self):
        """
        :return: Image binary data or Response
        """
        cmd_buf = [Command.HEAD, Command.UP_IMG, 0, 0,
                   0, 0, Command.CHK, Command.TAIL]
        res = self.send_command_response(cmd_buf)
        if res.ack == Ack.SUCCESS:
            res.val = res.val[1:-2]
        return res

    def download_eigenvalue(self):
        """
        read fingerprint eigenvalue
        :return: binary or Response
        """
        cmd_buf = [Command.HEAD, Command.EXT_EGV, 0, 0,
                   0, 0, Command.CHK, Command.TAIL]
        res = self.send_command_response(cmd_buf)
        if res.ack == Ack.SUCCESS:
            res.val = res.val[4:-2]
        return res

    def get_module_version(self):
        """
        get module version data
        :return: version str or Response
        """
        cmd_buf = [Command.HEAD, Command.VERSION, 0, 0,
                   0, 0, Command.CHK, Command.TAIL]
        res = self.send_command_response(cmd_buf)
        if res.ack == Ack.SUCCESS:
            res.val = bytes(res.val[1:-2]).decode('utf8')
        return res

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
        res.val = None
        return res

    def up_comp_by_id(self, eigenval, user_id):
        """
        Module download fingerprint eigen value and compare by user id
        :param eigenval: binary data
        :param user_id: number of user identification
        :return: Response
        """
        byte_len = len(eigenval).to_bytes(2, 'big')
        head = [Command.HEAD, Command.DOWN_COMP_ONE, byte_len[0], byte_len[1],
                    0, 0, Command.CHK, Command.TAIL]
        byte_id = text_to_byte(user_id)
        packet = bytes([Command.HEAD, byte_id[0], byte_id[1], 0])
        packet += eigenval
        packet += bytes([Command.CHK, Command.TAIL])
        packet[-2] = get_chksum(packet[1:-2])
        res = self.send_cmd_packet(head, packet, 8)
        res.val = None
        return res

    def up_comp_many(self, eigenval):
        """
        Module get fingerprint eigenvalue and compare finger exist
        :param eigenval: binary
        :return: Response val User
        """
        byte_len = len(eigenval).to_bytes(2, 'big')
        header = [Command.HEAD, Command.DOWN_COMP_MANY, byte_len[0], byte_len[1],
                      0, 0, Command.CHK, Command.TAIL]
        packet = [Command.HEAD, 0, 0, 0]
        packet += eigenval
        packet += [Command.CHK, Command.TAIL]
        packet[-2] = get_chksum(packet[1:-2])

        res = self.send_cmd_packet(header, packet, 8)

        if res.ack == Ack.NO_USER:
            pass
        else:
            res.val = User(res.val[2], res.val[3], res.val[4])
        return res

    def download_user_eigenvalue(self, user_id):
        """
        Client get user eigenvalue by user_id
        :param user_id: number
        :return: Response val binary
        """
        id_high, id_low = text_to_byte(user_id)
        cmd = [Command.HEAD, Command.UP_ONE_DB, id_high, id_low,
               0, 0, Command.CHK, Command.TAIL]
        res = self.send_command_response(cmd)
        if res.ack == Ack.SUCCESS:
            res.val = res.val[1:-2]
        return res

    def add_fingerprint_by_data(self, user_id, user_pri, eigenvalue):
        """
        Module get eigen value and save the fingerprint by user id and privilege
        :param user_id: number
        :param user_pri: number or Privilege
        :param eigenvalue: binary data
        :return: Response val User
        """
        id_high, id_low = text_to_byte(user_id)
        high_len, low_len = int.to_bytes(len(eigenvalue), 2, 'big')
        cmd_header = [Command.HEAD, Command.DOWN_ONE_DB, high_len, low_len,
                      0, 0, Command.CHK, Command.TAIL]
        cmd_packet = [Command.HEAD, id_high, id_low, user_pri]
        cmd_packet += eigenvalue
        cmd_packet += [Command.CHK, Command.TAIL]
        cmd_packet[-2] = get_chksum(cmd_packet[1:-2])
        res = self.send_cmd_packet(cmd_header, cmd_packet, 8)
        if res.ack == Ack.SUCCESS:
            res.val = User(id_high, id_low, user_pri)
        return res

    def get_all_user_info(self):
        """
        Registered all user information
        :return: Response of User List
        """
        cmd_buf = [Command.HEAD, Command.ALL_USR, 0, 0,
                   0, 0, Command.CHK, Command.TAIL]
        res = self.send_command_response(cmd_buf)
        if res.ack == Ack.SUCCESS:
            res.val = get_users(res.val[1:-2])
        return res


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
