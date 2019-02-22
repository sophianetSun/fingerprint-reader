#! python3
# This is WaveShare UART Fingerprint module

ACK_SUCCESS = 0x00      # Operation successfully
ACK_FAIL = 0x01         # Operation failed
ACK_FULL = 0x04         # Fingerprint database is full
ACK_NO_USER = 0x05      # No such user
ACK_USER_EXIST = 0x06   # User already exists
ACK_FIN_EXIST = 0x07    # Fingerprint already exists
ACK_TIMEOUT = 0x08      # Acquistion timeout
ACK_GO_OUT = 0x0F

ACK_ALL_USER = 0x00
ACK_GUEST_USER = 0x01
ACK_NORMAL_USER = 0x02
ACK_MASTER_USER = 0x03

USER_MAX_CNT = 40
# MAX = 1000

CMD_HEAD = 0xF5
CMD_TAIL = 0xF5
CMD_ADD_1 = 0x01
CMD_ADD_2 = 0x02
CMD_ADD_3 = 0x03
CMD_MATCH = 0x0C
CMD_DEL = 0x04
CMD_DEL_ALL = 0x05
CMD_USER_CNT = 0x09
CMD_COMP_LEV = 0x28
CMD_LP_MODE = 0x2C
CMD_TIMEOUT = 0x2E

CMD_FINGER_DETECTED = 0x14

CMD_ACQ_VER = 0x26

CMD_USER_PRI = 0x0A
CMD_COMP_ONE = 0x0B
CMD_COMP_MANY = 0x0C

CMD_ALL_USR = 0x2B

CMD_UP_EXT = 0x23
CMD_ACQ_UP = 0x24
CMD_UP_EGV = 0x31

CMD_DOWN_SAVE = 0x41
CMD_DOWN_COMP = 0x42
CMD_DOWN_COMP_N = 0x43
CMD_DOWN_ACQ = 0x44


def set_dormant_state():
    """
    fingerprint will be sleep.
    :return: 8 bytes
    """
    CHK = CMD_LP_MODE^0
    return bytes([CMD_HEAD, CMD_LP_MODE, 0, 0, 0, 0, CHK, CMD_TAIL])


def fingerprint_mode(mode, repeat=True):
    """
    set finger print add mode
    :param mode: should be 'set' or 'read'
    :param repeat: allow repeat, same finger can add one user only, Boolean
    :return: 8 bytes
    """
    cmd_add_mode = 0x2D
    cmd_repeat = 0
    chk = cmd_add_mode ^ 0

    if not repeat:
        cmd_repeat = 1

    if mode == 'set':
        cmd_set_mode = 0
        return bytes([CMD_HEAD, cmd_add_mode, 0, cmd_repeat,
                      cmd_set_mode, 0, chk, CMD_TAIL])
    elif mode == 'read':
        cmd_read_mode = 1
        return bytes([CMD_HEAD, cmd_add_mode, 0, cmd_repeat,
                      cmd_read_mode, 0, chk, CMD_TAIL])
    else:
        raise ValueError('mode should be "set" or "read"')


def id_to_byte(user_id=''):
    if type(user_id) is int:
        user_id = str(user_id)
    uid = user_id.encode()

    if len(uid) == 0:
        import random
        uid = int(random.random() * 4000).to_bytes(2, 'big')
    elif len(uid) == 1:
        uid = bytes([0, int(uid)])
    else:
        uid = uid[:2]

    return uid[0], uid[1]


def add_fingerprint_first(user_id='', user_privilege=1):
    id_high, id_low = id_to_byte(user_id)

    return bytes([CMD_HEAD, CMD_ADD_1, id_high, id_low,
                  user_privilege, 0, CMD_ADD_1^0, CMD_TAIL])


def add_fingerprint_second(user_id='', user_privilege=1):
    id_high, id_low = id_to_byte(user_id)

    return bytes([CMD_HEAD, CMD_ADD_2, id_high, id_low,
                  user_privilege, 0, CMD_ADD_2^0, CMD_TAIL])


def add_fingerprint_third(user_id='', user_privilege=1):
    id_high, id_low = id_to_byte(user_id)

    return bytes([CMD_HEAD, CMD_ADD_3, id_high, id_low,
                  user_privilege, 0, CMD_ADD_3^0, CMD_TAIL])


def del_specified_user(user_id):
    id_high, id_low = id_to_byte(user_id)

    return bytes([CMD_HEAD, CMD_DEL, id_high, id_low,
                  0, 0, CMD_DEL^0, CMD_TAIL])


def del_all_users():
    return bytes([CMD_HEAD, CMD_DEL_ALL, 0, 0,
                  0, 0, CMD_DEL_ALL^0, CMD_TAIL])


def get_total_users():
    return bytes([CMD_HEAD, CMD_USER_CNT, 0, 0,
                  0, 0, CMD_USER_CNT^0, CMD_TAIL])


def compare_by_id(user_id):
    id_high, id_low = id_to_byte(user_id)

    return bytes([CMD_HEAD, CMD_COMP_ONE, id_high, id_low,
                  0, 0, CMD_COMP_ONE ^ 0, CMD_TAIL])


def compare_many():
    return bytes([CMD_HEAD, CMD_COMP_MANY, 0, 0,
                  0, 0, 0, CMD_COMP_MANY^0, CMD_TAIL])


def get_user_privilege(user_id):
    id_high, id_low = id_to_byte(user_id)

    return bytes([CMD_HEAD, CMD_USER_PRI, id_high, id_low,
                  0, 0, CMD_USER_PRI^0, CMD_TAIL])


def get_dsp_version():
    return bytes([CMD_HEAD, CMD_ACQ_VER, 0, 0,
                  0, 0, CMD_ACQ_VER^0, CMD_TAIL])


def set_comp_level(level=5):
    if 0 > level or 9 < level:
        raise ValueError('out of argument level range, 0 <= level <= 9')
    return bytes([CMD_HEAD, CMD_COMP_LEV, 0, level, 0,
                  0, 0, CMD_COMP_LEV^0, CMD_TAIL])


def get_comp_level():
    return bytes([CMD_HEAD, CMD_COMP_LEV, 0, 0,
                  1, 0, CMD_COMP_LEV^0, CMD_TAIL])


def acquire_upload_imgs():
    return bytes([CMD_HEAD, CMD_ACQ_UP, 0, 0,
                  0, 0, CMD_ACQ_UP^0, 0])


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


assert bytes([0xF5, 0x2C, 0, 0, 0, 0, 0x2C^0, 0xF5]) == set_dormant_state(), 'Dormant State Response Error!'
assert bytes([0xF5, 0x2D, 0, 0, 0, 0, 0x2D^0, 0xF5]) == fingerprint_mode('set', True), 'Set Fingerprint add mode allow repeat'
assert bytes([0xF5, 0x2D, 0, 0x01, 0, 0, 0x2D^0, 0xF5]) == fingerprint_mode('set', False), 'Set Fingerprint add mode prohibit repeat'
assert bytes([0xF5, 0x2D, 0, 0, 0x01, 0, 0x2D^0, 0xF5]) == fingerprint_mode('read'), 'Read Fingerprint add mode'
assert bytes([0xF5, 0x01, 0, 0, 0x01, 0, 0x01^0, 0xF5]) == add_fingerprint_first('0'), 'Add first Fingerprint should be correct'
assert bytes([0xF5, 0x02, 0, 0, 0x01, 0, 0x02^0, 0xF5]) == add_fingerprint_second('0'), 'Add second Fingerprint should be correct'
assert bytes([0xF5, 0x03, 0, 0, 0x01, 0, 0x03^0, 0xF5]) == add_fingerprint_third('0'), 'Add third Fingerprint should be correct'
assert bytes([0xF5, 0x04, 0, 0, 0, 0, 0x04^0, 0xF5]) == del_specified_user('0'), 'Delete specified user by user id'
assert bytes([0xF5, 0x05, 0, 0, 0, 0, 0x05^0, 0xF5]) == del_all_users(), 'Del all users'
assert bytes([0xF5, 0x0B, 0, 0, 0, 0, 0x0B^0, 0xF5]) == compare_by_id('0'), 'compare with 0 should be correct'

