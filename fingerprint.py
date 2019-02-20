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
CMD_COM_LEV = 0x28
CMD_LP_MODE = 0x2C
CMD_TIMEOUT = 0x2E

CMD_FINGER_DETECTED = 0x14

"""
LED1_ON = GPIO_SetBits(GPIOF, GPIO_Pin_6)
LED1_OFF = GPIO_ResetBits(GPIOF, GPIO_Pin_6)

LED2_ON = GPIO_SetBits(GPIOF, GPIO_Pin_7)
LED2_OFF = GPIO_ResetBits(GPIOF, GPIO_Pin_7)

LED3_ON = GPIO_SetBits(GPIOF, GPIO_Pin_8)
LED3_OFF = GPIO_ResetBits(GPIOF, GPIO_Pin_8)

LED4_ON = GPIO_SetBits(GPIOF, GPIO_Pin_9)
LED4_OFF = GPIO_ResetBits(GPIOF, GPIO_Pin_9)

USER_KEY = GPIO_ReadInputDataBit(GPIOG, GPIO_Pin_6)
PRESS_KEY = GPIO_ReadInputDataBit(GPIOG, GPIO_Pin_8)
DEL_KEY = GPIO_ReadInputDataBit(GPIOC, GPIO_Pin_3)
"""

def set_dormant_state():
    """
    fingerprint will be sleep.
    :return: 8 bytes
    """
    CHK = CMD_LP_MODE^0
    return bytes([CMD_HEAD, CMD_LP_MODE, 0, 0,
                  0, 0, CHK, CMD_TAIL])

def fingerprint_mode(mode, repeat=True):
    """
    set finger print add mode
    :param mode: should be 'set' or 'read'
    :param repeat: allow repeat, same finger can add one user only, Boolean
    :return: 8 bytes
    """
    CMD_ADD_MODE = 0x2D
    CMD_REPEAT = 0
    CHK = CMD_ADD_MODE ^ 0

    if not repeat:
        CMD_REPEAT = 1

    if mode == 'set':
        CMD_SET_MODE = 0
        return bytes([CMD_HEAD, CMD_ADD_MODE, 0, CMD_REPEAT,
                      CMD_SET_MODE, 0, CHK, CMD_TAIL])
    elif mode == 'read':
        CMD_READ_MODE = 1
        return bytes([CMD_HEAD, CMD_ADD_MODE, 0, CMD_REPEAT,
                      CMD_READ_MODE, 0, CHK, CMD_TAIL])
    else:
        raise ValueError('mode should be "set" or "read"')

def add_fingerprint(id='', user_privilege=1):
    id = id.encode()
    if len(id) == 0:
        import random
        id = int(random.random()*10000).to_bytes(2, 'big')
        id = (id[0], id[1])
    elif len(id) == 1:
        id = (0, id)
    else:
        id = (id[0], id[1])

    USER_ID_HIGH, USER_ID_LOW = id
    USER_PRIVILEGE = user_privilege

    return bytes([CMD_HEAD, CMD_ADD_1, USER_ID_HIGH, USER_ID_LOW,
              USER_PRIVILEGE, 0, CMD_ADD_1^0, CMD_TAIL])


assert bytes([0xF5, 0x2C, 0, 0,
              0, 0, 0x2C^0, 0xF5]) == set_dormant_state(), \
    'Dormant State Response Error!'
assert bytes([0xF5, 0x2D, 0, 0,
              0, 0, 0x2D^0, 0xF5]) == fingerprint_mode('set', True), \
    'Set Fingerprint add mode allow repeat'
assert bytes([0xF5, 0x2D, 0, 1,
              0, 0, 0x2D^0, 0xF5]) == fingerprint_mode('set', False), \
    'Set Fingerprint add mode prohibit repeat'
assert bytes([0xF5, 0x2D, 0, 0,
              1, 0, 0x2D^0, 0xF5]) == fingerprint_mode('read'), \
    'Read Fingerprint add mode'
assert bytes([0xF5, 0x01, 0, 0,
              1, 0, 0x01^0, 0xF5]) == \
       add_fingerprint(), \
    'Add first Fingerprint should correct'

def exceptionTest():
    try:
        fingerprint_mode('rea')
    except ValueError as ve:
        print(ve)

exceptionTest()
