from fingerprint import FingerPrintReader, Privilege
from dbController import DBController
import threading
import requests
import json
import sys
import os

port = '/dev/cu.SLAB_USBtoUART'
fpr = FingerPrintReader(port, 19200, 0.5)
dbcon = DBController('lawdeck.db')
company = os.environ.get('company')
url = os.environ.get('fingerurl')

def main():
    #port = '/dev/ttyUSB0'  # raspbian
    pass
    port = '/dev/cu.SLAB_USBtoUART' # MacOS Test
    baudrate = 19200
    timeout = 0.5

    rlck = threading.RLock()
    fpr = FingerPrintReader(port, baudrate, timeout)


def auto_verify_finger(lck, result):
    while True:
        if lck.acquire() == True:
            pass
    lck.release()


def add_finger(user_name, privilege=2):
    user_id = dbcon.add_finger(user_name)
    res = fpr.add_user(user_id, Privilege(privilege))
    print(res)


def verify_finger():
    res = fpr.compare_many()
    user_name = dbcon.find_finger(res.value)
    dbcon.record(user_name)
    print(res)


def send_web_data(user_name):
    data = {'company': company, 'username': user_name}
    res = requests.post(url, data=json.dumps(data))
    res.raise_for_status()
    print(res.json())


def delete_user(user_name):
    fingers = dbcon.get_fingers(user_name)
    dbcon.del_by_user(user_name)
    for fpid, name in fingers:
        res = fpr.del_specified_user(fpid)
        print(res)


if __name__ == '__main__':
    try:
        pass
        main()
    except KeyboardInterrupt:
        print('\n\n Finished! \n')
        sys.exit()
