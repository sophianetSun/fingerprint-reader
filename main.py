from fingerprint import FingerPrintReader, Privilege, Ack
from dbController import DBController
import threading
import requests
import json
import sys
import os

sysDriver = {'win32': 'COM3', 'darwin':'/dev/cu.SLAB_USBtoUART', 'linux':'/dev/ttyUSB0'}
port = sysDriver[sys.platform]
fpr = FingerPrintReader(port, 19200)
dbcon = DBController('lawdeck.db')
dbcon.set_up()
company = os.environ.get('company')
url = os.environ.get('fingerurl')

def main():
	rlck = threading.RLock()
	while True:
		show_input_command()


def show_input_command():
	print('1: add, 2: verify, 3:delete')
	in_cmd = input('input command you want: ')
	in_cmd = int(in_cmd)
	if in_cmd == 1:
		user_name = input('type username: ')
		add_finger(user_name)
	elif in_cmd == 2:
		verify_finger()
	elif in_cmd == 3:
		user_name = input('type username: ')
		delete_user(user_name)


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
	if res.ack == Ack.SUCCESS:
		user = res.val
		user_name = dbcon.find_finger(user.id)
		dbcon.record(user_name)
		t1 = threading.Thread(target=send_web_data, args=(user_name,), daemon=True)
		t1.start()
		print(res)
	else:
		print(res)


def send_web_data(user_name):
    data = {'company': company, 'username': user_name}
    res = requests.post(url, data=data)
    res.raise_for_status()
    print(res.json())


def delete_user(user_name):
    fingers = dbcon.get_fingers(user_name)
    dbcon.del_by_user(user_name)
    for fpid, name in fingers:
        res = fpr.del_specified_user(fpid)
        print(res)


def initialize():
	if dbcon.highest_fpid() > 0:
		dbcon.del_all_fingers()
		fpr.clear_all_users()
		print('All data clear')
	else:
		print('Check Manually')


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print('\n\n Finished! \n')
        #sys.exit()
