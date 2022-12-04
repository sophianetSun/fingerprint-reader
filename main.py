from fingerprint import FingerPrintReader, Privilege, Ack
from dbController import DBController
import sys

sysDriver = {'win32': 'COM3', 'darwin':'/dev/cu.SLAB_USBtoUART', 'linux':'/dev/ttyUSB0'}
port = sysDriver[sys.platform]
fpr = FingerPrintReader(port, 19200)
dbcon = DBController('sample.db')
dbcon.set_up()

def main():
	while True:
		show_input_command()


def show_input_command():
	print('0: auto verify, 1: add, 2: verify, 3:delete')
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
	elif in_cmd == 0:
		while True:
			verify_finger()


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
		print(res)
	else:
		print(res)



def delete_user(user_name):
    fingers = dbcon.get_fingers(user_name)
    dbcon.del_by_user(user_name)
    for fpid, name in fingers:
        res = fpr.del_specified_user(fpid)
        print(res)


def initialize():
	if len(dbcon.get_fingers()) != fpr.get_user_count():
		dbcon.del_all_fingers()
		fpr.clear_all_users()
		print('All data clear')
	else:
		print('Nothing happen')


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print('\n\n Finished! \n')
        sys.exit()
