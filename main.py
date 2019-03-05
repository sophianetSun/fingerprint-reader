from fingerprint import FingerPrintReader, User
import threading
import time
import sys


def main():
    port = '/dev/ttyUSB0'
    baudrate = 19200
    timeout = 0.1

    rlck = threading.RLock()
    fpreader = FingerPrintReader(port, baudrate, timeout)

    print('finger-print reader is ready')
    print("Number of fingerprints already available: %d " % fpreader.get_user_count())
    print(" send commands to operate the module: ")
    print("  CMD1 : Query the number of existing fingerprints")
    print("  CMD2 : Registered fingerprint  needs 3x check")
    print("  CMD3 : Fingerprint matching  ")
    print("  CMD4 : Clear fingerprints ")

    thread_auto_verify = threading.Thread(target=auto_verify_finger, args=(rlck, fpreader.compare_many))
    thread_auto_verify.setDaemon(True)
    thread_auto_verify.start()

    while True:
        print("Plese input command :", sep='')
        analysis_command(input(), fpreader)


def analysis_command(cmd, fpr):
    if cmd == "CMD1":
        print("Number of fingerprints already available: {}".format(fpr.get_user_count()))
    elif cmd == "CMD2":
        user_id = input('type user id 2 character (ex: sw) :')
        print(
            "Add fingerprint (Each entry needs to be read two times: "
            "\"beep\",put the finger on sensor, \"beep\", put up ,\"beep\", put on again) ")
        res = fpr.add_user(user_id)
        print(res)
    elif cmd == "CMD3":
        print("Waiting Finger......Please try to place the center of the fingerprint flat to sensor !")
        res = fpr.compare_many()
        print(res)
    elif cmd == "CMD4":
        fpr.clear_all_users()
        print("All fingerprints have been cleared !")


def auto_verify_finger(lck, result):
    while True:
        if lck.acquire():
            print("Waiting Finger......Please try to place the center of the fingerprint flat to sensor !")
            time.sleep(0.25)
            res = result()
            if type(res) == User:
                print("Matching successful ! Hello", bytes([res.high, res.low]).decode())
            else:
                print("Failed Errorcode is", res)
    lck.release()


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print('\n\n Finished! \n')
        sys.exit()
