import fpController

PORT = '/dev/ttyUSB0'
BAUDRATE = 19200
TIMEOUT = 0.1

fpr = fpController(PORT, BAUDRATE, TIMEOUT)

print('finger-print reader is ready')

while True:
    print('select want function : ', sep='')
    try:
        pass
    except Exception as e:
        print(e)