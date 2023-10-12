import frida
import sys

jscode = """

"""

with open('fairfree.js') as f:
    jscode = f.read()

def printMessage(message,data):
    if message['type'] == 'send':
        print(' {0}'.format(message['payload']))
    else:
        print(message)

process = frida.get_usb_device().attach('fairplayd.H2')
script = process.create_script(jscode)
script.on('message',printMessage)
script.load()
sys.stdin.read()
