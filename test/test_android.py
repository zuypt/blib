import os
import sys
import traceback

#target = 'com.vinsmart.vmessage'

import frida
from bLib.bCov import frida_bCov

device = frida.get_usb_device(2);
try:
	session = device.attach('Gadget')
except:
	traceback.print_exc()
	print ('maybe start gadget first')


bcov = frida_bCov(session)
options = {
	'cov_module_names': ['libc++_shared.so']
}
bcov.set_options(options)
bcov.load()

while 1:
	cmd = input('>')
	if cmd == 'm':
		print (bcov.script.exports.get_modules())
	if cmd == 'i':
		bcov.script.exports.init_stalker()
