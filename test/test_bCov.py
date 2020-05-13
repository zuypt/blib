import sys
import frida 
from time import sleep
from bLib.bCov import bCov

pid = frida.spawn([r'bin32\Release\test_bin.exe', 'test'])
session = frida.attach(pid)
options = {
	'shm_name': 'f1_shm',
	'cov_modules': ['test_bin.exe'],
	'target_module': 'testlib.dll',
	'target_offset': 0x1020
}

bcov = bCov(**options)
bcov.load(session)
input('>')
frida.resume(pid)
sys.stdin.read()
