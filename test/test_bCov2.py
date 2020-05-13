import sys
import frida 
from time import sleep
from bLib.bCov import frida_bCov_shm

pid = frida.spawn([r'bin32\Release\cscript.exe', 'harness.vbs'])
session = frida.attach(pid)
options = {
	'shm_name': 'f1_shm',
	'cov_modules': ['vbscript.dll'],
	'target_module': 'vbscript.dll',
	'target_offset': 0x10D51
}

bcov = frida_bCov_shm(session, options)
bcov.load()
input('>')
frida.resume(pid)
sys.stdin.read()
