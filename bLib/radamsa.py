import os
import hashlib
import pickle
import string
import random
import atexit
import logging
import subprocess

from time import sleep
from subprocess import call
from shutil import rmtree

join = os.path.join
exists = os.path.exists

CACHE_SZ = 50
GDIR = 'rad_cache'

try:
	os.mkdir(GDIR)
except:
	pass

def save_state():
	global CACHE
	global CACHE_DIR
	global SESS_NAME

	state_file = join(GDIR, SESS_NAME+'.pkl')
	with open(state_file, 'wb') as f:
		f.write(pickle.dumps(CACHE))

def init(name):
	global CACHE
	global SESS_NAME
	global CACHE_DIR

	SESS_NAME = name
	CACHE_DIR = join(GDIR, SESS_NAME)

	state_file = join(GDIR, SESS_NAME+'.pkl') 
	if exists(state_file):
		with open(state_file, 'rb') as f:
			print ('loading previous cache')
			CACHE = pickle.loads(f.read())
	else:
		CACHE = {}
		os.makedirs(CACHE_DIR)
	atexit.register(save_state)

def radamsa(path, max_sz=None):
	global CACHE
	global CACHE_SZ
	global SESS_NAME
	global CACHE_DIR

	fname = os.path.basename(path)
	cache_key = fname + '_' + hashlib.md5(bytes(path, 'ansi')).hexdigest()[:4]
	dst = join(CACHE_DIR, cache_key)
	if cache_key not in CACHE:
		if exists(dst):
			rmtree(dst)
		os.makedirs(dst)
		'''work around, cuz radamsa on Windows has bugs '''
		if max_sz is None:
			args = ' '.join(['bash', '-c', '"', 'radamsa', '-n', str(CACHE_SZ), '-o', join(dst, r'%n'), path, '"']).replace('\\',  '/')
		else:
			args = ' '.join(['bash', '-c', '"', 'radamsa', '-n', str(CACHE_SZ), '-T', str(max_sz), '-o', join(dst, r'%n'), path, '"']).replace('\\',  '/')
		try:
			''' sending ctrl-c (sigint) cause radamsa to fail, in this case rerun and let the fuzzer finished the cylce  '''
			subprocess.check_output(args, stdin=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
			CACHE[cache_key] = CACHE_SZ
		except:
			pass
		return radamsa(path, max_sz)
	else:
		with open(join(CACHE_DIR, cache_key, str(CACHE[cache_key])), 'rb') as f:
			CACHE[cache_key] -= 1
			if CACHE[cache_key] == 0:
				del CACHE[cache_key]
			return f.read()[:1024]

if __name__ == '__main__':
	init('f1')
	for i in range(80):
		print (radamsa('testbin.exe'))
