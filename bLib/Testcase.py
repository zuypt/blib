import traceback
from bLib.util import *

class Testcase():
	def __init__(self, directory, fname):
		self.dir = directory
		self.fname = fname
		self.fullpath = join(self.dir, self.fname)

		self.exec_cksum = 0

		'''
		testcase result in variable behavior
		'''
		self.variable = False
		self.bitmap_sz = 0

		self.len = os.path.getsize(self.fullpath)


	def __str__(self):
		return self.fname

	def read(self):
		try:
			f = open(self.fullpath, 'rb')
		except:
			traceback.print_exc()
		d = bytearray(f.read())
		f.close()
		return d

	def write(self, buf):
		try:
			f = open(self.fullpath, 'wb')
		except:
			traceback.print_exc()
		f.write(buf)
		f.close()

		self.len = len(buf)