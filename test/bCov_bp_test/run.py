import sys
import time
import frida 
import random
import traceback
from time import sleep

from bLib.const import *
from bLib.Mutator import Mutator
from bLib.Executor import Executor
from bLib.FuzzServer import FuzzServer
from bLib.Cov import BreakPointCoverage

inp_path = sys.argv[1] + '.mp3'

args = ['mp32_p.exe', inp_path]

options = {
	'id': sys.argv[1],
	'idir': 'mp3',
	'odir': 'out',
	'target_module': 'mp32.exe',
	'target_offset': 0x10a0,
	'cov_modules': ['mp3dmod.dll'],
	'bbs_files': ['mp3dmod.bbs'],
	'inp_path': inp_path
}

class Server(FuzzServer):
	def __init__(self, args, **options):
		super().__init__(args, **options)

		self.bcov = BreakPointCoverage(**options)
		self.executor = Executor(self.bcov, args, **options)
		self.mutator = Mutator(self.executor, **options)

	def prepare_inp(self, buf):
		try:
			f = open(self.inp_path, 'wb')
			f.write(buf)
			f.close()
		except:
			traceback.print_exc()

	def _dry_run(self):
		''' TODO
		hanlde crash and timeout
		'''

		self.logger.info('dryrun')
		for testcase in self.queue:
			self.prepare_inp(testcase.read())
			self.executor.exec_one(INFINITE)
		self.logger.info('bb_count: ' + str(self.bcov.get_bb_count()))
		
	def _fuzz_loop(self):
		self.nexecs = 0
		self.starttime = time.monotonic()
		while self.running:
			testcase = random.choice(self.queue)
			print (testcase)
			t = testcase.read()

			for i in range(500):
				
				buf = self.mutator.havoc(t, 0, 1024)[0]
				self.prepare_inp(buf)

				fault = self.executor.exec_one(2000)

				if fault == FAULT_NONE:
					if self.bcov.has_new_cov():
						self.found_new_interesting_inp(buf)
						print ('new path: ', self.bcov.bb_count)
				elif fault == FAULT_TMOUT:
					self.logger.info('new hang')
					self.found_new_hang(buf)
					self._dry_run()
					'''
					cung khong biet tai sao :)
					'''
					break
				elif fault == FAULT_CRASH:
					self.logger.info('new crash')
					self.found_new_crash(buf)
					self._dry_run()
					'''
					cung khong biet tai sao :)
					'''
					break

				self.nexecs += 1
				if (self.nexecs == 50):
					self.nexecs = 0

					self.endtime = time.monotonic()
					interval = self.endtime-self.starttime
					self.starttime = self.endtime

					print ('exec/s: ', 50 / interval)
			self.sync()

fuzzserver = Server(args, **options)
fuzzserver.start()

# try:
# 	bcov = bCov_bp(**options)
# 	executor = bExecutor(bcov, args, **options)

# 	executor.exec_one('', 100000)
# 	print (bcov.get_bb_count())


# 	nexecs = 0
# 	starttime = time.monotonic()
# 	while 1:
# 		nexecs += 1
# 		executor.exec_one('', 100000)
# 		# print (bcov.get_bb_count())
# 		if (nexecs == 100):
# 			endtime = time.monotonic()
# 			interval = endtime - starttime
# 			starttime = endtime
# 			print (nexecs/interval)
# 			nexecs = 0
# except Exception as e:
# 	print (e)
# 	traceback.print_exc()
# 	executor.cleanup()

# input('>')