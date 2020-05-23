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
from bLib.FuzzClient import BreakpointClient

inp_path = sys.argv[1]

args = ['test.exe', inp_path, 'loop']

options = {
	'id': sys.argv[1],
	'idir': 'in_test',
	'odir': 'out_test',
	'target_module': 'test.exe',
	'target_offset': 0x1000,
	'cov_modules': ['test.exe'],
	'module_info_files': ['test.bbs'],
	'inp_path': inp_path
}

class Server(FuzzServer):
	def __init__(self, args, **options):
		super().__init__(args, **options)

		self.client = BreakpointClient(args, **options)
		self.mutator = Mutator(self.client, **options)

	def prepare_inp(self, buf):
		try:
			f = open(inp_path, 'wb')
			f.write(buf)
			f.close()
	
		except:
			pass
			traceback.print_exc()

	def _dry_run(self):
		'''
		TODO
		hanlde crash and timeout
		'''

		self.logger.info('dryrun')
		for testcase in self.queue:

			self.logger.info(testcase)
			self.prepare_inp(testcase.read())

			fault = self.client.exec_one(INFINITE)
			if fault == FAULT_CRASH or fault == FAULT_ERROR:
				self.logger.info('testcase cause crash')
				return FUZZER_STOP
			elif fault == FAULT_TMOUT:
				self.logger.info('testcase cause timeout')
				return FUZZER_STOP

			if not self.running:
				break

		self.logger.info('dryrun finished')
		self.logger.info('hitcount: %d' % self.client.get_hitcount())

	def fuzz_one(self, buf):
		fault = self.client.exec_one(20000)
		if fault == FAULT_NONE:
			if self.client.has_new_cov():
				self.logger.info('new path')
				self.found_new_interesting_inp(buf)
				self.logger.info('hitcount: %d' % self.client.get_hitcount())
		elif fault == FAULT_TMOUT:
			self.logger.info('new hang')
			self.found_new_hang(buf)

		elif fault == FAULT_CRASH or fault == FAULT_ERROR:
			self.logger.info('new crash')
			self.found_new_crash(buf)

	def _fuzz_loop(self):
		self.logger.info('fuzz loop')

		self.nexecs = 0
		self.starttime = time.monotonic()
		
		while self.running:
			testcase = random.choice(self.queue)
			self.logger.info('mutating: %s' % testcase.fname)

			orig_bytes = testcase.read()

			for i in range(2000):
				if not self.running:
					break

				buf = self.mutator.havoc(orig_bytes[:])

				self.prepare_inp(buf)

				fault = self.fuzz_one(buf)
				if fault == FAULT_TMOUT:
					break

				self.nexecs += 1
				if (self.nexecs % 1000 == 0):
					self.nexecs = 0
					self.endtime = time.monotonic()
					interval = self.endtime-self.starttime
					self.starttime = self.endtime
					print ('exec/s: ', 1000 / interval)

			self.logger.info('splice')
			buf = self.mutator.splice(orig_bytes[:], self.queue)

			self.prepare_inp(buf)
			self.fuzz_one(buf)
			self.sync()

fuzzserver = Server(args, **options)
fuzzserver.start()