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

inp_path = sys.argv[1] + '.aac'

args = ['aac.exe', inp_path]

options = {
	'id': sys.argv[1],
	'idir': 'aac',
	'odir': 'out_aac',
	'target_module': 'aac.exe',
	'target_offset': 0x10a0,
	'cov_modules': ['MSAudDecMFT.dll', 'mfsrcsnk.dll'],
	'module_info_files': ['msauddecmft.bbs', 'mfsrcsnk.bbs'],
	'inp_path': inp_path
}

class Server(FuzzServer):
	def __init__(self, args, **options):
		super().__init__(args, **options)

		self.client = BreakpointClient(args, **options)
		self.mutator = Mutator(self.client, **options)

	def prepare_inp(self, buf):
		try:
			f = open(self.inp_path, 'wb')
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

	def _fuzz_loop(self):
		self.logger.info('fuzz loop')

		self.nexecs = 0
		self.starttime = time.monotonic()
		
		while self.running:
			testcase = random.choice(self.queue)
	
			orig_bytes = testcase.read()

			self.logger.info('havoc')
			for i in range(500):
				if not self.running:
					break

				buf = self.mutator.havoc(orig_bytes[:])
				fault = self.fuzz_one(buf)
				if fault == FAULT_TMOUT:
					break

				self.nexecs += 1
				if (self.nexecs % 200 == 0):
					self.nexecs = 0
					self.endtime = time.monotonic()
					interval = self.endtime-self.starttime
					self.starttime = self.endtime
					self.print_info()
					self.logger.info('exec/s: {}'.format(200/interval))

			self.logger.info('splice')
			buf = self.mutator.splice(orig_bytes[:], self.queue)
			self.prepare_inp(buf)
			self.fuzz_one(buf)
			self.sync()

fuzzserver = Server(args, **options)
fuzzserver.start()