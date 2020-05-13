import os
import sys
import time
import pickle
import shutil
import frida
import platform
import random
import logging
import threading
import traceback
import psutil

from signal import signal, SIGINT

from time import sleep
from bLib.const import *

from bLib.bCov import bCov
from bLib.bMutator import bMutator
from bLib.bTestcase import Testcase
from bLib.bExecutor import bExecutor

from bLib.util import *
from bLib.win_util import *

import ctypes
from ctypes.wintypes import *
from ctypes import CDLL


class bFuzz_WinAFL():
	def __init__(self, args, **options):
		self.logger = logging.getLogger('bFuzzer')
		self.log_level = options.get('log_level', logging.DEBUG)
		self.logger.setLevel(self.log_level)

		self.options 	= options
		self.args 		= args
		self.id 		= options.get('id', 'Fuzzer1')
		self.map_sz 	= options.get('map_sz', MAP_SZ)

		self.options['shm_name'] = self.id
		self.bcov 		= bCov(**self.options)
		self.executor 	= bExecutor(self.bcov, self.args, **self.options)
		self.mutator 	= bMutator(self.executor, **self.options)
		
		signal(SIGINT, self.ctrlc)
		self.init_fuzzer_state(options)

	def init_fuzzer_state(self, options):
		self.virgin_tmout = malloc(self.map_sz)
		self.virgin_crash = malloc(self.map_sz)

		self.var_bytes = malloc(self.map_sz)
		'''
		used to check for testcase variable behavior
		'''
		self.first_trace = malloc(self.map_sz)
		'''
		use to mark variable edge/block 
		'''
		self.var_bytes = malloc(self.map_sz)

		self.queue = []

		self.hang_count = 0
		self.crash_count = 0
		self.dryrun_idx = 0
		self.queue_idx = 0
		self.new_interesting_inp_count = 0

		self.nexecs = 0

		self.skip_dryrun = options.get('skip_dryrun')

		self.timeout = options.get('timeout')
		if not self.timeout:
			self.timeout = 1000*10

		if 'idir' not in options:
			options['idir'] = 'in'
			self.logger.info('idir not specified, using default value `in`')
		if 'odir' not in options:
			options['odir'] = 'out'
			self.logger.info('odir not specified, using default value `out`')

		self.idir = options['idir']
		if not exists(self.idir):
			raise Exception('idir not exists')
		self.odir = join(options['odir'], self.id)
		self.queuedir = join(self.odir, 'queue')
		self.crashdir = join(self.odir, 'crash')
		self.hangdir = join(self.odir, 'hang')

		if os.path.exists(join(self.odir, 'cov.pkl')):
			self.resume = True
			self.logger.info('old session found, resume')
		else:
			self.resume = False
			self.logger.info('new fuzzing session')
			if os.path.exists(self.odir):
				shutil.rmtree(self.odir)
			os.makedirs(self.odir)
			os.mkdir(self.queuedir)
			os.mkdir(self.crashdir)
			os.mkdir(self.hangdir)

			for fname in os.listdir(self.idir):
				self.add_file_to_queue(join(self.idir, fname))

	def _found_new_interesting_inp(self, testcase):
		self.new_interesting_inp_count += 1
		fname = 'id_%06d' % (self.new_interesting_inp_count)
		f = open(join(self.queuedir, fname), 'wb')
		f.write(self.cur_inp)
		f.close()
		self.queue.append(Testcase(self.queuedir, fname))

	def _save_inp_to_crashdir(self):
		f = open(join(self.crashdir, 'crash_%d'%self.crash_count), 'wb')
		f.write(self.cur_inp)
		f.close()
		self.crash_count += 1

	def _save_inp_hangdir(self):
		f = open(join(self.hangdir, 'hang_%d' % self.hang_count), 'wb')
		f.write(self.cur_inp)
		f.close()
		self.hang_count += 1

	def _crash_handler(self):
		self._save_inp_to_crashdir()

	def _timeout_handler(self):
		self._save_inp_hangdir()

	def reload_queue(self):
		for fname in os.listdir(self.queuedir):
			testcase = Testcase(self.queuedir, fname)
			if fname not in self.queue:
				self.queue.append(testcase)

	def _save_state(self):
		fuzzer_state = {
			'hang_count': self.hang_count,
			'crash_count': self.crash_count,
			'new_interesting_inp_count': self.new_interesting_inp_count
		}
		with open(join(self.odir, 'state.pkl'), 'wb') as f:
			f.write(pickle.dumps(fuzzer_state))

		with open(join(self.odir, 'cov.pkl'), 'wb') as f:
			f.write(pickle.dumps(self.bcov.get_cov(), protocol=2))

	def _load_state(self):
		with open(join(self.odir, 'cov.pkl'), 'rb') as f:
			cov_dict = pickle.loads(f.read())
		self.executor.load_cov(cov_dict)
		with open(join(self.odir, 'state.pkl'), 'rb') as f:
			fuzzer_state = pickle.loads(f.read())

		self.hang_count = fuzzer_state['hang_count']
		self.crash_count = fuzzer_state['crash_count']
		self.new_interesting_inp_count = fuzzer_state['new_interesting_inp_count']

		self.reload_queue()

	def ctrlc(self, signal_received, frame):
		if self.running:
			self.logger.debug('ctrl-c pressed')
			self.running = False
			self.mutator.stop()

	def _do_dryrun(self):
		self.logger.info('dryrun')

		for testcase in self.queue:
			if not self.running:
				return FUZZER_STOP

			self.logger.info('calibrate ' + testcase.fname)
			fault = self._calibrate_case(testcase)
			if fault == FAULT_NONE:
				pass
			elif fault == FAULT_CRASH:
				self.logger.info('testcase %s crash when dryrun' % testcase.fname)
				return FUZZER_STOP
			elif fault == FAULT_TMOUT:
				self.logger.info('testcase %s timeout when dryrun' % testcase.fname)
				return FUZZER_STOP
			elif fault == FAULT_ERROR:
				self.logger.info('client fuckup when dryrun %s' % testcase.fname)
				return FUZZER_STOP
			elif fault == FAULT_NOINST:
				self.logger.info('no instrument detected %s' % testcase.fname)
			elif fault == FAULT_NOBITS:
				self.logger.info('testcase create no new path, maybe useless: %s' % testcase.fname)

		self.logger.info('dryrun finished')

	def _calibrate_case(self, testcase):
		'''
		TODO
		- extend to 8 instead of 3 run when variable behaviour is detected.
		- calibrate timeout.
		- measure execution time, bitmap score.
		'''

		'''
		we gonna run the test case for the first time
		'''
		# input('attach debugger>')

		fault = self.executor.exec_one(testcase.read(), self.timeout)

		if fault != FAULT_NONE:
			return fault

		if self.bcov.count_bytes() == 0:
			return FAULT_NOINST

		new_bits = self.bcov.has_new_bits()
		testcase.exec_cksum = self.bcov.hash32()
		ctypes.memmove(self.first_trace, self.bcov.trace_bits, self.map_sz)

		for i in range(2):
			'''
			it's the same testcase as the first runm should we check for tmout/error/crash here
			'''

			fault = self.executor.exec_one(testcase.read(), self.timeout)
			if fault != FAULT_NONE:
				return fault
			

			cksum = self.bcov.hash32()
			if cksum != testcase.exec_cksum:
				'''
				cksum different from the first run, check for variable bytes
				'''
				testcase.variable = True
				'''
				compare the first trace with the current trace to find var_bytes
				'''
				for i in range(self.map_sz):
					if self.var_bytes[i] == 0 and self.first_trace[i] != self.bcov.trace_bits[i]:
						self.var_bytes[i] = 1

				hnb = self.bcov.has_new_bits()
				if hnb > new_bits:
					new_bits = hnb

		'''
		this testcase generate no new path
		'''
		if new_bits == 0:
			fault = FAULT_NOBITS

		return fault

	def _do_fuzz(self):
		self.logger.info('fuzz')

		while self.running:
			testcase = random.choice(self.queue)

			for i in range(500):
				self.cur_inp = self.mutator.radamsa(testcase)
				self.logger.info('mutating: %s' % testcase.fname)
				fault = self.executor.exec_one(self.cur_inp, self.timeout)

				if fault == FAULT_NONE:
					if self.bcov.has_new_bits():
						self.logger.info('found new path')
						self._found_new_interesting_inp(testcase)
				elif fault == FAULT_TMOUT:
					self._timeout_handler()
				elif fault == FAULT_CRASH:
					self._crash_handler()
				elif fault == FAULT_ERROR:
					self._timeout_handler()

			testcase = random.choice(self.queue)
			self.logger.info('trimming: %s' % testcase.fname)
			fault = self.mutator.trim_case_ignore_loop(testcase)		
			if fault != FAULT_NONE:
				return
	def _loop(self):
		try:
			r = self._do_dryrun()
			if r == FUZZER_STOP:
				return r
		except:
			traceback.print_exc()

		try:
			self._do_fuzz()
		except:
			traceback.print_exc()

	def start(self):
		self.running = True
		if self.resume:
			self._load_state()
		self._loop()

		self.executor.cleanup()
		self.logger.debug('fuzzer exit')

	def add_file_to_queue(self, fpath):
		fname = 'orig,id_%06d,%s' % (self.queue_idx, os.path.basename(fpath))
		shutil.copyfile(fpath, join(self.queuedir, fname))
		self.queue.append(Testcase(self.queuedir, fname))
		self.queue_idx += 1

	def _read_input_from_queuedir(self, fname):
		f = open(join(self.queuedir, fname), 'rb')
		d = f.read()
		f.close()
		return d