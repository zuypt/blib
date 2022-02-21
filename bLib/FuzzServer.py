import os
import sys
import time
import frida
import pickle
import psutil
import shutil
import random
import logging
import platform
import threading
import traceback

from time import sleep
from signal import signal, SIGINT

from datetime import timedelta

from bLib.const import *
from bLib.Mutator import Mutator
from bLib.Testcase import Testcase
from bLib.Executor import Executor

from bLib.util import *
from bLib.win_util import *

import ctypes
from ctypes import CDLL
from ctypes.wintypes import *

from abc import ABC, abstractmethod

class FuzzServer(ABC):
	def __init__(self, args, **options):
		self.logger = logging.getLogger('FuzzServer')
		self.log_level = options.get('log_level', logging.DEBUG)
		self.logger.setLevel(self.log_level)

		self.args 		= args
		self.options 	= options
		self.id 		= options.get('id', 'Fuzzer1')

		self.client 	= None

		signal(SIGINT, self.ctrlc)
	
		self.queue 			= []
		self.queue_idx 		= 0
		self.syn_count 		= 0
		self.dryrun_idx 	= 0
		self.hang_count 	= 0
		self.crash_count 	= 0
		
		self.last_new_crash = None
		self.last_new_hang = None
		self.last_new_path = None

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
		self.syn_dir = options['odir']
		self.odir = join(self.syn_dir, self.id)
		self.queuedir = join(self.odir, 'queue')
		self.crashdir = join(self.odir, 'crash')
		self.hangdir = join(self.odir, 'hang')

		self.inp_path = options['inp_path']

		# dictionary to save syn state
		self.syn_dict = {}

		if os.path.exists(join(self.odir, 'cov.pkl')):
			self.resume = True
			self.logger.info('old session found, resume')
		else:
			self.resume = False
			self.logger.info('new fuzzing session')
			if os.path.exists(self.odir):
				shutil.rmtree(self.odir, ignore_errors=True)

			try:
				# the directory itself is already existed, no big deal
				os.makedirs(self.odir)
			except:
				pass
			os.mkdir(self.queuedir)
			os.mkdir(self.crashdir)
			os.mkdir(self.hangdir)

			for fname in os.listdir(self.idir):
				self.add_file_to_queue(join(self.idir, fname))

	def found_new_interesting_inp(self, buf):
		self.new_interesting_inp_count += 1
		fname = 'id_%06d' % (self.new_interesting_inp_count)
		f = open(join(self.queuedir, fname), 'wb')
		f.write(buf)
		f.close()
		self.queue.append(Testcase(self.queuedir, fname))
		self.last_new_path = time.time()

	def found_new_crash(self, buf):
		f = open(join(self.crashdir, 'crash_%d'%self.crash_count), 'wb')
		f.write(buf)
		f.close()
		self.crash_count += 1
		self.last_new_crash = time.time()

	def found_new_hang(self, buf):
		f = open(join(self.hangdir, 'hang_%d' % self.hang_count), 'wb')
		f.write(buf)
		f.close()
		self.hang_count += 1
		self.last_new_hang = time.time()
		
	def print_info(self):
		if self.last_new_path:
			self.logger.info('last new path: {}'.format(time.ctime(self.last_new_path)))
		if self.last_new_hang:
			self.logger.info('last new hang: {}'.format(time.ctime(self.last_new_hang)))
		if self.last_new_crash:
			self.logger.info('last new crash: {}'.format(time.ctime(self.last_new_crash)))
		self.logger.info('crash count: {}'.format(self.crash_count))

	def reload_queue(self):
		self.queue = []
		for fname in os.listdir(self.queuedir):
			testcase = Testcase(self.queuedir, fname)
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
			f.write(pickle.dumps(self.client.get_cov(), protocol=2))

	def _load_state(self):
		with open(join(self.odir, 'cov.pkl'), 'rb') as f:
			cov_dict = pickle.loads(f.read())
		self.client.load_cov(cov_dict)
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

	@abstractmethod
	def _fuzz_loop(self):
		while self.running:
			fuzz_one()

	def fuzz_one(self, buf):
		'''
		TODO: implement timeout
		'''
		
		self.prepare_inp(buf)
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

		return fault

	@abstractmethod
	def prepare_inp(self, buf):
		pass

	def _dry_run(self):
		pass

	def start(self):
		self.running = True
		if self.resume:
			self._load_state()

		if self.client is None:
			raise Exception('Subclass must init self.client')
		
		'''
		give client a chance to initialize before fuzzing
		start a persistence process for example
		'''
		try:
			self.client.init()
			if self._dry_run() != FUZZER_STOP:
				self._fuzz_loop()
		except:
			traceback.print_exc()
			self.client.kill()

		self.client.cleanup()
		self.logger.info('fuzzer exit')
		
	def add_file_to_queue(self, fpath):
		fname = 'orig,id_%06d,%s' % (self.queue_idx, os.path.basename(fpath))
		shutil.copyfile(fpath, join(self.queuedir, fname))
		testcase = Testcase(self.queuedir, fname)
		self.queue.append(testcase)
		self.queue_idx += 1
		return testcase

	def add_sync_file_to_queue(self, fpath):
		fname = 'syn_%06d' % self.syn_count
		shutil.copyfile(fpath, join(self.queuedir, fname))
		testcase = Testcase(self.queuedir, fname)
		self.queue.append(testcase)
		self.syn_count += 1
		return testcase

	def _do_sync(self, odir):
		queuedir = join(odir, 'queue')
		for fname in os.listdir(queuedir):
			full_path = join(queuedir, fname)

			if not isfile(full_path):
				continue
			if fname in self.syn_dict[odir]:
				continue

			self.syn_dict[odir][fname] = 1
			self.prepare_inp(readfile(full_path))

			'''
			TODO:

			handle crash, hang ?
			'''
			fault = self.client.exec_one(INFINITE)
			if self.client.has_new_cov():
				testcase = self.add_sync_file_to_queue(full_path)
				self.logger.info('sync ' + str(testcase))

			if not self.running:
				break

	def sync(self):
		for dirname in os.listdir(self.syn_dir):
			if dirname == self.id:
				continue
			odir = join(self.syn_dir, dirname)

			if not isdir(odir):
				continue
			if odir in self.syn_dict:
				continue
			if not exists(join(odir, 'queue')):
				continue
			self.syn_dict[odir] = {}

		for odir in self.syn_dict:
			if exists(odir):
				self._do_sync(odir)
			else:
				del self.syn_dict[odir]