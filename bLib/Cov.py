''' disable sandbox first '''
from __future__ import print_function
import argparse
import pickle
import frida
import json
import sys
import os
import random
import ctypes
import logging
import platform

from bLib.const import *

import ctypes
from ctypes.wintypes import *
from ctypes import CDLL

from bLib.util import *
from bLib.win_util import *

'''
what should the coverage component care about ?
1. which module to get coverage
1. where to start taking coverage
2. where to stop taking coverage
=> could be 2 sepearate offset or a specific function
3. how to extract coverage
	3.1 through RPC
	3.1 through shared memory
		=> what is the shm name

'''

class bCov():
	def __init__(self, **options):
		self.logger = logging.getLogger('bCov')
		self.log_level = options.get('log_level', logging.DEBUG)
		self.logger.setLevel(self.log_level)

		self.js_runtime = options.get('js_runtime', 'duk') 
		
		self.target_module = options.get('target_module')
		if self.target_module is None:
			self.logger.info('no target_module, always collecting')
		else:
			self.target_offset = options.get('target_offset')
			if self.target_offset is None:
				raise Exception('target_offset must be specified with target_module')

		self.cov_modules = options.get('cov_modules')
		if self.cov_modules is None:
			raise Exception('missing cov_modules')

		self.shm_name = options.get('shm_name')
		if self.shm_name is None:
			raise Exception('Missing shm_name')

		self.map_sz = MAP_SZ
		self.logger.debug(self.shm_name)
		self.trace_bits = create_shm(self.shm_name, self.map_sz)
		self.blk_map = create_shm(self.shm_name + '_MAP', self.map_sz*4)

		'''
		mark block/edge that we haven't seen before
		'''
		self.virgin_bits = malloc(self.map_sz)
		ctypes.memset(self.virgin_bits, 255, self.map_sz)

		self.logger.debug('trace_bits is at: ' + hex(addressof(self.trace_bits)))

	def __on_message(self, message, data):
		if (message['type'] == 'error'):
			self.logger.error(message)

	def load(self, session):
		self.session = session
		script_path = join(FRIDA_SCRIPTDIR, 'cov_shm_windows.js')
		with open(script_path, 'r') as scriptfile:
			self.script = self.session.create_script(scriptfile.read(), runtime=self.js_runtime)
			self.script.on('message', self.__on_message)
			self.script.load()

			options = {
				'target_module': self.target_module,
				'target_offset': self.target_offset,
				'cov_modules': self.cov_modules,
				'shm_name': self.shm_name,
				'shm_sz': self.map_sz,
				'libpath': CLIB32
			}
			self.script.exports.init(options)


	def count_bytes(self):
		r = count_bytes(self.trace_bits, self.map_sz)
		self.logger.debug('count_bytes: %d' % r)
		return r 

	def hash32(self):
		r = hash32(self.trace_bits, self.map_sz, HASH_CONST)
		return r

	'''
	Called after the execution of a new testcase to check if
	there is new path
	'''
	def has_new_bits(self):
		''' 
		TODO: fix this pointer casting shit
		'''
		hnb = has_new_bits(self.trace_bits, self.virgin_bits, self.map_sz)
		return hnb

	def cmp_bitmap_ignore_loop(self, m1, m2):
		for i in range(self.map_sz):
			if m1[i]*m2[i] == 0:
				if m1[i] != m2[i]:
					return 1
		return 0

	def clear_tracebits(self):
		ctypes.memset(self.trace_bits, 0, self.map_sz)

	def getcov(self):
		cov = []

		blk_map = u32_pointer(self.blk_map)
		shm = u8_pointer(self.trace_bits)

		for blk_id in range(self.map_sz):
			hitcount = shm[blk_id] 
			if hitcount:
				blk_addr = blk_map[blk_id]
				cov.append((blk_addr, hitcount))
		return {'cov': cov}

class BreakPointCoverage():
	def __init__(self, **options):
		self.logger = logging.getLogger('bCov_bp')
		self.log_level = options.get('log_level', logging.DEBUG)
		self.logger.setLevel(self.log_level)

		self.js_runtime = options.get('js_runtime', 'duk')

		self.cov_modules = options.get('cov_modules')
		if self.cov_modules is None:
			raise Exception('missing cov_modules')

		bbs_files = options.get('bbs_files')
		if bbs_files is None:
			raise Exception('missing bbs')
		self._load_bbs_files(bbs_files)

		self.shm_name = '%d_BBCOUNT' % RAND(0xffffffff)
		self.shm = create_shm(self.shm_name, 4)

	def __on_message(self, message, data):
		if (message['type'] == 'error'):
			self.logger.error(message)

	def load(self, session):
		self.session = session
		script_path = join(FRIDA_SCRIPTDIR, 'cov_bp_win.js')
		with open(script_path, 'r') as scriptfile:
			self.script = self.session.create_script(scriptfile.read(), runtime=self.js_runtime)
			self.script.on('message', self.__on_message)
			self.script.load()

			options = {
				'shm_name': self.shm_name, # store bb_count
				'cov_modules': self.cov_modules,
				'bbs_infos': self.bbs_infos
			}
			self.script.exports.init(options)

	def _load_bbs_files(self, bbs_files):
		self.bbs_infos = []
		for bbs_file in bbs_files:
			with open(bbs_file, 'rb') as f:
				bbs_dict 	= pickle.loads(f.read())
				self.bbs_infos.append(bbs_dict)

	def get_bb_count(self):
		self.bb_count = u32_pointer(self.shm)[0] 
		return self.bb_count

	def has_new_cov(self):
		t = u32_pointer(self.shm)[0]
		if (t > self.bb_count):
			self.bb_count = t
			return True
		return False



