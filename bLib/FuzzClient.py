import time
import frida
import pickle
import psutil
import logging

from time import sleep

from bLib.util import *
from bLib.const import *
from bLib.win_util import *

from abc import ABC, abstractmethod

class FridaClient(ABC):
	def __init__(self, args, **options):
		self.logger = logging.getLogger('FuzzClient')
		self.log_level = options.get('log_level', logging.DEBUG)
		self.logger.setLevel(self.log_level)

		self.args = args
		self.id = options.get('id', 'Fuzzer1')

		self.script = {}

		'''
		Do we always need pipe ?
		'''
		self.pipe_name = 'pipe_%s' % self.id
		self.js_runtime = options.get('js_runtime', 'duk') 

		self.inp_script_path = options.get('inp_script')

		'''
		TODO
		Support persistence mode
		'''

		'''
		valid value:
		- persistence
		- in_app
		'''
		self.persistence_mode = options.get('persistence_mode', 'persistence')

		self.target_module = options.get('target_module')
		if self.target_module is None:
			pass
		else:
			self.target_offset = options.get('target_offset')
			if self.target_offset is None:
				raise Exception('target_offset must be specified with target_module')

		self.cov_modules = options.get('cov_modules')
		if self.cov_modules is None:
			raise Exception('missing cov_modules')

		module_info_files = options.get('module_info_files')
		if module_info_files is None:
			raise Exception('missing module_info_files')

		'''
		This is used to wait for FuzzServer to write inp file in case of
		the target binary read input before target_offset
		'''
		self.inp_sync_module = options.get('inp_sync_module')
		self.inp_sync_offset = options.get('inp_sync_offset')

		if self.inp_sync_module and self.inp_sync_offset:
			self.inp_sync = True
		elif self.inp_sync_module and not self.inp_sync_offset:
			raise Exception('missing inp_sync_offset')
		elif self.inp_sync_offset and not self.inp_sync_module:
			raise Exception('missing inp_sync_module')
		else:
			self.inp_sync = False

	def __executor_on_message(self, message, data):
		if (message['type'] == 'error'):
			self.logger.error(message)

	@abstractmethod
	def init(self):
		pass

	@abstractmethod
	def cleanup(self):
		pass

	def restart_persistence_process(self):
		if psutil.pid_exists(self.pid):
			self.kill()
		CleanupPipe()
		self.logger.debug('restart_persistence_process')
		self.start_persistence_process()

	def exec_one(self, timeout):
		# we could hang here
		cmd = ReadCommandFromPipe(INFINITE)
		# self.logger.debug('recieved from pipe: ' + repr(r))
		if cmd != b'P':
			self.logger.error('unexpected cmd, expetected P, recieved: ' + repr(cmd))
			self.restart_persistence_process()
			return FAULT_ERROR
		WriteCommandToPipe(b'F')

		cmd = ReadCommandFromPipe(timeout)
		# self.logger.debug('recieved from pipe: ' + repr(r))

		self._update_cov()

		if cmd == b'K':
			return FAULT_NONE
		elif cmd == b'C':
			self.restart_persistence_process()
			return FAULT_CRASH
		elif cmd == b'\x00':
			'''
			It's good to know if client has failed (cause target process to crash without sending 'C') 
			or the target process is hang when dryrun (goood for debugging purpose).
			Known bugs: Frida crashes when encounter a stack exhaustion bug.
			'''

			'''
			it takes a while for a crashed process to disasspear
			'''
			sleep(1) 
			if psutil.pid_exists(self.pid):
				self.logger.info('timeout')
				self.restart_persistence_process()
				return FAULT_TMOUT
			else:
				'''
				client crashed but not sending 'C'
				'''
				self.logger.error('client is dead')
				return FAULT_ERROR
		else:
			self.restart_persistence_process()
			self.logger.error('unexpected cmd, recieved: ' + repr(cmd))
			return FAULT_ERROR


	'''
	used to implement resume functionality
	for example: save seen basic block
	'''
	def _load_client_state(self):
		pass

	def start_persistence_process(self):
		'''
		TODO
		implement stdout sink
		'''
		self.pid = frida.spawn(self.args)
		self.session = frida.attach(self.pid)

		self._load_client_scripts()
		self.resume()

	def kill(self):
		self.logger.info('kill process')

		'''
		TODO
		program won't terminate right away
		fix this
		'''
		while psutil.pid_exists(self.pid):
			frida.kill(self.pid)
		

		'''
		frida won't kill its thread without this
		'''
		self.session.detach()

	def resume(self):
		frida.resume(self.pid)

	'''
	doesn't need to override this class if using dump fuzzing
	'''
	def _load_cov_script(self):
		pass

	def _load_executor_script(self):
		if not SetupPipe(str2PCSTR('\\\\.\\pipe\\%s' % self.pipe_name)):
			self.logger.error('SetupPipe failed')
			return False
		options = {
			'libpath32': CLIB32,
			'libpath64': CLIB64,
			'pipe_name': self.pipe_name,
			'target_module': self.target_module,
			'target_offset': self.target_offset,
			'inp_sync_module': self.inp_sync_module,
			'inp_sync_offset': self.inp_sync_offset
		}
		self.load_script('executor_cli_win.js', options, self.__executor_on_message)
		if not OverlappedConnectNamedPipe():
			self.logger.error('OverlappedConnectNamedPipe failed')
			return False
		return True

	def _load_client_scripts(self):
		'''
		TODO: implement input script 
		'''
		self._load_executor_script()
		self._load_cov_script()

	def load_script(self, script_name, options, callback):
		script_path = join(FRIDA_SCRIPTDIR, script_name)
		with open(script_path, 'r') as scriptfile:
			self.script[script_name] = self.session.create_script(scriptfile.read(), runtime=self.js_runtime)
			self.script[script_name].on('message', callback)
			self.script[script_name].load()
			self.script[script_name].exports.init(options)

	@abstractmethod
	def _update_cov(self):
		pass

	@abstractmethod
	def has_new_cov(self):
		pass

	@abstractmethod
	def has_new_bb(self):
		pass

	@abstractmethod
	def has_new_edge(self):
		pass

class BreakpointClient(FridaClient):
	def __init__(self, args, **options):
		super().__init__(args, **options)

		module_info_files = options.get('module_info_files')
		if module_info_files is None:
			raise Exception('missing module_info_files')

		self._load_module_infos(module_info_files)

		self._local_hitcount = 0
		self._has_new_bb = False

	def __on_message(self, message, data):
		if (message['type'] == 'error'):
			self.logger.error(message)

	def _load_cov_script(self):
		options = {
			'shm_name': self.shm_name,
			'shm_size': self.bb_count,
			'cov_modules': self.cov_modules,
			'module_infos': self.module_infos
		}
		self.load_script('cov_bp_win.js', options, self.__on_message)
		script_path = join(FRIDA_SCRIPTDIR, 'cov_bp_win.js')

	def _load_module_infos(self, module_info_files):
		'''
		the total number of basic block
		'''
		self.bb_count = 0

		start_id = 0
		self.module_infos = []
		for module_info_file in module_info_files:
			with open(module_info_file, 'rb') as f:
				module_info = pickle.loads(f.read())

				block_dict = module_info['block_dict']
				self.bb_count += len(block_dict)

				'''
				assign a unique id to each block
				'''
				for k in block_dict:
					block_dict[k]['id'] = start_id
					start_id += 1

				self.module_infos.append(module_info)

		self.shm_name = '%s' % self.id
		self.shm = create_shm(self.shm_name + '_MAP', self.bb_count)
		self.hitcount = create_shm(self.shm_name + '_HITCOUNT', 4)

	def init(self):
		self.start_persistence_process()

	def cleanup(self):
		self.logger.info('client cleanup')
		self.kill()

	def get_hitcount(self):
		return u32_pointer(self.hitcount)[0]

	def _update_cov(self):
		t = self.get_hitcount()
		if t > self._local_hitcount:
			self._local_hitcount = t
			self._has_new_bb = True
		else:
			self._has_new_bb = False

	'''
	TODO
	comeup with a better design for this duplicate
	'''
	def has_new_cov(self):
		return self._has_new_bb

	def has_new_bb(self):
		return self._has_new_bb

	def has_new_edge(self):
		raise Exception('Not supprted')