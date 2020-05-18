import traceback
import frida
import psutil
import logging
import inspect
import time

from bLib.const import *
from bLib.win_util import *

logging.basicConfig()

class Executor():
	def __init__(self, bcov, args, **options):
		self.logger = logging.getLogger('bExecutor')
		self.log_level = options.get('log_level', logging.DEBUG)
		self.logger.setLevel(self.log_level)

		self.bcov = bcov
		self.args = args

		self.id = options.get('id', 'Fuzzer1')

		self.pipe_name = 'pipe_%s' % self.id

		self.js_runtime = options.get('js_runtime', 'duk') 

		self.inp_script_path = options.get('inp_script')

		self.persistence_mode = options.get('persistence_mode', 'persistence')

		self.target_module = options.get('target_module')
		if self.target_module is None:
			pass
		else:
			self.target_offset = options.get('target_offset')
			if self.target_offset is None:
				raise Exception('target_offset must be specified with target_module')

		'''
		we gonna write input file to this path
		'''
		self.inp_path = options.get('inp_path')
		self.logger.debug('inp_path: %s' % self.inp_path)

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

		self.exec_one = self.__start_process

	def cleanup(self):
		self.kill()

	def resume(self):
		frida.resume(self.pid)

	def __start_process(self, tmout):		
		self.pid 		= frida.spawn(self.args)
		self.session 	= frida.attach(self.pid)

		self._load_inp_cli()
		self._load_executor_cli()
		
		self.bcov.load(self.session)

		self.resume()

		self.exec_one = self.__exec_one
		return self.__exec_one(tmout)

	def __exec_one(self, tmout):
		cmd = ReadCommandFromPipe(INFINITE)
		# self.logger.debug('recieved from pipe: ' + repr(r))
		if cmd != b'P':
			self.logger.error('unexpected cmd, expetected P, recieved: ' + repr(cmd))
			self.kill()
			return FAULT_ERROR
		WriteCommandToPipe(b'F')

		cmd = ReadCommandFromPipe(tmout)
		# self.logger.debug('recieved from pipe: ' + repr(r))
		if cmd == b'K':
			return FAULT_NONE
		elif cmd == b'C':
			self.cleanup()
			return FAULT_CRASH
		elif cmd == b'\x00':
			'''
			It's good to know if client has failed (cause target process to crash without sending 'C') 
			or the target process is hang when dryrun (goood for debugging purpose).
			Known bugs: client crashes when encounter a stack exhaustion bug.
			'''
			time.sleep(1) # wait for target process to terminate 
			if psutil.pid_exists(self.pid):
				self.logger.info('timeout')
				self.cleanup()
				return FAULT_TMOUT
			else:
				self.cleanup()
				self.logger.error('client is dead')
				return FAULT_ERROR
		else:
			self.logger.error('unexpected cmd, recieved: ' + repr(cmd))
			return FAULT_ERROR

	def kill(self):
		self.exec_one = self.__start_process
		# make sure the process is gone
		while psutil.pid_exists(self.pid):
			frida.kill(self.pid)
		CleanupPipe()
		
		self.logger.info('Process {} is killed'.format(self.pid))

	def write_inp_to_file(self, cur_inp):
		try:
			f = open(self.inp_path, 'wb')
			f.write(cur_inp)
			f.close()
		except:
			traceback.print_exc()

		if self.inp_sync:
			WriteCommandToPipe(b'I')

	def __on_message(self, message, data):
		if (message['type'] == 'error'):
			self.logger.error(message)

	def _load_inp_cli(self):
		if self.inp_script_path:
			self.logger.info('using input_script: %s' % self.inp_script_path)
			with open(self.inp_script_path, 'r') as f:
				self.input_script = self.session.create_script(f.read(), runtime=self.js_runtime)
				self.input_script.on('message', self.__on_message)
				self.input_script.load()
				self.setup_event()
				options = {
					'input_path': self.cur_inp
				}
				self.input_script.exports.init(options)

	def _load_executor_cli(self):
		assert(SetupPipe(str2PCSTR('\\\\.\\pipe\\%s' % self.pipe_name)) == True)
		with open(join(FRIDA_SCRIPTDIR, 'executor_cli_win.js'), 'r') as f:
			self.executor_script = self.session.create_script(f.read(), runtime=self.js_runtime)
			self.executor_script.on_message = self.__on_message
			self.executor_script.load()

			options = {
				'libpath32': CLIB32,
				'libpath64': CLIB64,
				'pipe_name': self.pipe_name,
				'target_module': self.target_module,
				'target_offset': self.target_offset,
				'inp_sync_module': self.inp_sync_module,
				'inp_sync_offset': self.inp_sync_offset
			}

			self.executor_script.exports.init(options)
			assert (OverlappedConnectNamedPipe() == True)
