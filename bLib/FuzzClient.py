from abc import ABC, abstractmethod

class FuzzClient(ABC):
	def __init__(self, **options):
		self.logger = logging.getLogger('FuzzClient')
		self.log_level = options.get('log_level', logging.DEBUG)
		self.logger.setLevel(self.log_level)

		self.args = args
		self.pipe_name = options.get('pipe_name', 'Fuzzer1')

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