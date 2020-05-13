

			self.cur_inp = radamsa.radamsa(testcase.fullpath)
			while not self.cur_inp:
				self.cur_inp = radamsa.radamsa(testcase.fullpath)
			self.logger.info('mutating ' + testcase)
			r = self.executor.exec_one(self.cur_inp)
			if r == OK:
				pass
			elif r == CRASH:
				self.logger.info('testcase result in a crash')
				self._crash_handler()
			elif r == TIMEOUT:
				self.logger.info('testcase timeout')
				self._timeout_handler()
			elif r == CLIENT_FUCKUP:
				'''
				TODO
				fix client so we don't have to handle this case anymore\
				handle it like timeout for now
				'''
				self.logger.error('client fuckup')
				self._timeout_handler()

''' for android '''
''' everything is through rpc, slow but works for non root device '''

if len(inp) < 5:
			return 
		len_p2 = next_pow2(len(inp))
		self.logger.debug('len_p2: %d' % len_p2)

		''' the number of bytes we gonna remove '''
		remove_len = max(len_p2 / self.TRIM_START_STEPS, self.TRIM_MIN_BYTES)
		while remove_len >= max(len_p2 / self.TRIM_END_STEPS, self.TRIM_MIN_BYTES):
			''' our starting position '''
			remove_pos = remove_len
			
			self.stage_name = 'trim %d' % remove_len
			self.stage_cur = 0
			self.stage_max = len(inp) / remove_len

			while remove_pos < len(inp):
				trim_avail = min(remove_len, len(inp) - remove_pos)

class frida_bCov():
	def __init__(self, session, log_level=logging.DEBUG):
		self.session = session
		self.runtime = 'duk'
		self.options = None
		self.crash_cb = None
		self.covlen = 0

		self.logger = logging.getLogger('frida_bCov')
		self.logger.setLevel(log_level)
		

	def set_options(self, options):
		self.options = options
		if options:
			if 'cov_module_names' not in self.options:
				raise Exception('Missing cov_module_names')

	def load(self):
		if not self.options:
			raise Exception('set bCov.options first')

		script_path = join(BCOV_SCRIPTDIR, 'cov_event.js')
		with open(script_path, 'r') as scriptfile:
			self.script = self.session.create_script(scriptfile.read(), runtime=self.runtime)
			self.script.on('message', self.on_message)
			self.script.load()
			#self.script.exports.init(self.options)
			self.loaded = True

	def get_options(self):
		return self.script.exports.get_options()

	def get_modules(self):
		modules = self.script.exports.get_modules()
		for module in modules:
			module['base'] = int(module['base'], 16)
		return modules

	def get_cov(self):
		covs = []
		for temp in self.script.exports.get_cov():
			cov = []
			for addr in temp.keys():
				cov.append(int(addr))
			covs.append(cov)
		return covs

	def load_cov(self, covs):
		raise Exception('not implemented')

	def get_covlen(self):
		return self.script.exports.get_covlen()

	def on_crash(self):
		details = self.script.exports.get_crash()
		if self.crash_cb:
			self.crash_cb(details)
		else:
			self.logger.info(details)

	def on_message(self, message, data):
		MSG_DEBUG 		= '\x01'
		MSG_COVLEN 		= '\x03'
		MSG_CRASH		= '\x04'

		if (message['type'] == 'send'):
			payload = message['payload']
			if payload[0] == MSG_DEBUG:
				self.logger.debug(payload)
			elif payload[0] == MSG_COVLEN:
				self.covlen = int(payload[1:])
		elif (message['type'] == 'error'):
				self.logger.error(message)


def get_covlen(self):
	return self.script.exports.get_covlen()

def on_crash(self):
	details = self.script.exports.get_crash()
	if self.crash_cb:
		self.crash_cb(details)
	else:
		self.logger.info(details)

@property
def covlen(self):
	return u32_pointer(self.shm)[0]



class bFuzz_AFL():
	def __init__(self, args, log_level=logging.DEBUG):
		self.fuzzer_id = 'f1'
		# self.bin_path = path
		self.args = args

		self.options = None

		self.covlen = 0
		self.queue = []

		self.hang_id = 0
		self.crash_id = 0
		self.dryrun_idx = 0
		self.new_path_count = 0

		self.timeout = 60*2
		self.timer_started = 0

		self.nexecs = 0

		self.logger = logging.getLogger('bFuzzer')
		self.logger.setLevel(log_level)

		self.lock = threading.Lock()

	def kill(self):
		frida.kill(self.pid)

	def start_process(self, covs=None):
		self.pid = frida.spawn(self.args)
		self.session = frida.attach(self.pid)
		self.bcov = frida_bCov(self.session, type='shm')
		self.bcov.crash_cb = self.on_crash
		self.bcov.set_options(
			{
			'fuzzer_id': self.fuzzer_id, 
			'cov_module_names': ['AdobeXMP.dll'], 
			'target_module_name': 'EScript.api', 
			'target_offset': 0xa8020
			}
		)
		self.bcov.load()
		if covs:
			self.bcov.load_cov(covs)

	def post_input(self, inp):
		with open(self.cur_inp, 'wb') as f:
			f.write(inp)
		self.set_event()

	def get_next_dryrun_input(self):
		if self.dryrun_idx < len(self.queue):	
			fname = self.queue[self.dryrun_idx]
			self.logger.debug('dryrun: ' + fname)
			r = self.read_input(fname)
			self.dryrun_idx += 1
			return r
		else:
			return None

	'''for detect timeout and unexpected crash '''
	def timeout_handler(self):
		covs = self.bcov.get_cov()

		fname = 'hang_%d' % self.hang_id
		self.hang_id += 1
		shutil.copy(self.cur_inp, join(self.hangdir, fname))
		self.logger.info('timeout')
		self.kill()
		self.start_process(covs)
		self.load_inpscript()
		frida.resume(self.pid)

	def get_next_fuzzing_input(self):
		fname = random.choice(self.queue)
		self.logger.debug('mutating %s' % fname)
		return radamsa.radamsa(join(self.queuedir, fname))

	def found_new_path(self):
		self.new_path_count += 1
		fname = 'id_%06d' % self.new_path_count
		shutil.copy(self.cur_inp, join(self.queuedir, fname))
		self.queue.append(fname)

	def state_dryrun(self):
		inp = self.get_next_dryrun_input()
		if inp == None:
			self.covlen = self.bcov.covlen
			self.logger.info('dryrun finished')
			self.state = STATE_FUZZING
			self.state_fuzzing()
		else:		
			self.post_input(inp)

	def state_fuzzing(self):
		if self.bcov.covlen > self.covlen:
			self.covlen = self.bcov.covlen
			self.found_new_path()
		inp = self.get_next_fuzzing_input()
		self.post_input(inp)

	def inp_script_cb(self):
		self.logger.debug('>>')
		self.lock.acquire()

		self.nexecs += 1
		if self.nexecs%10==0:
			self.runtime = time.time() - self.starttime
			self.logger.info('exec speed: %f' % (self.nexecs/self.runtime))


		if self.timer_started == 1:
			self.timer.cancel()
			self.timer_started = 0

		self.logger.info('covlen: %d' % self.bcov.covlen)
		if self.state == STATE_DRYRUN:
			self.state_dryrun()

		elif self.state == STATE_FUZZING:
			self.state_fuzzing()

		self.timer = threading.Timer(self.timeout, self.timeout_handler) 
		self.timer.start()
		self.timer_started = 1
		self.logger.debug('<<')
		self.lock.release()

	def on_crash(self, details):
		self.timer.cancel()
		self.timer_started = 0
		covs = self.bcov.get_cov()
		shutil.copyfile(self.cur_inp, join(self.crashdir, 'crash_%d'%self.crash_id))
		self.crash_id += 1
		self.logger.info('crash')
		self.kill()
		self.start_process(covs)
		self.load_inpscript()
		frida.resume(self.pid)

	def on_message(self, message, data):
		# self.logger.debug(message)
		MSG_INPUT = '\x01'
		if message['type'] == 'send':
			if message['payload'] == MSG_INPUT:
				self.inp_script_cb()
		elif message['type'] == 'error':
			self.logger.error(message)

	def reload_queue(self):
		for fname in os.listdir(self.queuedir):
			if fname not in self.queue:
				self.queue.append(fname)

	def save_state(self):
		fuzzer_state = {
			'new_path_count': self.new_path_count,
			'state': self.state,
			# ugly hack, we are not sure if the current dryrun is finished
			'dryrun_idx': self.dryrun_idx-1,
			'hang_id': self.hang_id,
			'crash_id:': self.crash_id
		}
		with open(join(self.odir, 'state.pkl'), 'wb') as f:
			f.write(pickle.dumps(fuzzer_state))

		with open(join(self.odir, 'cov.pkl'), 'wb') as f:
			f.write(pickle.dumps(self.bcov.get_cov(), protocol=2))

	def load_state(self):
		with open(join(self.odir, 'cov.pkl'), 'rb') as f:
			covs = pickle.loads(f.read())
		self.bcov.load_cov(covs)
		with open(join(self.odir, 'state.pkl'), 'rb') as f:
			fuzzer_state = pickle.loads(f.read())
		self.reload_queue()
		self.state = fuzzer_state['state']
		self.new_path_count = fuzzer_state['new_path_count']
		self.dryrun_idx = fuzzer_state['dryrun_idx']
		self.hang_id = fuzzer_state['hang_id']
		self.crash_id = fuzzer_state['crash_id']

	def setup_event(self):
		CreateEvent = windll.kernel32.CreateEventA
		CreateEvent.argtypes = (LPVOID, BOOL, BOOL, LPCSTR)
		CreateEvent.restype = HANDLE
		self.event = CreateEvent(0, 1, 0, c_char_p(bytes(self.fuzzer_id, 'ansi')))

	def set_event(self):
		SetEvent = windll.kernel32.SetEvent
		SetEvent.argtypes = (HANDLE,)
		SetEvent(self.event)

	def load_inpscript(self):
		input_script = self.options.get('input_script')
		if input_script:
			self.logger.debug('using input_script: %s' % input_script)
			with open(input_script, 'r') as scriptfile:
				self.input_script = self.session.create_script(scriptfile.read())
				self.input_script.on('message', self.on_message)
				self.input_script.load()
				self.setup_event()
				options = {
					'input_path': self.cur_inp,
					'event_name': self.fuzzer_id
				}
				self.input_script.exports.init(options)

	def start(self):
		if not self.options:
			raise Exception('options not set')
		self.start_process()
		radamsa.init(self.fuzzer_id)
		self.load_inpscript()

		if self.options.get('skip_dryrun'):
			self.state = STATE_FUZZING
		else:
			self.state = STATE_DRYRUN

		if os.path.exists(join(self.odir, 'cov.pkl')):
			self.logger.info('resuming')
			self.load_state()
		else:
			self.logger.info('new fuzzing session')
			if os.path.exists(self.odir):
				shutil.rmtree(self.odir)
			os.makedirs(self.odir)
			os.mkdir(self.queuedir)
			os.mkdir(self.crashdir)
			os.mkdir(self.hangdir)

			for fname in os.listdir(self.idir):
				self.add_file_to_queue(join(self.idir, fname))
		self.starttime = time.time()
		frida.resume(self.pid)

	def set_options(self, options):
		self.options = options
		if options:
			if 'idir' not in options:
				options['idir'] = 'in'
				self.logger.info('idir not specified, using default value `in`')
			if 'odir' not in options:
				options['odir'] = 'out'
				self.logger.info('odir not specified, using default value `out`')

			self.idir = options['idir']
			self.odir = join(options['odir'], self.fuzzer_id)
			self.queuedir = join(self.odir, 'queue')
			self.crashdir = join(self.odir, 'crash')
			self.hangdir = join(self.odir, 'hang')
			self.cur_inp = join(self.odir, 'cur_inp')

	def add_file_to_queue(self, path):
		fname = os.path.basename(path)
		''' copy file to queue follder '''
		shutil.copyfile(path, join(self.queuedir, fname))
		''' add fname to queue '''
		self.queue.append(fname)

	def read_input(self, fname):
		with open(join(self.queuedir, fname), 'rb') as f:
			d = f.read()
		return d


class bFuzz():
	def __init__(self, args, log_level=logging.DEBUG):
		self.fuzzer_id = 'f1'
		# self.bin_path = path
		self.args = args

		self.options = None

		self.covlen = 0
		self.queue = []

		self.hang_id = 0
		self.crash_id = 0
		self.dryrun_idx = 0
		self.new_path_count = 0

		self.timeout = 60*2
		self.timer_started = 0

		self.nexecs = 0

		self.logger = logging.getLogger('bFuzzer')
		self.logger.setLevel(log_level)

		self.lock = threading.Lock()

	def kill(self):
		frida.kill(self.pid)

	def start_process(self, covs=None):
		self.pid = frida.spawn(self.args)
		self.session = frida.attach(self.pid)
		self.bcov = frida_bCov(self.session, type='shm')
		self.bcov.crash_cb = self.on_crash
		self.bcov.set_options(
			{
			'fuzzer_id': self.fuzzer_id, 
			'cov_module_names': ['AdobeXMP.dll'], 
			'target_module_name': 'EScript.api', 
			'target_offset': 0xa8020
			}
		)
		self.bcov.load()
		if covs:
			self.bcov.load_cov(covs)

	def post_input(self, inp):
		with open(self.cur_inp, 'wb') as f:
			f.write(inp)
		self.set_event()

	def get_next_dryrun_input(self):
		if self.dryrun_idx < len(self.queue):	
			fname = self.queue[self.dryrun_idx]
			self.logger.debug('dryrun: ' + fname)
			r = self.read_input(fname)
			self.dryrun_idx += 1
			return r
		else:
			return None

	'''for detect timeout and unexpected crash '''
	def timeout_handler(self):
		covs = self.bcov.get_cov()

		fname = 'hang_%d' % self.hang_id
		self.hang_id += 1
		shutil.copy(self.cur_inp, join(self.hangdir, fname))
		self.logger.info('timeout')
		self.kill()
		self.start_process(covs)
		self.load_inpscript()
		frida.resume(self.pid)

	def get_next_fuzzing_input(self):
		fname = random.choice(self.queue)
		self.logger.debug('mutating %s' % fname)
		return radamsa.radamsa(join(self.queuedir, fname))

	def found_new_path(self):
		self.new_path_count += 1
		fname = 'id_%06d' % self.new_path_count
		shutil.copy(self.cur_inp, join(self.queuedir, fname))
		self.queue.append(fname)

	def state_dryrun(self):
		inp = self.get_next_dryrun_input()
		if inp == None:
			self.covlen = self.bcov.covlen
			self.logger.info('dryrun finished')
			self.state = STATE_FUZZING
			self.state_fuzzing()
		else:		
			self.post_input(inp)

	def state_fuzzing(self):
		if self.bcov.covlen > self.covlen:
			self.covlen = self.bcov.covlen
			self.found_new_path()
		inp = self.get_next_fuzzing_input()
		self.post_input(inp)

	def inp_script_cb(self):
		self.logger.debug('>>')
		self.lock.acquire()

		self.nexecs += 1
		if self.nexecs%10==0:
			self.runtime = time.time() - self.starttime
			self.logger.info('exec speed: %f' % (self.nexecs/self.runtime))


		if self.timer_started == 1:
			self.timer.cancel()
			self.timer_started = 0

		self.logger.info('covlen: %d' % self.bcov.covlen)
		if self.state == STATE_DRYRUN:
			self.state_dryrun()

		elif self.state == STATE_FUZZING:
			self.state_fuzzing()

		self.timer = threading.Timer(self.timeout, self.timeout_handler) 
		self.timer.start()
		self.timer_started = 1
		self.logger.debug('<<')
		self.lock.release()

	def on_crash(self, details):
		self.timer.cancel()
		self.timer_started = 0
		covs = self.bcov.get_cov()
		shutil.copyfile(self.cur_inp, join(self.crashdir, 'crash_%d'%self.crash_id))
		self.crash_id += 1
		self.logger.info('crash')
		self.kill()
		self.start_process(covs)
		self.load_inpscript()
		frida.resume(self.pid)

	def on_message(self, message, data):
		# self.logger.debug(message)
		MSG_INPUT = '\x01'
		if message['type'] == 'send':
			if message['payload'] == MSG_INPUT:
				self.inp_script_cb()
		elif message['type'] == 'error':
			self.logger.error(message)

	def reload_queue(self):
		for fname in os.listdir(self.queuedir):
			if fname not in self.queue:
				self.queue.append(fname)

	def save_state(self):
		fuzzer_state = {
			'new_path_count': self.new_path_count,
			'state': self.state,
			# ugly hack, we are not sure if the current dryrun is finished
			'dryrun_idx': self.dryrun_idx-1,
			'hang_id': self.hang_id,
			'crash_id:': self.crash_id
		}
		with open(join(self.odir, 'state.pkl'), 'wb') as f:
			f.write(pickle.dumps(fuzzer_state))

		with open(join(self.odir, 'cov.pkl'), 'wb') as f:
			f.write(pickle.dumps(self.bcov.get_cov(), protocol=2))

	def load_state(self):
		with open(join(self.odir, 'cov.pkl'), 'rb') as f:
			covs = pickle.loads(f.read())
		self.bcov.load_cov(covs)
		with open(join(self.odir, 'state.pkl'), 'rb') as f:
			fuzzer_state = pickle.loads(f.read())
		self.reload_queue()
		self.state = fuzzer_state['state']
		self.new_path_count = fuzzer_state['new_path_count']
		self.dryrun_idx = fuzzer_state['dryrun_idx']
		self.hang_id = fuzzer_state['hang_id']
		self.crash_id = fuzzer_state['crash_id']

	def setup_event(self):
		CreateEvent = windll.kernel32.CreateEventA
		CreateEvent.argtypes = (LPVOID, BOOL, BOOL, LPCSTR)
		CreateEvent.restype = HANDLE
		self.event = CreateEvent(0, 1, 0, c_char_p(bytes(self.fuzzer_id, 'ansi')))

	def set_event(self):
		SetEvent = windll.kernel32.SetEvent
		SetEvent.argtypes = (HANDLE,)
		SetEvent(self.event)

	def load_inpscript(self):
		input_script = self.options.get('input_script')
		if input_script:
			self.logger.debug('using input_script: %s' % input_script)
			with open(input_script, 'r') as scriptfile:
				self.input_script = self.session.create_script(scriptfile.read())
				self.input_script.on('message', self.on_message)
				self.input_script.load()
				self.setup_event()
				options = {
					'input_path': self.cur_inp,
					'event_name': self.fuzzer_id
				}
				self.input_script.exports.init(options)

	def start(self):
		if not self.options:
			raise Exception('options not set')
		self.start_process()
		radamsa.init(self.fuzzer_id)
		self.load_inpscript()

		if self.options.get('skip_dryrun'):
			self.state = STATE_FUZZING
		else:
			self.state = STATE_DRYRUN

		if os.path.exists(join(self.odir, 'cov.pkl')):
			self.logger.info('resuming')
			self.load_state()
		else:
			self.logger.info('new fuzzing session')
			if os.path.exists(self.odir):
				shutil.rmtree(self.odir)
			os.makedirs(self.odir)
			os.mkdir(self.queuedir)
			os.mkdir(self.crashdir)
			os.mkdir(self.hangdir)

			for fname in os.listdir(self.idir):
				self.add_file_to_queue(join(self.idir, fname))
		self.starttime = time.time()
		frida.resume(self.pid)

	def set_options(self, options):
		self.options = options
		if options:
			if 'idir' not in options:
				options['idir'] = 'in'
				self.logger.info('idir not specified, using default value `in`')
			if 'odir' not in options:
				options['odir'] = 'out'
				self.logger.info('odir not specified, using default value `out`')

			self.idir = options['idir']
			self.odir = join(options['odir'], self.fuzzer_id)
			self.queuedir = join(self.odir, 'queue')
			self.crashdir = join(self.odir, 'crash')
			self.hangdir = join(self.odir, 'hang')
			self.cur_inp = join(self.odir, 'cur_inp')

	def add_file_to_queue(self, path):
		fname = os.path.basename(path)
		''' copy file to queue follder '''
		shutil.copyfile(path, join(self.queuedir, fname))
		''' add fname to queue '''
		self.queue.append(fname)

	def read_input(self, fname):
		with open(join(self.queuedir, fname), 'rb') as f:
			d = f.read()
		return d


		