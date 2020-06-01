import random
import logging

from bLib.util import *
from bLib.const import *

from bLib import radamsa

class Mutator():
	def __init__(self, client, **options):
		self.logger = logging.getLogger('bMutator')
		self.log_level = options.get('log_level', logging.DEBUG)
		self.logger.setLevel(self.log_level)

		self.id = options.get('id', 'Fuzzer1')

		self.trim_start_steps = options.get('trim_start_steps', TRIM_START_STEPS)
		self.trim_end_steps   = options.get('trim_end_steps', TRIM_END_STEPS)
		self.trim_min_bytes   = options.get('trim_min_bytes', TRIM_MIN_BYTES)

		self.map_sz   = options.get('map_sz', MAP_SZ)
		self.client = client

	def stop(self):
		self.running = False

	def init_radamsa(self):
		radamsa.init(self.id)

	def radamsa(self, testcase):
		'''
		TODO:
		fix this size here
		'''
		r = radamsa.radamsa(testcase.fullpath, 1024)
		while len(r) == 0:
			r = radamsa.radamsa(testcase.fullpath, 1024)
		return r
	
	def trim_case(self, testcase):
		self.running = True

		self.logger.debug('trimming: %s' % testcase.fname)
		self.logger.debug('exec_cksum: %x' % testcase.exec_cksum)
		self.logger.debug('testcase len: %d' % testcase.len)

		if testcase.len < 5:
			return

		len_p2 = next_pow2(testcase.len)
		'''
		start trimming 1/16 of the file size
		remove_len is the number of byte we want to trim
		'''
		remove_len = max(len_p2//self.trim_start_steps, self.trim_min_bytes)

		while remove_len >= max(len_p2//self.trim_end_steps, self.trim_min_bytes):
			self.logger.debug('remove_len: %d' % remove_len)
			'''
			we don't start trimming at the start of the file
			should remove pos start at 0
			'''
			remove_pos = 0

			while remove_pos < testcase.len:
				self.logger.debug('remove_pos: %d' % remove_pos)
				'''
				the number of byte we can actually trim
				'''
				trim_avail = min(remove_len, testcase.len - remove_pos)
				buf = cut(testcase.read(), remove_pos, trim_avail)

				'''
				TODO:
				fix the timeout
				execute the new testcase
				'''
				fault = self.client.exec_one(buf, 10*1000)
				
				cksum = self.client.hash32()
				self.logger.debug('cksum: %x' % cksum)
				if cksum == testcase.exec_cksum:
					self.logger.debug('commit change')
					''' write the change back into testcase '''
					testcase.write(buf)
					len_p2 = next_pow2(testcase.len)
				else:
					'''
					the trim result into a different path
					move remove_ps up
					'''
					remove_pos += remove_len
			'''
			switch to a smaller step
			'''
			remove_len >>= 1


	def trim_case_ignore_loop(self, testcase):
		self.running = True

		if testcase.len < 5:
			return FAULT_NONE

		# self.logger.debug('trimming: %s' % testcase.fname)
		# self.logger.debug('exec_cksum: %x' % testcase.exec_cksum)
		# self.logger.debug('testcase len: %d' % testcase.len)

		f = open('trim', 'wb')
		f.write(testcase.read())
		f.close()

		first_trace = malloc(self.map_sz)
		fault = self.client.exec_one(testcase.read(), 10*1000)
		if fault != FAULT_NONE:
			return fault

		ctypes.memmove(first_trace, self.client.trace_bits, self.map_sz)


		len_p2 = next_pow2(testcase.len)
		# self.logger.debug('testcase.len: %d' % testcase.len)
		# self.logger.debug('len_p2: %d' % len_p2)
		'''
		start trimming 1/16 of the file size
		remove_len is the number of byte we want to trim
		'''
		remove_len = max(len_p2//self.trim_start_steps, self.trim_min_bytes)
		# self.logger.debug('remove_len: %d' % remove_len)
		while remove_len >= max(len_p2//self.trim_end_steps, self.trim_min_bytes):
			# self.logger.debug('remove_len: %d' % remove_len)
			'''
			afl's original code
			remove_pos = remove_len => skip the first block.
			'''
			remove_pos = 0

			'''
			without the second condition (remove_len < testcase.len)
			it is possible that the trim result will have 0 bytes
			'''
			while remove_pos < testcase.len and remove_len < testcase.len:
				if not self.running:
					return

				# self.logger.debug('remove_pos: %d' % remove_pos)
				'''
				the number of byte we can actually trim
				'''
				trim_avail = min(remove_len, testcase.len - remove_pos)
				buf = cut(testcase.read(), remove_pos, trim_avail)

				'''
				TODO:
				fix the timeout
				execute the new testcase
				'''
				fault = self.client.exec_one(buf, 10*1000)
				if fault != FAULT_NONE:
					return fault

				r = self.client.cmp_bitmap_ignore_loop(first_trace, self.client.trace_bits)
				if r == 0:
					# self.logger.debug('commit change')
					''' write the change back into testcase '''
					testcase.write(buf)
					len_p2 = next_pow2(testcase.len)
					# self.logger.debug('len_p2: %d' % len_p2)
				else:
					'''
					the trim result into a different path
					move remove_ps up
					'''
					remove_pos += remove_len
			'''
			switch to a smaller step
			'''
			remove_len >>= 1

		return FAULT_NONE

	def havoc(self, data):
		func_to_choose = [havoc_bitflip, havoc_interesting_byte, havoc_interesting_2bytes, havoc_interesting_4bytes,
						  havoc_randomly_add, havoc_randomly_substract, havoc_randomly_add_2bytes,
						  havoc_randomly_substract_2bytes, havoc_randomly_add_4bytes, havoc_randomly_substract_4bytes,
						  havoc_set_randomly, havoc_remove_randomly_block, havoc_clone_randomly_block,
						  havoc_overwrite_randomly_block]

		# use_stacking = 1 << 1 + RAND(AFL_HAVOC_STACK_POW2)
		# allow use_stacking == 1, good for small input
		# crash testbin in 30 mins
		use_stacking = 1 << RAND(AFL_HAVOC_STACK_POW2)

		for _ in range (0, use_stacking):
			method = RAND(len(func_to_choose))
			# randomly select one of the available methods
			data = func_to_choose[method](data)

		return data

	def splice(self, data, list_of_files):
		data_len = len(data)
		if data_len <= 2:
			return data

		testcase = random.choice(list_of_files)
		

		content_target = testcase.read()

		# self.logger.debug(b'1\n' + data)
		# self.logger.debug(b'2\n' + content_target)

		f_diff, l_diff = locate_diffs(data, content_target)

		# afl has f_diff == 0 but I believe we want to start with 0
		if l_diff < 2 or f_diff == l_diff: 
			return data

		split_last_byte = f_diff + RAND(l_diff - f_diff)
		block = data[f_diff:f_diff+split_last_byte]
		content_target = content_target[:f_diff] + block + content_target[f_diff+split_last_byte:]
		data = content_target

		# self.logger.debug(b'2\n' + data[:32])

		data = self.havoc(data)
		return data