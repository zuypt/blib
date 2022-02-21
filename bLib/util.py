import os
import shutil
import ctypes
import traceback
from bLib.helper import *

basename = os.path.basename
dirname = os.path.dirname
abspath = os.path.abspath
exists = os.path.exists
join = os.path.join
isdir = os.path.isdir
isfile = os.path.isfile

def rename_corpus(path, ext=''):
	ext = ext.replace('.', '')
	for i, fname in enumerate(os.listdir(path)):
		fpath = join(path, fname)
		if isfile(fpath):
			dpath = join(path, '{:05d}.{}'.format(i, ext))
			shutil.move(fpath, dpath)

def fill_struct(is_qword = False, sz = 1024):
	r = ''
	if is_qword:
		pref = 'QWORD'
	else:
		pref = 'DWORD'

	for i in range(sz):
		r += pref + ' a%d;\n'%i
	return r

def readfile(path):
	try:
		f = open(path, 'rb')
	except:
		traceback.print_exc()
	d = f.read()
	f.close()
	return d

PACKAGE_DIR = dirname(abspath(__file__))

CLIB32 				= join(PACKAGE_DIR, 'clib', 'bin32', 'release')
CLIB64 				= join(PACKAGE_DIR, 'clib', 'bin64', 'release')
FRIDA_SCRIPTDIR 	= join(PACKAGE_DIR, 'frida_scripts')

def addressof(pointer):
	return ctypes.addressof(pointer.contents)

def void_pointer(addr):
	VOIDP = ctypes.POINTER(ctypes.c_void_p)
	p = ctypes.cast(addr, VOIDP)
	return p

def u32_pointer(addr):
	INTP = ctypes.POINTER(ctypes.c_uint)
	p = ctypes.cast(addr, INTP)
	return p

def u64_pointer(addr):
	INTP = ctypes.POINTER(ctypes.c_uint64)
	p = ctypes.cast(addr, INTP)
	return p

def u8_pointer(addr):
	U8P = ctypes.POINTER(ctypes.c_ubyte)
	p = ctypes.cast(addr, U8P)
	return p

def malloc(sz):
	return u8_pointer((ctypes.c_ubyte*sz)())

def str2PCSTR(s):
	return ctypes.c_char_p(bytes(s, 'ansi'))

def next_pow2(n):
	if n == 0:
		return 0
	out = n - 1
	out |= out >> 1
	out |= out >> 2
	out |= out >> 4
	out |= out >> 8
	out |= out >> 16
	return out + 1

'''
TODO
check these flip functions's correctness
'''
def bitflip_1bit(data, pos):
	data[int(pos / 8)] ^= (0x80 >> (pos % 8))
	return data

def bitflip_2bits(data, pos):
	if pos >= len(data) * 7:
		return data
	data[int(pos / 7)] ^= (0xC0 >> (pos % 7))
	return data

def bitflip_4bits(data, pos):
	if pos >= len(data) * 5:
		return data
	data[int(pos / 5)] ^= (0xF0 >> (pos % 5))
	return data

def byteflip_1(data, pos):
	if pos >= len(data):
		return data
	data[pos] ^= 0xFF
	return data

def byteflip_2(data, pos):
	if pos + 1 >= len(data) or len(data) <= 1:
		return data
	data[pos] ^= 0xFF
	data[pos + 1] ^= 0xFF
	return data

def byteflip_4(data, pos):
	if pos + 3 >= len(data) or len(data) <= 3:
		return data
	data[pos] ^= 0xFF
	data[pos + 1] ^= 0xFF
	data[pos + 2] ^= 0xFF
	data[pos + 3] ^= 0xFF
	return data

def mutate_byte_arithmetic(data, func_state):
	if not func_state:
		func_state = [0, 0, False]

	if func_state[1] > AFL_ARITH_MAX:
		func_state[0] += 1
		func_state[1] = 0

	if func_state[0] >= len(data):
		if func_state[2] == False:
			func_state = [0, 0, True]
		else:
			return data, None

	# TODO: we have to check for could_be_bitflip()

	if func_state[2] == False:
		val = data[func_state[0]] + func_state[1]
	else:
		val = data[func_state[0]] - func_state[1]

	store_8(data, func_state[0], val)

	func_state[1] += 1

	return data, func_state


def mutate_2bytes_arithmetic(data, pos, n, is_sub):
	# TODO: we have to check for could_be_bitflip()
	val = load_16(data, pos)
	if is_sub == False:
		val += n
	else:
		val -= n
	store_16(data, pos, val)
	return data

def mutate_4bytes_arithmetic(data, pos, n, is_sub):
	# TODO: we have to check for could_be_bitflip()
	val = load_32(data, pos)
	if is_sub == False:
		val += n
	else:
		val -= n
	store_32(data, pos, val)
	return data

# TODO: implement is_not_bitflip and is_not_arithmetic
def mutate_1byte_interesting(data, pos, idx):
	data[pos] = interesting_8_Bit[idx]
	return data

# TODO: implement is_not_bitflip and is_not_arithmetic
def mutate_2bytes_interesting(data, pos, idx, swap):
	interesting_value = interesting_16_Bit[idx]
	if swap:
		interesting_value = swap_16(interesting_value)
	store_16(data, pos, interesting_value)
	return data

# TODO: implement is_not_bitflip and is_not_arithmetic
def mutate_4bytes_interesting(data, pos, idx, swap):
	interesting_value = interesting_32_Bit[idx]
	if swap:
		interesting_value = swap_32(interesting_value)
	store_32(data, pos, interesting_value)
	return data

def havoc_bitflip(data):
	pos = RAND(len(data) * 8)
	data = bitflip_1bit(data, pos)
	return data

def havoc_interesting_byte(data):
	pos = RAND(len(data))
	idx = RAND(len(interesting_8_Bit))
	data = mutate_1byte_interesting(data, pos, idx)
	return data

def havoc_interesting_2bytes(data):
	data_len = len(data)
	if data_len < 2:
		return data
	pos = RAND(data_len - 1) # substract 1 to make sure we have space for 2 bytes
	idx = RAND(len(interesting_16_Bit))
	swap = RAND(2) # is swap?
	data = mutate_2bytes_interesting(data, pos, idx, swap)
	return data

def havoc_interesting_4bytes(data):
	data_len = len(data)
	if data_len < 4:
		return data
	pos = RAND(len(data) - 3) # substract 1 to make sure we have space for 2 bytes
	idx = RAND(len(interesting_32_Bit))
	swap = RAND(2) # is swap?
	data = mutate_4bytes_interesting(data, pos, idx, swap)
	return data

def havoc_randomly_add(data): # similar to mutate_byte_arithmetic but a bit faster
	pos = RAND(len(data))
	data[pos] = in_range_8(data[pos] + 1 + RAND(AFL_ARITH_MAX))
	return data

def havoc_randomly_substract(data): # similar to mutate_byte_arithmetic but a bit faster
	pos = RAND(len(data))
	data[pos] = in_range_8(data[pos] - (1 + RAND(AFL_ARITH_MAX)))
	return data


def havoc_randomly_add_2bytes(data): # similar to mutate_byte_arithmetic but a bit faster
	data_len = len(data)
	if data_len < 2:
		return data
	pos = RAND(data_len - 1)
	n = 1 + RAND(AFL_ARITH_MAX)
	data = mutate_2bytes_arithmetic(data, pos, n, True)
	return data

def havoc_randomly_substract_2bytes(data): # similar to mutate_byte_arithmetic but a bit faster
	data_len = len(data)
	if data_len < 2:
		return data
	pos = RAND(data_len - 1)
	n = 1 + RAND(AFL_ARITH_MAX)
	data = mutate_2bytes_arithmetic(data, pos, n, False)
	return data


def havoc_randomly_add_4bytes(data): # similar to mutate_byte_arithmetic but a bit faster
	data_len = len(data)
	if data_len < 4:
		return data
	pos, n, is_sub = RAND(data_len - 3), 1 + RAND(AFL_ARITH_MAX), False
	data = mutate_4bytes_arithmetic(data, pos, n , is_sub)
	return data

def havoc_randomly_substract_4bytes(data): # similar to mutate_byte_arithmetic but a bit faster
	data_len = len(data)
	if data_len < 4:
		return data
	pos, n, is_sub = RAND(data_len - 3), 1 + RAND(AFL_ARITH_MAX), True
	data = mutate_4bytes_arithmetic(data, pos, n, is_sub)
	return data

def havoc_set_randomly(data):
	pos = RAND(len(data))
	data[pos] = in_range_8(data[pos] ^ (1 + RAND(255)))
	return data

def havoc_remove_randomly_block(data):
	data_len = len(data)
	if data_len <= 2:
		return data

	len_to_remove = AFL_choose_block_len(data_len - 1)
	pos = RAND(data_len - len_to_remove + 1)
	data = data[:pos] + data[pos+len_to_remove:]
	return data

def prepare_block(data):
	actually_clone = RAND(4)
	data_len = len(data)

	if actually_clone:
		clone_len = AFL_choose_block_len(data_len)
		clone_from = RAND(data_len - clone_len + 1 )
	else:
		clone_len = AFL_choose_block_len(AFL_HAVOC_BLK_XL)
		clone_from = 0
	clone_to = RAND(data_len)

	if actually_clone:
		block = data[clone_from:clone_from + clone_len]
	else:
		use_data_block = RAND(2)
		if use_data_block:
			block_start = RAND(data_len)
			block = data[block_start:block_start+clone_len]
		else:
			block = [RAND(256)] * clone_len # TODO: check if it is actually correct implementation
			block = bytearray(block)
	return block, clone_to, clone_len

# insert random block
def havoc_clone_randomly_block(data):
	block, clone_to, clone_len = prepare_block(data)
	if clone_len == 0:
		return data
	data = data[:clone_to] + block + data[clone_to:]
	return data

# overwrite random block
def havoc_overwrite_randomly_block(data):
	block, clone_to, clone_len = prepare_block(data)
	if clone_len == 0:
		return data
	data = data[:clone_to] + block + data[clone_to+clone_len:]
	return data