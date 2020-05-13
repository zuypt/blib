import os
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

# func state is the position of the bit/byte to flip
def bitflip_1bit(data, func_state): # for i in range((len(data)*8)):
	if not func_state:
		func_state = 0

	if func_state >= len(data) * 8:
		return data, None # we are done here, lets switch to the next function

	data[int(func_state / 8)] ^= (0x80 >> (func_state % 8))
	func_state += 1

	return data, func_state

def bitflip_2bits(data, func_state): # for i in range((len(data)*7)):
	if not func_state:
		func_state = 0

	if func_state >= len(data) * 7:
		return data, None# we are done here, lets switch to the next function

	data[int(func_state / 7)] ^= (0xC0 >> (func_state % 7))

	func_state += 1

	return data, func_state


def bitflip_4bits(data, func_state): # for i in range((len(data)*5)):
	if not func_state:
		func_state = 0

	if func_state >= len(data) * 5:
		return data, None # we are done here, lets switch to the next function

	data[int(func_state / 5)] ^= (0xF0 >> (func_state % 5))

	func_state += 1

	return data, func_state


def byteflip_1(data, func_state): # for i in range((len(data))):
	if not func_state:
		func_state = 0

	if func_state >= len(data):
		return data, None # we are done here, lets switch to the next function

	data[func_state] ^= 0xFF

	func_state += 1

	return data, func_state


def byteflip_2(data, func_state): # for i in range(1, ((len(data)))):
	if not func_state:
		func_state = 0

	if func_state + 1 >= len(data):
		return data, None # we are done here, lets switch to the next function

	if len(data) > 1:
		data[func_state] ^= 0xFF
		data[func_state + 1] ^= 0xFF
	else:
		return data, None # input too small for byteflipping

	func_state += 1



	return data, func_state


def byteflip_4(data, func_state):
	if not func_state:
		func_state = 0

	if func_state + 3 >= len(data):
		return data, None

	if len(data) > 3:
		data[func_state] ^= 0xFF
		data[func_state + 1] ^= 0xFF
		data[func_state + 2] ^= 0xFF
		data[func_state + 3] ^= 0xFF
	else:
		return data, None # input too small for byteflipping

	func_state += 1


	return data, func_state


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


def mutate_2bytes_arithmetic(data, func_state):
	data_len = len(data)
	if data_len < 2:
		return data, None

	if not func_state:
		func_state = [0, 0, False]

	if func_state[1] > AFL_ARITH_MAX:
		func_state[0] += 1
		func_state[1] = 0

	if func_state[0] + 1 >= data_len:
		if func_state[2] == False:
			func_state = [0, 0, True]
		else:
			return data, None

	# TODO: we have to check for could_be_bitflip()
	val = load_16(data, func_state[0])

	if func_state[2] == False:
		val += func_state[1]
	else:
		val -= func_state[1]

	store_16(data, func_state[0], val)

	func_state[1] += 1

	return data, func_state


def mutate_4bytes_arithmetic(data, func_state):
	data_len = len(data)
	if data_len < 4:
		return data, None

	if not func_state:
		func_state = [0, 0, False]

	if func_state[1] > AFL_ARITH_MAX:
		func_state[0] += 1
		func_state[1] = 0

	if func_state[0] + 3 >= len(data):
		if func_state[2] == False:
			func_state = [0, 0, True]
		else:
			return data, None

	# TODO: we have to check for could_be_bitflip()
	val = load_32(data, func_state[0])

	if func_state[2] == False:
		val += func_state[1]
	else:
		val -= func_state[1]

	store_32(data, func_state[0], val)

	func_state[1] += 1

	return data, func_state


# TODO: implement is_not_bitflip and is_not_arithmetic
def mutate_1byte_interesting(data, func_state):
	if not func_state:
		func_state = [0, 0]

	if func_state[1] >= len(interesting_8_Bit):
		func_state[0] += 1
		func_state[1] = 0

	if func_state[0] >= len(data):
		return data, None

	interesting_value = interesting_8_Bit[func_state[1]]

	data[func_state[0]] = in_range_8(interesting_value)

	func_state[1] += 1

	return data, func_state


# TODO: implement is_not_bitflip and is_not_arithmetic
def mutate_2bytes_interesting(data, func_state):
	data_len = len(data)
	if data_len < 2:
		return data, None

	if not func_state:
		func_state = [0, 0, False]

	if func_state[1] >= len(interesting_16_Bit):
		func_state[0] += 1
		func_state[1] = 0

	if func_state[0] + 1 >= data_len:
		if func_state[2] == False:
			func_state = [0, 0, True]
		else:
			return data, None

	interesting_value = in_range_16(interesting_16_Bit[func_state[1]])

	if func_state[2]:
		interesting_value = swap_16(interesting_value)

	store_16(data, func_state[0], interesting_value)

	func_state[1] += 1

	return data, func_state


# TODO: implement is_not_bitflip and is_not_arithmetic
def mutate_4bytes_interesting(data, func_state):
	data_len = len(data)
	if data_len < 4:
		return data, None

	if not func_state:
		func_state = [0, 0, False]

	if func_state[1] >= len(interesting_32_Bit):
		func_state[0] += 1
		func_state[1] = 0

	if func_state[0] + 3 >= data_len:
		if func_state[2] == False:
			func_state = [0, 0, True]
		else:
			return data, None

	interesting_value = in_range_32(interesting_32_Bit[func_state[1]])

	if func_state[2]:
		interesting_value = swap_32(interesting_value)

	store_32(data, func_state[0], interesting_value)

	func_state[1] += 1

	return data, func_state


#TODO: auto-create dictionary from binary
#TODO: afl has this also https://github.com/mirrorer/afl/blob/2fb5a3482ec27b593c57258baae7089ebdc89043/afl-fuzz.c#L5123
def dictionary_overwrite(data, func_state):
	global tokens_list, tokens_list_length
	if tokens_list_length <= 0:
		return data, None

	if not func_state:
		func_state = [0, 0] # first is an index in tokens_list, second is an index in data

	data_len = len(data)
	token = tokens_list[func_state[0]]
	place = func_state[1]

	if data_len < len(token):
		return data, None

	if place >= data_len - len(token):
		func_state[0] += 1 # take the next token
		func_state[1] = 0

		if func_state[0] >= len(tokens_list):
			return data, None

	data = data[:place] + bytearray(token) + data[place + len(token):]
	func_state[1] += 1

	return data, func_state


def dictionary_insert(data, func_state):
	global tokens_list, tokens_list_length
	if tokens_list_length <= 0:
		return data, None

	if not func_state:
		func_state = [0, 0] # first is an index in tokens_list, second is an index in data

	data_len = len(data)

	token = tokens_list[func_state[0]]
	place = func_state[1]

	if place >= data_len:
		func_state[0] += 1 # take the next token
		func_state[1] = 0

		if func_state[0] >= len(tokens_list):
			return data, None

	data = data[:place] + bytearray(token) + data[place:]
	func_state[1] += 1

	return data, func_state


def havoc_bitflip(data):
	value_to_flip = RAND(len(data) * 8)
	data, res = bitflip_1bit(data, value_to_flip)
	return data


def havoc_interesting_byte(data):
	value_to_change = RAND(len(data))
	interesting_value_index = RAND(len(interesting_8_Bit))

	func_state = [value_to_change, interesting_value_index]
	data, state = mutate_1byte_interesting(data, func_state)
	return data


def havoc_interesting_2bytes(data):
	data_len = len(data)
	if data_len < 2:
		return data
	value_to_change = RAND(data_len - 1) # substract 1 to make sure we have space for 2 bytes
	interesting_value_index = RAND(len(interesting_16_Bit))
	swap = RAND(2) # is swap?

	func_state = [value_to_change, interesting_value_index, swap]
	data, state = mutate_2bytes_interesting(data, func_state)
	return data


def havoc_interesting_4bytes(data):
	data_len = len(data)
	if data_len < 4:
		return data
	value_to_change = RAND(len(data) - 3) # substract 1 to make sure we have space for 2 bytes
	interesting_value_index = RAND(len(interesting_32_Bit))
	swap = RAND(2) # is swap?

	func_state = [value_to_change, interesting_value_index, swap]
	data, state = mutate_4bytes_interesting(data, func_state)
	return data


def havoc_randomly_add(data): # similar to mutate_byte_arithmetic but a bit faster
	value_to_change = RAND(len(data))
	data[value_to_change] = in_range_8(data[value_to_change] + 1 + RAND(AFL_ARITH_MAX))
	return data


def havoc_randomly_substract(data): # similar to mutate_byte_arithmetic but a bit faster
	value_to_change = RAND(len(data))
	data[value_to_change] = in_range_8(data[value_to_change] - (1 + RAND(AFL_ARITH_MAX)))
	return data


def havoc_randomly_add_2bytes(data): # similar to mutate_byte_arithmetic but a bit faster
	data_len = len(data)
	if data_len < 2:
		return data
	func_state = [RAND(data_len - 1), RAND(AFL_ARITH_MAX), True] # pos, value, is_sub
	data, func_state = mutate_2bytes_arithmetic(data, func_state)
	return data


def havoc_randomly_substract_2bytes(data): # similar to mutate_byte_arithmetic but a bit faster
	data_len = len(data)
	if data_len < 2:
		return data
	func_state = [RAND(data_len - 1), RAND(AFL_ARITH_MAX), False] # pos, value, is_sub
	data, func_state = mutate_2bytes_arithmetic(data, func_state)
	return data


def havoc_randomly_add_4bytes(data): # similar to mutate_byte_arithmetic but a bit faster
	data_len = len(data)
	if data_len < 4:
		return data
	func_state = [RAND(data_len - 3), RAND(AFL_ARITH_MAX), True] # pos, value, is_sub
	data, func_state = mutate_4bytes_arithmetic(data, func_state)
	return data


def havoc_randomly_substract_4bytes(data): # similar to mutate_byte_arithmetic but a bit faster
	data_len = len(data)
	if data_len < 4:
		return data
	func_state = [RAND(data_len - 3), RAND(AFL_ARITH_MAX), False] # pos, value, is_sub
	data, func_state = mutate_4bytes_arithmetic(data, func_state)
	return data


def havoc_set_randomly(data):
	pos = RAND(len(data))
	data[pos] = in_range_8(data[pos] ^ (1 + RAND(255)));
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


# overwrite from dict
def havoc_overwrite_with_dict(data):
	func_state = [RAND(len(tokens_list)), RAND(len(data))]
	data, func_state = dictionary_overwrite(data, func_state)
	return data


# overwrite from dict
def havoc_insert_with_dict(data):
	func_state = [RAND(len(tokens_list)), RAND(len(data))]
	data, func_state = dictionary_insert(data, func_state)
	return data