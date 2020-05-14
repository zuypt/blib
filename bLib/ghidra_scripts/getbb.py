import pickle
from ghidra.program.model.block import BasicBlockModel
from ghidra.program.model.block import SimpleBlockModel
from ghidra.program.model.block import SimpleBlockIterator

from docking.widgets.filechooser import GhidraFileChooser
from ghidra.program.model.address import Address
from ghidra.app.plugin.core.colorizer import ColorizingService
from java.awt import Color

SBM = SimpleBlockModel(currentProgram)
BlockIterator = SimpleBlockIterator(SBM, None)

BLOCK_DICT = {}

MEMORY = currentProgram.getMemory()
SEGMENTS = MEMORY.getBlocks()

def get_text_segment():
	for seg in SEGMENTS:
		if seg.getName() == '.text':
			return (seg.getStart(), seg.getEnd(), seg.getSize())
	raise Exception('cannot find .text segment')

def get_file_offset(addr):
	global SEGMENTS

	for seg in SEGMENTS:
		if seg.contains(addr):
			assert seg.getName() == '.text'
			source_infos = seg.getSourceInfos()
			assert len(source_infos) == 1
			return source_infos[0].getFileBytesOffset(addr)

def addr2int(addr):
	return int(addr.toString(), 16)

while BlockIterator.hasNext():
	blk = BlockIterator.next()
	# print (dir(blk))
	# print (blk.minAddress)
	# print (blk.maxAddress)
	# print (blk.startAddresses)
	BLOCK_DICT[addr2int(blk.minAddress)] = {
		'start': addr2int(blk.minAddress), 
		'end': addr2int(blk.maxAddress),
		'size': blk.maxAddress.subtract(blk.minAddress) + 1,
		'file_offset': get_file_offset(blk.minAddress),
		'byte': getByte(blk.minAddress) & 0xff # yes this function return negative int
	}

fc = GhidraFileChooser(None)
fp = fc.getSelectedFile()

print ('num bb: ', len(BLOCK_DICT))
f = open(repr(fp), 'wb')

start, end, size = get_text_segment()
print start, end, size


BLOCK_INFO = {
	'text_start': addr2int(start),
	'text_end': addr2int(end),
	'text_size': size,
	'block_dict': BLOCK_DICT
}

f.write(pickle.dumps(BLOCK_INFO, protocol=2))
f.close()