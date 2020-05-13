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

BBS = {}

MEMORY = currentProgram.getMemory()
SEGMENTS = MEMORY.getBlocks()

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
	BBS[addr2int(blk.minAddress)] = {
		'start': addr2int(blk.minAddress), 
		'end': addr2int(blk.maxAddress),
		'size': blk.maxAddress.subtract(blk.minAddress) + 1,
		'file_offset': get_file_offset(blk.minAddress),
		'byte': getByte(blk.minAddress) & 0xff # yes this function return negative int
	}

fc = GhidraFileChooser(None)
fp = fc.getSelectedFile()

print ('num bb: ', len(BBS))

f = open(repr(fp), 'wb')
f.write(pickle.dumps(BBS, protocol=2))
f.close()


	