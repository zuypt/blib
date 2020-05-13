from ctypes.wintypes import *
from ctypes import *

util = CDLL('winafl_util_cli.dll')
setup_pipe = util.setup_pipe
setup_pipe.argtypes = (LPCSTR, )
setup_pipe.restype = BOOL

t = c_char_p(bytes('\\\\.\\pipe\\afl_pipe_'+'f1', 'ansi'))

setup_pipe(t)