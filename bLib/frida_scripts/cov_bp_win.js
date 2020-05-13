function stringify(o) {
	return JSON.stringify(o)
}

var DEBUG = true;
var printf = new NativeFunction(Module.getExportByName(null, 'printf'), 'uint32', ['pointer'])

function debug(msg)
{
	if (DEBUG) 
	{
		var mem = Memory.allocAnsiString('[bCov_bp]: ' + msg + '\n')
		printf(mem)
	}
}

function info(msg)
{
	var mem = Memory.allocAnsiString('[cov_shm_windows]: ' + msg + '\n')
	printf(mem)
}

function baseName(path)
{
	var idx = path.lastIndexOf('\\')
	if (idx == -1) return path
	else return path.slice(idx+1)
}

function strcmpi(s1, s2) {
	return s1.toLowerCase() == s2.toLowerCase()
}

function endsWithi(s, e) {
	return s.toLowerCase().endsWith(e.toLowerCase())
}

function setup_shm_win(name, sz)
{
	const FILE_MAP_ALL_ACCESS = 0xF001F
	const PAGE_READWRITE = 0x04

	var OpenFileMapping = Module.findExportByName(null, 'OpenFileMappingA')
	var OpenFileMappingFn = new NativeFunction(OpenFileMapping, 'uint32', ['uint32', 'bool', 'pointer'])
	var MapViewOfFile = Module.findExportByName(null, 'MapViewOfFile')
	var MapViewOfFileFn = new NativeFunction(MapViewOfFile, 'pointer', ['uint', 'uint', 'uint', 'uint', 'uint'])
	var hMap = OpenFileMappingFn(FILE_MAP_ALL_ACCESS, 0, Memory.allocAnsiString(name))
	return MapViewOfFileFn(hMap, FILE_MAP_ALL_ACCESS, 0, 0, sz)
}

var OPTIONS = null
var MAIN_THREAD = null
var EXITING = false;

var BLK_MAP = null
var BLK_ID_COUNTER = 0

var ExitProcess = new NativeFunction(Module.getExportByName(null, 'ExitProcess'), 'void', ['int32'])
var GetLastError = new NativeFunction(Module.getExportByName(null, 'GetLastError'), 'void', ['uint32'])

var COV_MODULE_STARTS = []
var COV_MODULE_ENDS   = []

var BB_COUNT = null

rpc.exports = {
	init: function(options)
	{
		OPTIONS = options

		BB_COUNT = new NativePointer(setup_shm_win(OPTIONS['shm_name'], 4))
		BB_COUNT.writeU32(0)

		Process.enumerateModulesSync(
		{
			onMatch: function(module)
			{
				var cov_modules = OPTIONS['cov_modules']

				for (var i=0; i<cov_modules.length; i++)
				{
					var module_name = module.name
					var cov_module = cov_modules[i]
					if (endsWithi(cov_module, module_name))
					{
						addBreakpoint(module)
					}
				}
			},
			onComplete: function(){}
		})

		var exit_point = Module.getExportByName('ntdll', 'RtlExitUserProcess')
		Interceptor.attach(exit_point, {
			onEnter: function()
			{
				EXITING = true;
			},
			onLeave: function(){}
		})
		loadLibraryHook();
	}
}

var LOADED_MODULES = {}
function loadLibraryHook() {
	var LoadLibraryExW 	= Module.getExportByName('KERNELBASE', 'LoadLibraryExW')
	Interceptor.attach(LoadLibraryExW, {
		onEnter: function (args)
		{
			this.module_name = baseName(args[0].readUtf16String())
		},
		onLeave: function (retval)
		{
			if (retval)
			{
				try
				{
					var module = Process.getModuleByAddress(retval)	
				} catch (err) {}
				if (module)
				{
					//debug(module.name + ' ' + module.base)
					if (LOADED_MODULES.hasOwnProperty(module.name))
					{

						if (module.base.compare(LOADED_MODULES[module.name].base))
						{
							info('Module reload, ExitProcess ' + module.name)
							ExitProcess(-1)
						}
					}
					else
					{
						LOADED_MODULES[module.name] = module
						loadLibraryEvent(module)
					}
				}
				else
				{
					// weird retval is returned. Could be a frida bug
					;
				}	
			}
		}
	});
}

var VirtualProtect = new NativeFunction (
						Module.getExportByName(null, 'VirtualProtect'),
						['bool'],
						['pointer', 'uint32', 'uint32', 'pointer'],
						{'scheduling': 'exclusive'}
					)
const PAGE_EXECUTE_READWRITE = 0x40
const PAGE_EXECUTE_READ = 0x20
const PAGE_READWRITE = 4
function addBreakpoint(module, idx) 
{
	debug('addBreakpoint ' + module.name)

	var base = module.base
	var module_name = module.name

	var old_protect = Memory.alloc(4)
	var bbs = OPTIONS['bbs'][idx]

	for (var bb in bbs)
	{
		var bb_offset = parseInt(bb)
		//debug(bb_offset.toString(16))
		var target = base.add(bb_offset)
		
		VirtualProtect(target, 1, PAGE_EXECUTE_READWRITE, old_protect)
		target.writeU8(0xcc)
		VirtualProtect(target, 1, PAGE_EXECUTE_READ, old_protect)
	}
	debug('addBreakpoint ' + 'done')
}

function removeBreakpoint(addr, offset, idx)
{
	var key = offset.toUInt32()
	var bbs = OPTIONS['bbs'][idx]

	if (bbs.hasOwnProperty(key)) 
	{
		var bb = bbs[key]
		var old_protect = Memory.alloc(4)
		VirtualProtect(addr, 1, PAGE_EXECUTE_READWRITE, old_protect)
		addr.writeU8(bb['byte'])
		VirtualProtect(addr, 1, PAGE_EXECUTE_READ, old_protect)
		
		var t = BB_COUNT.readU32() + 1
		BB_COUNT.writeU32(t)

		return true;
	}
	return false;
}

function loadLibraryEvent(module) {
	var module_name = module.name.toLowerCase()
	var cov_modules = OPTIONS['cov_modules']

	for (var i = 0; i < cov_modules.length; i++)
	{
		var cov_module = cov_modules[i].toLowerCase()
		if (module_name.endsWith(cov_module))
		{
			addBreakpoint(module, i)
		}
	}
}

Process.setExceptionHandler(
	function (details)
	{		
		if (details.type == 'breakpoint')
		{
			//debug('breakpoint handler')
			var addr = details.address		
			var module = Process.getModuleByAddress(addr)
			if (!module)
			{
				debug('ignore breakpoint')
				return false;
			}
			
			var offset = addr.sub(module.base)
			var module_name = module.name

			//debug(module_name)
			var cov_modules = OPTIONS['cov_modules']

			for (var i = 0; i < cov_modules.length; i++)
			{
				var cov_module = cov_modules[i]
				if (endsWithi(module_name, cov_module))
				{
					return removeBreakpoint(addr, offset, i)
				}
			}
			return false;
		}
	}
);