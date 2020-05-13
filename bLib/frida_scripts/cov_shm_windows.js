/*
TODO: MAKE this compatible with Winafl

what doesn't work
- frida can't catch crash (exception) inside CModule
*/

function stringify(o) {
	return JSON.stringify(o)
}

var DEBUG = true;
var printf = new NativeFunction(Module.getExportByName(null, 'printf'), 'uint32', ['pointer'])

function debug(msg)
{
	if (DEBUG) 
	{
		var mem = Memory.allocAnsiString('[cov_shm_windows]: ' + msg + '\n')
		printf(mem)
	}
}

function info(msg)
{
	var mem = Memory.allocAnsiString('[cov_shm_windows]: ' + msg + '\n')
	printf(mem)
}

function basename(path)
{
	var idx = path.lastIndexOf('\\')
	if (idx == -1) return path
	else return path.slice(idx+1)
}

var OPTIONS = null
var SHM = null
var SHM_SZ = null

var MAIN_THREAD = null
var EXITING = false;
//CModule
var CM = null
var COLLECTING = Memory.alloc(4)
COLLECTING.writeU32(0)
var disableCollecting = null
var enableCollecting = null

var BLK_MAP = null
var BLK_ID_COUNTER = 0

var setup_pipe = null
var ReadCommandFromPipe = null
var WriteCommandToPipe = null

var ExitProcess = new NativeFunction(Module.getExportByName(null, 'ExitProcess'), 'void', ['uint16'])

var COV_MODULE_STARTS = []
var COV_MODULE_ENDS   = []

rpc.exports = {
	init: function(options)
	{
		OPTIONS = options
		//debug(stringify(OPTIONS))

		SHM_SZ = OPTIONS['shm_sz']
		SHM = setup_shm_win(OPTIONS['shm_name'], SHM_SZ)
		BLK_MAP = new NativePointer(setup_shm_win(OPTIONS['shm_name'] + '_MAP', SHM_SZ*4))

		CM = setup_CModule()
		
		Process.enumerateModulesSync(
		{
			onMatch: function(module)
			{
				var target_module = OPTIONS['target_module'].toLowerCase()
				var module_name = module.name.toLowerCase()
				var cov_modules = OPTIONS['cov_modules']

				if (module_name.endsWith(target_module))
				{
					cov_handler_setup(module)	
				}

				for (var i=0; i<cov_modules.length; i++)
				{
					var cov_module = cov_modules[i].toLowerCase()
					if (module_name.endsWith(cov_module))
					{
						COV_MODULE_STARTS[i] = module.base
						COV_MODULE_ENDS[i] = COV_MODULE_STARTS[i].add(module.size)
					}
				}
			},
			onComplete: function(){}
		})

		var exit_point = Module.getExportByName('ntdll', 'RtlExitUserProcess')
		debug('exit_point: ' + exit_point)
		Interceptor.attach(exit_point, {
			onEnter: function()
			{
				EXITING = true;
				// debug('unfollow: ' + MAIN_THREAD);
				// Stalker.unfollow(MAIN_THREAD)
			},
			onLeave: function()
			{

			}
		})
		LoadLibEvent_setup();
		initStalker()
	},
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

function LoadLibEvent_setup() {
	var LoadLibraryExW 	= Module.getExportByName('KERNELBASE', 'LoadLibraryExW')
	Interceptor.attach(LoadLibraryExW, {
		onEnter: function (args)
		{
			this.module_name = basename(args[0].readUtf16String())
			//debug('LoadLibraryExW(' + this.module_name + ')')
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
					LoadLibEvent(module)
				}
				else
				{
					debug('we should not be here')
				}	
			}
		}
	});
}

function LoadLibEvent(module) {
	var module_name = module.name.toLowerCase()
	var cov_modules = OPTIONS['cov_modules']

	for (var i=0; i<cov_modules.length; i++)
	{
		var cov_module = cov_modules[i].toLowerCase()
		if (module_name.endsWith(cov_module))
		{
			COV_MODULE_STARTS[i] = module.base
			COV_MODULE_ENDS[i] = COV_MODULE_STARTS[i].add(module.size)
			//debug(cov_module + '_base: ' + COV_MODULE_STARTS)
			//debug(cov_module + '_end: ' + COV_MODULE_ENDS)
		}
	}

	var target_module = OPTIONS['target_module'].toLowerCase()
	if (module_name.endsWith(target_module))
	{
		cov_handler_setup(module)
	}
}

function initStalker()
{
	debug('initStalker')
	Stalker.trustThreshold = 0;
	MAIN_THREAD = Process.enumerateThreads()[0]
	debug('stalker follow: ' + MAIN_THREAD.id)
	Stalker.follow(MAIN_THREAD.id,
	{
		transform: function(iterator)
		{
			if (!EXITING) {
				var ins = iterator.next()
				if (ins == null) return
				//debug('bb at ' + ins.address)
				for(var i=0; i<COV_MODULE_STARTS.length; i++)
				{
					var cov_module_start = COV_MODULE_STARTS[i]
					var cov_module_end = COV_MODULE_ENDS[i]
					if (ins.address.compare(cov_module_start)>=0 && ins.address.compare(cov_module_end)===-1)
					{
						var blk_addr = ins.address.sub(cov_module_start)

						//debug('instrumenting: ' + blk_addr)

						BLK_MAP.add(BLK_ID_COUNTER*4).writeU32(blk_addr.toUInt32())
						/*
						TODO: call instruction is exensive ?. replace with an inline function
						*/
						iterator.putCallout(CM.bb_cov, new NativePointer(BLK_ID_COUNTER))
						BLK_ID_COUNTER += 1

						if (BLK_ID_COUNTER > SHM_SZ)
						{
							info('Increase map sz')
							ExitProcess()
						}
						//debug('instrument bb at ' + blk_addr)
					}
				}
				iterator.keep()
			}
			while (iterator.next() != null) iterator.keep();
		}
	})
}

function cov_handler_setup(module)
{
	debug('cov_handler_setup')
	// debug('target_offset: ' + OPTIONS['target_offset'])
	// debug('module_name: ' + module.name)
	Interceptor.attach(module.base.add(OPTIONS['target_offset']),
	{
		onEnter: function()
		{
			//debug('cov_handler>')
			enableCollecting();
		},
		onLeave: function()
		{
			disableCollecting()
			//debug('<cov_handler')
		},	
	})
}

function setup_CModule()
{
	// I want to kill myself for this piece of code
	var source = "#include <stdint.h>\n\
	#include <stdio.h>\n\
	#define SHM_SZ YYY\n\
	uint32_t *COLLECTING = (uint32_t*)ZZZ;\
	void on() {\
		*COLLECTING = 1;\
	}\
	void off() {\
		*COLLECTING = 0;\
	}\
	void bb_cov(void *foo, uint64_t blk_id)\n\
	{\
		if (*COLLECTING==1) {\
			uint8_t *shm = (uint8_t*)XXX;\
			if (shm[blk_id] != 0xff)\
			{\
				shm[blk_id] += 1;\
			}\
		}\
	}".replace('XXX', SHM.toString()).replace('YYY', SHM_SZ.toString()).replace('ZZZ', COLLECTING.toString());
	//debug(source)
	var cm = new CModule(source);
	disableCollecting = new NativeFunction(cm.off, 'void', [])
	enableCollecting = new NativeFunction(cm.on, 'void', [])
	debug('disableCollecting: ' + cm.off)
	debug('enableCollecting: ' + cm.on)
	return cm;
}
