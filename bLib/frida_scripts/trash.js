/*
TODO: MAKE this compatible with Winafl

what doesn't work
- frida can't catch crash (exception) inside CModule
*/

		Process.enumerateModulesSync({
			onMatch: function(module) {
				var cov_module = OPTIONS['cov_module']
				var module_name = module.name
				if (module_name.toLowerCase().endsWith(cov_module.toLowerCase())) {
					COV_MODULE_START = module.base
					COV_MODULE_END = COV_MODULE_START.add(module.size)
					debug('COV_MODULE_START: ' + COV_MODULE_START)
					debug('COV_MODULE_END: ' + COV_MODULE_END)
					SHOULD_START_STALKER = true;
				} else {
					//Stalker.exclude(module)
				}
			},
			onComplete: function(){}
		})
		if (SHOULD_START_STALKER) {
			STALKER_LOADED = true;
			initStalker();
		}

function stringify(o) {
	return JSON.stringify(o)
}

function debug(msg) {
	console.log('DEBUG:cov_shm_windows.js:' + msg)
}

var OPTIONS = null
var SHM = null
var SHM_SZ = null

//CModule
var CM = null
var COLLECTING = Memory.alloc(4)
COLLECTING.writeU32(0)
var disableCollecting = null
var enableCollecting = null

var setup_pipe = null
var ReadCommandFromPipe = null
var WriteCommandToPipe = null

var ExitProcess = new NativeFunction(Module.getExportByName(null, 'ExitProcess'), 'void', ['uint16'])

rpc.exports = {
	init: function(options) {
		OPTIONS = options
		debug(stringify(OPTIONS))

		SHM_SZ = OPTIONS['shm_sz']
		SHM = setup_shm_win()
		CM = setup_CModule()

		Module.load('winafl_util_cli.dll')
		setup_pipe 					= new NativeFunction(Module.getExportByName('winafl_util_cli', 'setup_pipe'), 'void', ['pointer'])
		ReadCommandFromPipe 		= new NativeFunction(Module.getExportByName('winafl_util_cli', 'ReadCommandFromPipe'), 'char', [])
		WriteCommandToPipe 			= new NativeFunction(Module.getExportByName('winafl_util_cli', 'WriteCommandToPipe'), void, ['char'])
		
		var pipe_name = Memory.allocAnsiString('\\\\.\\pipe\\afl_pipe_%s' + OPTIONS['fuzzer_id'])
		setup_pipe(pipe_name)
		
		LoadLibEvent_setup();
	}
}

function setup_shm_win() {
	const FILE_MAP_ALL_ACCESS = 0xF001F
	const PAGE_READWRITE = 0x04

	var OpenFileMapping = Module.findExportByName(null, 'OpenFileMappingA')
	var OpenFileMappingFn = new NativeFunction(OpenFileMapping, 'uint32', ['uint32', 'bool', 'pointer'])
	var MapViewOfFile = Module.findExportByName(null, 'MapViewOfFile')
	var MapViewOfFileFn = new NativeFunction(MapViewOfFile, 'pointer', ['uint', 'uint', 'uint', 'uint', 'uint'])
	var hMap = OpenFileMappingFn(FILE_MAP_ALL_ACCESS, 0, Memory.allocAnsiString(OPTIONS['shm_name']))
	return MapViewOfFileFn(hMap, FILE_MAP_ALL_ACCESS, 0, 0, SHM_SZ)
}

function LoadLibEvent_setup() {
	var LoadLibraryA 	= Module.getExportByName(null, 'LoadLibraryA')
	var LoadLibraryW 	= Module.getExportByName(null, 'LoadLibraryW')
	var LoadLibraryExA 	= Module.getExportByName(null, 'LoadLibraryExA')
	var LoadLibraryExW 	= Module.getExportByName(null, 'LoadLibraryExW')

	Interceptor.attach(LoadLibraryExW, {
		onEnter: function (args) {
			this.module_name = args[0].readUtf16String()
		},
		onLeave: function (retval) {
			var module = Process.findModuleByAddress(retval)
			if (module) LoadLibEvent(module)
		}
	});

	Interceptor.attach(LoadLibraryExA, {
		onEnter: function (args) {
			this.module_name = args[0].readCString()
		},
		onLeave: function (retval) {
			var module = Process.findModuleByAddress(retval)
			if (module) LoadLibEvent(module)
		}
	});

	Interceptor.attach(LoadLibraryA, {
		onEnter: function (args) {
			this.module_name = args[0].readCString()
		},
		onLeave: function (retval) {
			var module = Process.findModuleByAddress(retval)
			if (module) LoadLibEvent(module)
		}
	});

	Interceptor.attach(LoadLibraryW, {
		onEnter: function (args) {
			this.module_name = args[0].readUtf16String()
		},
		onLeave: function (retval) {
			var module = Process.findModuleByAddress(retval)
			if (module) LoadLibEvent(module)
		}
	});
}

function initStalker() {
	debug('initStalker')
	Stalker.trustThreshold = 0;
	Stalker.queueDrainInterval = 0
	const main_thread = Process.enumerateThreads()[0]
	Stalker.follow(main_thread.id, {
		transform: function(iterator) {
			var ins = iterator.next()
			if (ins == null) return
			for(var i=0; i<COVERAGE_MODULE_STARTS.length; i++) {
				if ( (ins.address>=COVERAGE_MODULE_STARTS[i]) && (ins.address<=COVERAGE_MODULE_ENDS[i]) ) {
					var blk_addr = ins.address.sub(COVERAGE_MODULE_STARTS[i])
					iterator.putCallout(CM.bb_cov, blk_addr)
					break;
				}
			}
			iterator.keep()
			while (iterator.next() != null) iterator.keep();
		}
	})
}

//var zzz = 0
function fuzz_handler_setup(module) {
	debug('fuzz_handler_setup')
	Interceptor.attach(module.base.add(OPTIONS['target_offset']), {
		//pre_fuzz_handler
		onEnter: function() {
			WriteCommandToPipe('P');
			var cmd = ReadCommandFromPipe()
			if (cmd != 'F') {
				if (cmd == 'Q') {
					ExitProcess()
				}
			}
			debug('e>')
			enableCollecting();
		},
		//post_fuzz_handler
		onLeave: function() {
			WriteCommandToPipe('K')
			disableCollecting()
			debug('<e\n')
			//debug(performance.now() - zzz)
		},	
	})
}

const MAX_NMODULE				= 32
/* we handle 64bit later */
var COVERAGE_MODULE_STARTS 		= new Uint32Array(MAX_NMODULE)
var COVERAGE_MODULE_ENDS 		= new Uint32Array(MAX_NMODULE)
var number_cov_module_loaded = 0
function LoadLibEvent(module) {
	var module_name = module.name
	var cov_module_names = OPTIONS['cov_module_names']
	for(var i=0; i<cov_module_names.length; i++) {
		if (module_name.toLowerCase().endsWith(cov_module_names[i].toLowerCase())) {
			number_cov_module_loaded += 1
			COVERAGE_MODULE_STARTS[i] 		= module.base
			COVERAGE_MODULE_ENDS[i] 		= COVERAGE_MODULE_STARTS[i] + module.size

			/* Only initStalker when every cov_module is loaded */
			if (number_cov_module_loaded == cov_module_names.length) {
				initStalker()
			}
		}
	}

	if (OPTIONS.hasOwnProperty('target_module_name')) {
		var target_module_name = OPTIONS['target_module_name']
		if (module_name.toLowerCase().endsWith(target_module_name.toLowerCase())) {
			fuzz_handler_setup(module)
		}
	}
}

function setup_CModule() {
	// I want to kill myself for this piece of code
	var source = "#include <gum/gumstalker.h>\n\
	#include <stdio.h>\n\
	#define SHM_SZ YYY\n\
	uint32_t *COLLECTING = (uint32_t*)ZZZ;\
	void on() {\
		*COLLECTING = 1;\
	}\
	void off() {\
		*COLLECTING = 0;\
	}\
	void bb_cov(void *foo, uint32_t addr)\n\
	{\
		if (*COLLECTING==1) {\
			uint32_t *cov_len = (uint32_t*)XXX;\
			uint8_t *shm = (uint8_t*)cov_len+4;\
			if (shm[addr] == 0) {\
				shm[addr] = 1;\
				*cov_len += 1;\
			}\
		}\
	}".replace('XXX', '0x' + SHM.toUInt32().toString(16)).replace('YYY', SHM_SZ.toString()).replace('ZZZ', '0x'+COLLECTING.toUInt32().toString(16));
	//debug(source)
	var cm = new CModule(source);
	disableCollecting = new NativeFunction(cm.off, 'void', [])
	enableCollecting = new NativeFunction(cm.on, 'void', [])
	return cm;
}

var CRASH_DETAIL = null
var EXCEPTION_WHITELIST = {
	'abort': true,
	'access-violation': true,
	'guard-page': true,
	'illegal-instruction': true,
	'stack-overflow': true,
	'arithmetic': true,
	'breakpoint': true
}
Process.setExceptionHandler(
	function (details) {
		if (EXCEPTION_WHITELIST.hasOwnProperty(details.type)) {
			CRASH_DETAIL = details
		}
	}
);

	// Interceptor.attach(LoadLibraryExW, {
	// 	onEnter: function (args) {
	// 		this.module_name = args[0].readUtf16String()
	// 	},
	// 	onLeave: function (retval) {
	// 		var module = Process.findModuleByAddress(retval)
	// 		if (module) LoadLibEvent(module)
	// 	}
	// });

	// Interceptor.attach(LoadLibraryExA, {
	// 	onEnter: function (args) {
	// 		this.module_name = args[0].readCString()
	// 	},
	// 	onLeave: function (retval) {
	// 		var module = Process.findModuleByAddress(retval)
	// 		if (module) LoadLibEvent(module)
	// 	}
	// });

	// Interceptor.attach(LoadLibraryA, {
	// 	onEnter: function (args) {
	// 		this.module_name = args[0].readCString()
	// 	},
	// 	onLeave: function (retval) {
	// 		var module = Process.findModuleByAddress(retval)
	// 		if (module) LoadLibEvent(module)
	// 	}
	// });

	// Interceptor.attach(LoadLibraryW, {
	// 	onEnter: function (args) {
	// 		this.module_name = args[0].readUtf16String()
	// 	},
	// 	onLeave: function (retval) {
	// 		var module = Process.findModuleByAddress(retval)
	// 		if (module) LoadLibEvent(module)
	// 	}
	// });