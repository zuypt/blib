/*
what doesn't work ?
- we have to wait for coverage modules to all be loaded before starting stalker
- this broke when EScript.api is the coverage module
- only get coverage of the main thread
- known crash when EnterCriticalSection is called

what works ?

*/

Process.setExceptionHandler(
	function (details) {
		//send(MSG_CRASH)
		console.log(JSON.stringify(details))
	}
);

const MSG_DEBUG 		= '\x01'
const MSG_INITDONE 		= '\x02'
const MSG_COVLEN 		= '\x03'
const MSG_CRASH			= '\x04'

function stringify(o) {
	return JSON.stringify(o)
}

function debug(msg) {
	console.log('DEBUG:cov.js:' + msg)
}

var OPTIONS = null
const MAX_NMODULE				= 32
/* we handle 64bit later */

var COVERAGE_MODULE_STARTS 		= []
var COVERAGE_MODULE_ENDS 		= []
var COVERAGES 					= []
//var COVLENS 				= []
var COVLEN 					= 0
/* 10MB for now */
const COV_MAX_SZ 			= 1024*1024*10

var number_cov_module_loaded = 0
var cov_module_names = null
//all of these are async, can run at the same time with putCallout
rpc.exports = {
	init: function(options) {
		OPTIONS = options
		cov_module_names = OPTIONS['cov_module_names']
		debug(cov_module_names.length)
		Process.enumerateModules({
			onMatch: function(module) {
				var module_name = module.name
				for(var i=0; i<cov_module_names.length; i++) {
					if (module_name.toLowerCase().endsWith(cov_module_names[i].toLowerCase())) {
						number_cov_module_loaded += 1
						COVERAGE_MODULE_STARTS[i] 		= module.base
						COVERAGE_MODULE_ENDS[i] 		= COVERAGE_MODULE_STARTS[i].add(module.size)
						//COVERAGES[i]					= new Uint8Array(COV_MAX_SZ)
						COVERAGES[i]					= {}

						/* Only initStalker when every cov_module is loaded */
						if (number_cov_module_loaded == cov_module_names.length) {
							//initStalker()
							//;
						}
					}
				}
			},
			onComplete: function() {}
		})
	},
	getOptions: function() {
		return OPTIONS
	},
	getModules: function() {
		var modules = []
		Process.enumerateModules({
			onMatch: function(module) {
				modules.push(module)
			},
			onComplete: function() {}
		})
		return modules
	},
	getCov: function() {
		return COVERAGES
	},
	getCovlen: function() {
		return COVLEN
	},
	getCrash: function() {
		return CRASH_DETAIL;
	},
	initStalker: function() {
		initStalker()
	}
}

function initStalker() {
	debug('initStalker')
	debug(Process.pointerSize)
	Stalker.trustThreshold = 0;
	const main_thread = Process.enumerateThreads()[0]
	Stalker.follow(main_thread.id, {
		transform: function(iterator) {
			/*
			var ins = iterator.next()
			if (ins == null) return	
			debug('???')
			for(var i=0; i<cov_module_names.length; i++) {
				debug(COVERAGE_MODULE_STARTS[i].toString(16))
				debug(COVERAGE_MODULE_ENDS[i].toString(16))
				debug(ins.address)
				debug('===')
				if ( (ins.address>=COVERAGE_MODULE_STARTS[i]) && (ins.address<=COVERAGE_MODULE_ENDS[i]) ) {
					debug('!!!')
					if (!OPTIONS.hasOwnProperty('target_module_name')) {
						iterator.putCallout(collect_everything);
					} else {
						iterator.putCallout(selective_collecting)
					}
					
					break;
				}
			}
			debug('###')
			while (1) {
				iterator.keep()
				if (iterator.next() == null) break
			}
			debug('^^^')
			*/
		while (iterator.next() !== null) iterator.keep();
		debug('test')
		}
	})
}


