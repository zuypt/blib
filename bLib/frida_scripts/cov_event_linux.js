function stringify(o) {return JSON.stringify(o)}

rpc.exports = {
	getcov: function() {
		send(COVERAGE)
	},
	getlength: function() {
		send(COVERAGE_LENGTH)
	},
	initStalker: function() {
		initStalker()
	}
}

var COVERAGE_MODULE_NAME  = 'AdobeXMP.dll'
var COVERAGE_MODULE_START = null
var COVERAGE_MODULE_END = null

var TARGET_MODULE_NAME = 'EScript.api'
var TARGET_OFFSET = 0xa8020

var COLLECT_COVERAGE = false

var COVERAGE = {}
var COVERAGE_LENGTH = 0

function LoadLibEvent_setup() {
	var dlopen 	= Module.getExportByName(null, 'dlopen')


	Interceptor.attach(dlopen, {
		onEnter: function (args) {
			this.module_name = args[0].readUtf16String()
		},
		onLeave: function (retval) {
			var module = Process.findModuleByAddress(retval)
			if (module) LoadLibEvent(module)
		}
	});
}

function LoadLibEvent(module) {
	var module_name = module.name
	if (module_name.toLowerCase().endsWith(COVERAGE_MODULE_NAME.toLowerCase())) {
		COVERAGE_MODULE_START = module.base
		COVERAGE_MODULE_END = COVERAGE_MODULE_START.add(module.size)
		console.log(COVERAGE_MODULE_NAME)
		initStalker()
	}

	if (module_name.toLowerCase().endsWith(TARGET_MODULE_NAME.toLowerCase())) {
		setInputHook(module)
		setTargetHook(module)
	}
}

function setInputHook(module) {
	console.log('setInputHook')
	Interceptor.attach(module.base.add(0xd9ca0), {
		onEnter: function () {
			send('')
			var r = recv('input', function(data) {
				//console.log(data.payload)
				INPUT.writeAnsiString('\x00'.repeat(data.payload.length+32))
				INPUT.writeAnsiString(data.payload)
			})
			r.wait()
			this.context.eax = INPUT.toUInt32()
		}
	})
}

function setTargetHook(module) {
	console.log('setTargetHook')
	Interceptor.attach(module.base.add(TARGET_OFFSET), {
		onEnter: function (args) {
			Stalker.flush()
			COLLECT_COVERAGE = true
		},
		onLeave: function (retval) {
			Stalker.flush()
			COLLECT_COVERAGE = false
			send(COVERAGE_LENGTH)
			
		}
	})
}

function initStalker() {
	console.log('initStalker')
	//Stalker.trustThreshold = 0;
	//Stalker.queueDrainInterval = 0
	const main_thread = Process.enumerateThreads()[0]
	Stalker.follow(main_thread.id, {events: {block: true},
		onReceive: bb_hit
	})
	console.log('Stalker started')
}

var EV_TYPE_BLOCK = 8;
var intSize = Process.pointerSize;
var EV_STRUCT_SIZE = 2 * Process.pointerSize + 2 * intSize;

function parseBlockEvent(blob, idx) {
	var begin = parsePointer(blob, idx, intSize);
	return begin
}

function parseInteger(blob, idx, offset) {
	return new Int32Array(blob, idx * EV_STRUCT_SIZE + offset, 1)[0];
}

function parsePointer(blob, idx, offset) {
	var view = new Uint8Array(blob, idx * EV_STRUCT_SIZE + offset, Process.pointerSize);
	var stringed = [];
	for (var i = 0; i < Process.pointerSize; i++) {
		var x = view[i];
		var conv = x.toString(16);
		if (conv.length === 1) {
			conv = '0' + conv;
		}
		stringed.push(conv);
	}
	return ptr('0x' + stringed.reverse().join(''));
}

function getType(blob, idx) {
	return parseInteger(blob, idx, 0);
}

function getLen(blob) {
	return blob.byteLength / EV_STRUCT_SIZE;
}

function parseEvents(blob, callback) {
	var len = getLen(blob);
	for (var i = 0; i !== len; i++) {
		var type = getType(blob, i);
		if (type != EV_TYPE_BLOCK) {
			console.log('error event type: ' + type)
		}
		callback(parseBlockEvent(blob, i));
	}
}

function bb_hit(raw_events) {
	return
	parseEvents(raw_events, function(begin) {})
	// 		if (begin>=COVERAGE_MODULE_START  && begin<=COVERAGE_MODULE_END) {
	// 			begin = begin.sub(COVERAGE_MODULE_START)
	// 			if (!COVERAGE.hasOwnProperty(begin)) {
	// 				COVERAGE[begin] = true
	// 				COVERAGE_LENGTH += 1
	// 			}
	// 		}
	// 	});
	// }
}

