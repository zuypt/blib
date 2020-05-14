/*
TODO: MAKE this compatible with Winafl

what doesn't work
- frida can't catch crash (exception) inside CModule
*/

function ord(s){return s.charCodeAt(0)}
function stringify(o) {return JSON.stringify(o)}

var DEBUG = true;
var printf = new NativeFunction(Module.getExportByName(null, 'printf'), 'uint32', ['pointer'])
function debug(msg)
{
	if (DEBUG)
		//console.log(msg)
		printf(Memory.allocAnsiString('[executor_cli]: ' + msg + '\n'))
}

function basename(path)
{
	var idx = path.lastIndexOf('\\')
	if (idx == -1) return path
	else return path.slice(idx+1)
}

var OPTIONS = null

var setup_pipe = null
var ReadCommandFromPipe = null
var WriteCommandToPipe = null
var MessageBox = null

var ExitProcess = null;
var EXCEPTION_WHITELIST = null
rpc.exports = {
	init: function(options)
	{
		ExitProcess = new NativeFunction(Module.getExportByName(null, 'ExitProcess'), 'void', ['uint16'])
		
		EXCEPTION_WHITELIST = {
			'abort': 1,
			'access-violation': 1,
			'guard-page': 1,
			'illegal-instruction': 1,
			'stack-overflow': 1 
		}


		OPTIONS = options
		//debug(stringify(OPTIONS))
		if (Process.arch == 'x64') Module.load(OPTIONS['libpath64'] + '\\winafl_util_cli.dll')
		else Module.load(OPTIONS['libpath32'] + '\\winafl_util_cli.dll')
		setup_pipe 					= new NativeFunction(Module.getExportByName('winafl_util_cli', 'setup_pipe'), 'bool', ['pointer'])
		ReadCommandFromPipe 		= new NativeFunction(Module.getExportByName('winafl_util_cli', 'ReadCommandFromPipe'), 'char', [])
		WriteCommandToPipe 			= new NativeFunction(Module.getExportByName('winafl_util_cli', 'WriteCommandToPipe'), 'void', ['char'])

		Process.enumerateModulesSync(
		{
			onMatch: function(module)
			{
				var target_module = OPTIONS['target_module'].toLowerCase()
				var module_name = module.name.toLowerCase()
				var cov_modules = OPTIONS['cov_modules']

				if (module_name.endsWith(target_module))
				{
					fuzz_handler_setup(module)	
				}
			},
			onComplete: function(){}
		})

		var pipe_name = Memory.allocAnsiString('\\\\.\\pipe\\' + OPTIONS['pipe_name'])
		if (setup_pipe(pipe_name) == 0)
		{
			debug('connect to pipe failed, exit')
			ExitProcess(0)
		}
		debug('pipe connected')
		setup_crash_handler()
		LoadLibEvent_setup();
	}
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
				var module = Process.getModuleByAddress(retval)
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

function LoadLibEvent(module)
{
	var module_name = module.name.toLowerCase()
	if (OPTIONS.hasOwnProperty('target_module'))
	{
		var target_module = OPTIONS['target_module'].toLowerCase()
		if (module_name.endsWith(target_module))
		{
			fuzz_handler_setup(module)
		}

		if (OPTIONS.hasOwnProperty('inp_sync_module'))
		{
			var inp_sync_module = OPTIONS['inp_sync_module'].toLowerCase()
			if (module_name.endsWith(inp_sync_module))
			{
				inp_sync_setup(module)
			}
		}
	}
}

function inp_sync_setup(module)
{
	//debug('inp_sync_setup')
	Interceptor.attach(module.base.add(OPTIONS['inp_sync_offset']), {
		onEnter: wait_for_inp,
	})
}

function wait_for_inp() 
{
	var cmd = ReadCommandFromPipe()
	if (cmd != ord('I'))
	{
		debug('invalid cmd, expected I, got: ' + cmd)
	}
}

function fuzz_handler_setup(module)
{
	//debug('fuzz_handler_setup')
	Interceptor.attach(module.base.add(OPTIONS['target_offset']), {
		onEnter: pre_fuzz_handler,
		onLeave: post_fuzz_handler
	})
}

function pre_fuzz_handler()
{
	//debug('pre_fuzz_handler>')
	WriteCommandToPipe(ord('P'))
	var cmd = ReadCommandFromPipe()
	if (cmd != ord('F'))
	{
		if (cmd == ord('Q'))
		{
			ExitProcess(0)
		}
		else
		{
			debug('invalid cmd: ' + cmd)
			ExitProcess(0)
		}
	}
}

function post_fuzz_handler()
{
	//debug('post_fuzz_handler>')
	WriteCommandToPipe(ord('K'));
}

function setup_crash_handler()
{	
	//debug('setup_crash_handler')
	Process.setExceptionHandler(
		function (details)
		{			
			if (EXCEPTION_WHITELIST.hasOwnProperty(details.type))
			{
				WriteCommandToPipe(ord('C'));
				return false;
			}
		}
	);
}
