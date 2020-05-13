import sys
import frida

t =\
'''
rpc.exports = {
	init: function()
	{
		console.log('init')
		Process.setExceptionHandler(
			function (details)
			{
				console.log(JSON.stringify(details))
			}
		);
	}
}
'''

def on_msg(msg, data):
	print (repr(msg), repr(data))


pid = frida.spawn([r'bin32\Release\test_bin.exe'])
session = frida.attach(pid)
script = session.create_script(t)

script.on('message', on_msg)

script.load()
script.exports.init()
input('>')
frida.resume(pid)
sys.stdin.read()