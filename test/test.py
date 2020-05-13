import sys
import frida

t = '''
function initStalker()
{
	Stalker.trustThreshold = 0;
	var t = Process.enumerateThreads()[0]
	Stalker.follow(t.id,
	{
		transform: function(iterator)
		{
			var lolol = new NativePointer(123)
			while (iterator.next() != null) iterator.keep();
		}
	})
}

initStalker()
'''

pid = frida.spawn([r'bin32\Release\test_bin.exe'])
session = frida.attach(pid)
script = session.create_script(t)
script.load()
input('>')
frida.resume(pid)
sys.stdin.read()