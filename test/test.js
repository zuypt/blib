function initStalker()
{
	Stalker.trustThreshold = 0;
	var t = Process.enumerateThreads()[0]
	Stalker.follow(t.id,
	{
		transform: function(iterator)
		{
			while (iterator.next() != null) iterator.keep();
		}
	})
}

initStalker()
