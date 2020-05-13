#include <Windows.h>
#include <stdio.h>
#include <time.h>
#include <stdlib.h>

typedef DWORD (*CALCPROTO)(DWORD);

__declspec(noinline) void do_work()
{
	int i;
	__asm{nop}

	HMODULE hMod = LoadLibraryA("bin32\\Release\\testlib.dll");
	CALCPROTO f = (CALCPROTO)GetProcAddress(hMod, "calc");

	srand(time(0));
	for(i=0; i<32; i++) {
		int n = rand();
		if (n%2==0) {
			printf("even: %d\n", f(n));
		} else {
			printf("odd: %d\n", f(n));
		}
	}
	printf("done\n");
	scanf("%d", &i);
}

int main(int argc, char** argv)
{
	
	// printf("main is at: 0x%p\n", &main);
	// printf("current thread is: %d\n", GetCurrentThreadId());

	// for(int i=0; i<2;i++) do_work();
	try
	{
		RaiseException(0xdeadead, 0, 0, NULL);
	}
	catch(...)
	{
		printf("stalker stopped");
	}

}

