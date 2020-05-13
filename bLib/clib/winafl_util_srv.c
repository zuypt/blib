#include <Windows.h>
#include <stdint.h>
#include <intrin.h>

#define u8 uint8_t
#define u64 uint64_t
#define u32 uint32_t
#define i32 int32_t

static HANDLE pipe;            /* Handle of the name pipe          */
static OVERLAPPED pipe_overlapped;    /* Overlapped structure of pipe     */

#define EXPORT __declspec(dllexport)

EXPORT BOOL SetupPipe(char* pipe_name)
{
	pipe = CreateNamedPipe(
		pipe_name,                // pipe name
		PIPE_ACCESS_DUPLEX |     // read/write access 
		FILE_FLAG_OVERLAPPED,    // overlapped mode 
		0,
		1,                        // max. instances
		512,                      // output buffer size
		512,                      // input buffer size
		20000,                    // client time-out
		NULL					  // default security attribute
	);

	if (pipe == INVALID_HANDLE_VALUE) {
		DWORD err = GetLastError();
		LPCSTR err_msg = NULL;
		FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM, NULL, err, 0, (LPSTR)&err_msg, 0, NULL);
		MessageBoxA(NULL, err_msg, "GetLastError", MB_OK|MB_ICONWARNING);

		return FALSE;
	}
	return TRUE;
}

EXPORT void CleanupPipe()
{
	DisconnectNamedPipe(pipe);
	CloseHandle(pipe);
	CloseHandle(pipe_overlapped.hEvent);
}

EXPORT char ReadCommandFromPipe(DWORD timeout)
{
	DWORD num_read;
	char result = 0;

	if (ReadFile(pipe, &result, 1, &num_read, &pipe_overlapped) || GetLastError() == ERROR_IO_PENDING)
	{
		if (WaitForSingleObject(pipe_overlapped.hEvent, timeout) != WAIT_OBJECT_0) {
			CancelIo(pipe);
			WaitForSingleObject(pipe_overlapped.hEvent, INFINITE);
			result = 0;
		}
	}
	return result;
}

EXPORT void WriteCommandToPipe(char cmd)
{
	DWORD num_written;
	WriteFile(pipe, &cmd, 1, &num_written, &pipe_overlapped);
}

EXPORT BOOL OverlappedConnectNamedPipe()
{
	ZeroMemory(&pipe_overlapped, sizeof(pipe_overlapped));
	
	pipe_overlapped.hEvent = CreateEvent(
		NULL,    // default security attribute 
		TRUE,    // manual-reset event 
		TRUE,    // initial state = signaled 
		NULL	// unnamed event object 
	);   

	if (pipe_overlapped.hEvent == NULL) return FALSE;

	if (ConnectNamedPipe(pipe, &pipe_overlapped)) return FALSE;
	
	switch (GetLastError()) {
		// The overlapped connection in progress. 
		case ERROR_IO_PENDING:
			WaitForSingleObject(pipe_overlapped.hEvent, INFINITE);
			return TRUE;
		// Client is already connected
		case ERROR_PIPE_CONNECTED:
			return TRUE;
		default:
			return FALSE;
	}
}

#define FF(_b) (0xff << ((_b) << 3))
/*
count the number of non zero byte in a bitmap
*/
EXPORT u32 count_bytes(u8 *mem, u32 shm_sz)
{
	u32 *ptr = (u32 *)mem;
	u32  i = (shm_sz >> 2);
	u32  ret = 0;

	while (i--)
	{

		u32 v = *(ptr++);

		if (!v) continue;
		if (v & FF(0)) ++ret;
		if (v & FF(1)) ++ret;
		if (v & FF(2)) ++ret;
		if (v & FF(3)) ++ret;

	}
	return ret;
}


/*
TODO:
for linux
*/
#ifdef _WIN64

#define ROL64(_x, _r) ((((u64)(_x)) << (_r)) | (((u64)(_x)) >> (64 - (_r))))

EXPORT u32 hash32(const void *key, u32 len, u32 seed)
{
	const u64 *data = (u64 *)key;
	u64 h1 = seed ^ len;
 	
 	len >>= 3;

	while (len--)
	{

		u64 k1 = *data++;

		k1 *= 0x87c37b91114253d5ULL;
		k1 = ROL64(k1, 31);
		k1 *= 0x4cf5ad432745937fULL;

		h1 ^= k1;
		h1 = ROL64(h1, 27);
		h1 = h1 * 5 + 0x52dce729;
	}

	h1 ^= h1 >> 33;
	h1 *= 0xff51afd7ed558ccdULL;
	h1 ^= h1 >> 33;
	h1 *= 0xc4ceb9fe1a85ec53ULL;
	h1 ^= h1 >> 33;
	return h1;
}

#else

#define ROL32(_x, _r) ((((u32)(_x)) << (_r)) | (((u32)(_x)) >> (32 - (_r))))

EXPORT u32 hash32(const void *key, u32 len, u32 seed)
{

	const u32 *data = (u32 *)key;
	u32 h1 = seed ^ len;

	len >>= 2;

	while (len--)
	{

		u32 k1 = *data++;

		k1 *= 0xcc9e2d51;
		k1 = ROL32(k1, 15);
		k1 *= 0x1b873593;

		h1 ^= k1;
		h1 = ROL32(h1, 13);
		h1 = h1 * 5 + 0xe6546b64;
	}

	h1 ^= h1 >> 16;
	h1 *= 0x85ebca6b;
	h1 ^= h1 >> 13;
	h1 *= 0xc2b2ae35;
	h1 ^= h1 >> 16;
	return h1;
}
#endif


EXPORT u8 has_new_bits(u8 *trace_bits, u8 *virgin_map, u32 map_size)
{

#ifdef _WIN64

	u64 *current = (u64 *)trace_bits;
	u64 *virgin = (u64 *)virgin_map;

	u32 i = (map_size >> 3);

#else

	u32 *current = (u32 *)trace_bits;
	u32 *virgin = (u32 *)virgin_map;

	u32 i = (map_size >> 2);

#endif                                                     /* ^WORD_SIZE_64 */

	u8 ret = 0;

	while (i--)
	{

    /* Optimize for (*current & *virgin) == 0 - i.e., no bits in current bitmap
       that have not been already cleared from the virgin map - since this will
       almost always be the case. */

		if (*current && *current & *virgin)
		{

			if (ret < 2)
			{

	        	u8 *cur = (u8 *)current;
	        	u8 *vir = (u8 *)virgin;

				/* Looks like we have not found any new bytes yet; see if any non-zero
					bytes in current[] are pristine in virgin[]. */

#ifdef _WIN64

				if ((cur[0] && vir[0] == 0xff) || (cur[1] && vir[1] == 0xff) ||
					(cur[2] && vir[2] == 0xff) || (cur[3] && vir[3] == 0xff) ||
					(cur[4] && vir[4] == 0xff) || (cur[5] && vir[5] == 0xff) ||
					(cur[6] && vir[6] == 0xff) || (cur[7] && vir[7] == 0xff))
					ret = 2;
				else
					ret = 1;

#else

				if ((cur[0] && vir[0] == 0xff) || (cur[1] && vir[1] == 0xff) ||
					(cur[2] && vir[2] == 0xff) || (cur[3] && vir[3] == 0xff))
					ret = 2;
				else
					ret = 1;

#endif                                                     /* ^WORD_SIZE_64 */

			}

		*virgin &= ~*current;
		}

	++current;
	++virgin;

	}
	return ret;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		break;
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}