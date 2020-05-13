#include <Windows.h>

static HANDLE pipe = INVALID_HANDLE_VALUE;
static OVERLAPPED pipe_overlapped;    /* Overlapped structure of pipe     */

#define EXPORT __declspec(dllexport)

EXPORT BOOL setup_pipe(char *pipe_name)
{
    pipe = CreateFileA(
        pipe_name,   // pipe name
        GENERIC_READ |  // read and write access
        GENERIC_WRITE,
        0,              // no sharing
        NULL,           // default security attributes
        OPEN_EXISTING,  // opens existing pipe
        0,              // default attributes
        NULL);          // no template file

    if (pipe == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        LPCSTR err_msg = NULL;
        FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM, NULL, err, 0, (LPSTR)&err_msg, 0, NULL);
        MessageBoxA(NULL, err_msg, "GetLastError", MB_OK|MB_ICONWARNING);

        return FALSE;
    }
    return TRUE;
}

EXPORT char ReadCommandFromPipe() 
{
	DWORD num_read;
	char result;
	ReadFile(pipe, &result, 1, &num_read, NULL);
	return result;
}

EXPORT void WriteCommandToPipe(char cmd)
{
    //MessageBoxA(NULL, "WriteCommandToPipe", "WriteCommandToPipe", MB_OK|MB_ICONWARNING);
	DWORD num_written;
	WriteFile(pipe, &cmd, 1, &num_written, NULL);
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