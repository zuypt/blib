#include <Windows.h>

static HANDLE pipe = INVALID_HANDLE_VALUE;
static OVERLAPPED pipe_overlapped;    /* Overlapped structure of pipe     */

#define EXPORT __declspec(dllexport)

EXPORT DWORD calc(DWORD num) {
	if (num%2==0) return num*num;
	else return num*num*num;
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