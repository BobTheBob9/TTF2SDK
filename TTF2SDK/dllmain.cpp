#include "stdafx.h"

DWORD WINAPI OnAttach(LPVOID lpThreadParameter)
{
	return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved)
{
    switch (dwReason)
    {
    case DLL_PROCESS_ATTACH:
		DisableThreadLibraryCalls(hModule);
		CreateThread(NULL, 0, OnAttach, hModule, 0, NULL);
		break;
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
