#include "stdafx.h"

struct Curl_easy
{
    uint32_t magic;
    struct Curl_easy* next;
    struct Curl_easy* prev;

};

struct UserDefined
{
    
};

typedef void(__fastcall* curl_infofType)(Curl_easy* data, const char* format, ...);
curl_infofType curl_infof;
void __fastcall curl_infofHook(void* data, const char* format, ...)
{
    char out[4096] = "[curl] info: ";

    va_list args;
    va_start(args, format);
    vsprintf_s(out + 13, sizeof out - 13, format, args);

    spdlog::get("logger")->debug(out);

    //return curl_infof(data, out + 12);
}

curl_infofType curl_failf;
void __fastcall curl_failfHook(Curl_easy* data, const char* format, ...)
{
    char out[4096] = "[curl] fail: ";

    va_list args;
    va_start(args, format);
    vsprintf_s(out + 13, sizeof out - 13, format, args);

    spdlog::get("logger")->warn(out);

    //return curl_infof(data, out + 12);
}

void CreateCurlHooks()
{
    std::shared_ptr<spdlog::logger> logger = spdlog::get("logger");

    LPVOID infofAddress = (LPVOID)((DWORD64)Util::GetModuleInfo("engine.dll").lpBaseOfDll + 0x260180);
    if (MH_CreateHookEx(infofAddress, &curl_infofHook, &curl_infof) != MH_OK)
        SPDLOG_LOGGER_DEBUG(logger, "failed hooking curl_infof");

    LPVOID failfAddress = (LPVOID)((DWORD64)Util::GetModuleInfo("engine.dll").lpBaseOfDll + 0x2600B0);
    if (MH_CreateHookEx(failfAddress, &curl_failfHook, &curl_failf) != MH_OK)
        SPDLOG_LOGGER_DEBUG(logger, "failed hooking curl_failf");

}