#include "stdafx.h"

std::unique_ptr<Console> g_console;
std::unique_ptr<TTF2SDK> g_SDK;

TTF2SDK& SDK()
{
    return *g_SDK;
}

// TODO: Add a hook for the script error function (not just compile error)
// TODO: Hook CoreMsgV

#define WRAPPED_MEMBER(name) MemberWrapper<decltype(&TTF2SDK::##name), &TTF2SDK::##name, decltype(&SDK), &SDK>::Call

HookedFunc<void, double, float> _Host_RunFrame("engine.dll", "\x48\x8B\xC4\x48\x89\x58\x00\xF3\x0F\x11\x48\x00\xF2\x0F\x11\x40\x00", "xxxxxx?xxxx?xxxx?");
HookedVTableFunc<decltype(&IVEngineServer::VTable::SpewFunc), &IVEngineServer::VTable::SpewFunc> IVEngineServer_SpewFunc;
SigScanFunc<void> d3d11DeviceFinder("materialsystem_dx11.dll", "\x48\x83\xEC\x00\x33\xC0\x89\x54\x24\x00\x4C\x8B\xC9\x48\x8B\x0D\x00\x00\x00\x00\xC7\x44\x24\x00\x00\x00\x00\x00", "xxx?xxxxx?xxxxxx????xxx?????");
SigScanFunc<void> mpJumpPatchFinder("engine.dll", "\x75\x00\x44\x8D\x40\x00\x48\x8D\x15\x00\x00\x00\x00\x48\x8D\x0D\x00\x00\x00\x00\xE8\x00\x00\x00\x00", "x?xxx?xxx????xxx????x????");
HookedFunc<int64_t, const char*, const char*, int64_t> engineCompareFunc("engine.dll", "\x4D\x8B\xD0\x4D\x85\xC0", "xxxxxx");
SigScanFunc<void> secondMpJumpPatchFinder("engine.dll", "\x0F\x84\x00\x00\x00\x00\x84\xDB\x74\x00\x48\x8B\x0D\x00\x00\x00\x00", "xx????xxx?xxx????");
SigScanFunc<int64_t, void*> EnableNoclip("server.dll", "\x48\x89\x5C\x24\x00\x57\x48\x83\xEC\x00\x48\x8B\x01\x41\x83\xC8\x00\x33\xD2\x48\x8B\xF9", "xxxx?xxxx?xxxxxx?xxxxx");
SigScanFunc<int64_t, void*> DisableNoclip("server.dll", "\x48\x89\x5C\x24\x00\x57\x48\x81\xEC\x00\x00\x00\x00\x33\xC0", "xxxx?xxxx????xx");
SigScanFunc<void*, int> UTIL_EntityByIndex("server.dll", "\x66\x83\xF9\xFF\x75\x03\x33\xC0\xC3", "xxxxxxxxx");

char* pdefBuffer;

void InvalidParameterHandler(
    const wchar_t* expression,
    const wchar_t* function,
    const wchar_t* file,
    unsigned int line,
    uintptr_t pReserved
)
{
    // Do nothing so that _vsnprintf_s returns an error instead of aborting
}

__int64 SpewFuncHook(IVEngineServer* engineServer, SpewType_t type, const char* format, va_list args)
{
    char pTempBuffer[5020];

    // There are some cases where Titanfall will pass an invalid format string to this function, causing a crash.
    // To avoid this, we setup a temporary invalid parameter handler which will just continue execution.

    int val = -1;
    #if _DEBUG
    // so titanfall 2 does this really cool thing where it occasionally gives invalid format strings that use invalid specifiers e.g. %', probably by mistake
    // this is a problem exclusively in debug builds since the printf functions have debug asserts that will fail due to said specifiers
    // in release these asserts aren't compiled in so our fail code will function by itself, but we've gotta detect and handle these failures manually in debug
    
    // in theory this could be bad when format[0] == null but i don't think that should ever happen and is easy to patch anyway
    // aside from that this should mostly work? unsure
    bool debugShouldSkip = false;
    for (int i = 1; format[i] != 0; i++)
        if (format[i - 1] == '%')
        {
            switch (format[i])
            {
            // this is fucking awful lol
            case 'd':
            case 'i':
            case 'u':
            case 'x':
            case 'X':
            case 'f':
            case 'F':
            case 'g':
            case 'G':
            case 'a':
            case 'A':
            case 'c':
            case 's':
            case 'p':
            case 'n':
            case '%':
            case '-':
            case '+':
            case ' ':
            case '#':
            case '*':
            case '0':
            case '1':
            case '2':
            case '3':
            case '4':
            case '5':
            case '6':
            case '7':
            case '8':
            case '9':
                break;

            default:
                debugShouldSkip = true;
            }
        }

    if (!debugShouldSkip)
    #endif
    {
        _invalid_parameter_handler oldHandler = _set_thread_local_invalid_parameter_handler(InvalidParameterHandler);
        val = _vsnprintf_s(pTempBuffer, sizeof(pTempBuffer) - 1, format, args); // causes an assertion failure in debug builds
        _set_thread_local_invalid_parameter_handler(oldHandler);
    }

    if (val == -1)
    {
        spdlog::get("logger")->warn("Failed to call _vsnprintf_s for SpewFunc (format = {})", format);
        return IVEngineServer_SpewFunc(engineServer, type, format, args);
    }

    if (type == SPEW_MESSAGE)
    {
        spdlog::get("logger")->info("SERVER (SPEW_MESSAGE): {}", pTempBuffer);
    }
    else if (type == SPEW_WARNING)
    {
        spdlog::get("logger")->warn("SERVER (SPEW_WARNING): {}", pTempBuffer);
    }
    else
    {
        spdlog::get("logger")->info("SERVER ({}): {}", type, pTempBuffer);
    }

    return IVEngineServer_SpewFunc(engineServer, type, format, args);
}

int64_t compareFuncHook(const char* first, const char* second, int64_t count)
{
    if (strcmp(second, "mp_") == 0 && strncmp(first, "mp_", 3) == 0)
    {
        SPDLOG_LOGGER_TRACE(spdlog::get("logger"), "Overwriting result of compareFunc for {}", first);
        return 1;
    }
    else
    {
        return engineCompareFunc(first, second, count);
    }
}

typedef char(__fastcall* parsePdefType)(char* pdef, int32_t a2, int64_t a3, int32_t a4);
parsePdefType parsePdef;
char parsePdefHook(char* pdef, int32_t a2, int64_t a3, int32_t a4)
{
    size_t len = strlen(pdef);
    SPDLOG_LOGGER_TRACE(spdlog::get("logger"), len);
    pdefBuffer = new char[len + 1];
    strcpy_s(pdefBuffer, len + 1, pdef);

    return parsePdef(pdef, a2, a3, a4);
}

char* nextPlayerPdata;

typedef __int64(__fastcall* connectClientType)(void* server, void* a2, __int64 a3, uint32_t a4, uint32_t a5, int32_t a6, __int64 a7, __int64 a8, char* serverFilter, __int64 a10, char a11, __int64 a12, char a13, char a14, __int64 a15, uint32_t a16, uint32_t a17);
connectClientType connectClient;
__int64 __fastcall connectClientHook(void* server, void* a2, __int64 a3, uint32_t a4, uint32_t a5, int32_t a6, __int64 a7, __int64 a8, char* serverFilter, __int64 a10, char a11, __int64 a12, char a13, char a14, __int64 a15, uint32_t a16, uint32_t a17)
{
    // very temp code for the testing session
    // we store player auth info in the serverfilter, since it's sent in the connection packet already
    // for testing this is just a unique identifier
    nextPlayerPdata = serverFilter;
    serverFilter = "";

    return connectClient(server, a2, a3, a4, a5, a6, a7, a8, serverFilter, a10, a11, a12, a13, a14, a15, a16, a17);
}

int pdataLength;

typedef DWORD(__fastcall* clientConstructorType)(__int64 a1);
clientConstructorType clientConstructor;
DWORD __fastcall clientConstructorHook(__int64 player, __int64 a2, __int64 a3, __int64 a4)
{
    __int64 ret = clientConstructor(player);

    // set persistent data as ready
    *(char*)(player + 0x4a0) = (char)0x3;

    SPDLOG_LOGGER_TRACE(spdlog::get("logger"), "player addr = {}", (player + 0x4a0));

    char* playerdataBuffer = (char*)(player + 0x4fa);

    // build path
    std::string path = "playerdata/placeholder_playerdata.pdata";
    if (*nextPlayerPdata)
    {
        path = "playerdata/playerdata_";
        path += nextPlayerPdata;
        path += ".pdata";

        SPDLOG_LOGGER_DEBUG(spdlog::get("logger"), "playerdata:");
        SPDLOG_LOGGER_DEBUG(spdlog::get("logger"), path);

        // set uuid too lol
        strcpy_s((char*)(player + 0xF500), strlen(nextPlayerPdata) + 1,nextPlayerPdata);
    }

    // copy playerdata from disk
    std::fstream playerdataStream(path, std::ios_base::in);

    if (playerdataStream.fail()) // file doesn't exist, use placeholder for now, we'll save it to its own file later
    {
        path = "playerdata/placeholder_playerdata.pdata";
        playerdataStream = std::fstream(path, std::ios_base::in);
    }

    // get length of file
    playerdataStream.seekg(0, playerdataStream.end);
    int length = playerdataStream.tellg();
    pdataLength = length;
    playerdataStream.seekg(0, playerdataStream.beg);

    // write to client
    playerdataStream.read(playerdataBuffer, length);

    return ret;
}

typedef void(__fastcall* rejectClientType)(void* a1, uint32_t a2, void* a3, char* a4, ...);
rejectClientType rejectClient;
void __fastcall rejectClientHook(void* a1, uint32_t a2, void* connectingClient, char* format, ...)
{
    // temp hook until serverFilter fuckery is complete

    char tempBuffer[4096];

    va_list args;
    va_start(args, format);
    vsprintf_s(tempBuffer, format, args);
    va_end(args);

    char* rejectString = tempBuffer;
    // if this is a serverFilter kick we don't wanna leak the serverFilter we're using to clients
    char* serverFilterString = "Incoming server filter of";
    if (strncmp(rejectString, serverFilterString, strlen(serverFilterString)) == 0)
        rejectString = "The password entered was incorrect";

    rejectClient(a1, a2, connectingClient, rejectString);
}

typedef void(__fastcall* doConCommandType)(int32_t a1, char* command, uint32_t a3);

typedef __int64(__fastcall* commandConnectType)(__int64 a1);
commandConnectType commandConnect;
__int64 __fastcall commandConnectHook(__int64 a1)
{
    // very temp for pre-refactor playtests
    // set serverfilter for auth
    doConCommandType doConCommand = (doConCommandType)((DWORD64)Util::GetModuleInfo("engine.dll").lpBaseOfDll + 0x1203B0);
    char* originUid = (char*)((DWORD64)Util::GetModuleInfo("engine.dll").lpBaseOfDll + 0x13F8E688);
    std::string filterCommand = "serverFilter ";
    filterCommand += originUid;

    doConCommand(0, (char*)filterCommand.c_str(), 0);

    return commandConnect(a1);
}

typedef bool(__fastcall* isFlagSetType)(void* convar, int flags);
isFlagSetType isFlagSet;
bool __fastcall isFlagSetHook(void* convar, int flags)
{
    if (convar != nullptr)
    {
        // allow us to fuck with any hidden/devonly convars
        char* nameptr = *((char**)convar + 3); // base + 24
        if (flags == 1 << 1 || flags == 1 << 4) // FCVAR_DEVELOPMENTONLY or FCVAR_HIDDEN
            return false; // can't check with | rather than == because it seems to fuck up a few things regarding auth/platform stuff
    }


    return isFlagSet(convar, flags);
}

TTF2SDK::TTF2SDK(const SDKSettings& settings) :
    m_engineServer("engine.dll", "VEngineServer022"),
    m_engineClient("engine.dll", "VEngineClient013"),
    m_inputSystem("inputsystem.dll", "InputSystemVersion001")
{
    m_logger = spdlog::get("logger");

    SigScanFuncRegistry::GetInstance().ResolveAll();

    if (MH_Initialize() != MH_OK)
    {
        throw std::exception("Failed to initialise MinHook");
    }

    // to refactor: misc hooks

    CreateCurlHooks();

    LPVOID parsePdefAddress = (LPVOID)((DWORD64)Util::GetModuleInfo("engine.dll").lpBaseOfDll + 0x23A990);
    if (MH_CreateHookEx(parsePdefAddress, &parsePdefHook, &parsePdef) != MH_OK)
        SPDLOG_LOGGER_DEBUG(m_logger, "failed hooking parsePdef");

    LPVOID connectClientAddress = (LPVOID)((DWORD64)Util::GetModuleInfo("engine.dll").lpBaseOfDll + 0x114430);
    if (MH_CreateHookEx(connectClientAddress, &connectClientHook, &connectClient) != MH_OK)
        SPDLOG_LOGGER_DEBUG(m_logger, "failed hooking CBaseServer::ConnectClient");

    LPVOID clientConstructorAddress = (LPVOID)((DWORD64)Util::GetModuleInfo("engine.dll").lpBaseOfDll + 0x101480);
    if (MH_CreateHookEx(clientConstructorAddress, &clientConstructorHook, &clientConstructor) != MH_OK)
        SPDLOG_LOGGER_DEBUG(m_logger, "failed hooking clientConstructor");

    LPVOID rejectClientAddress = (LPVOID)((DWORD64)Util::GetModuleInfo("engine.dll").lpBaseOfDll + 0x1182e0);
    if (MH_CreateHookEx(rejectClientAddress, &rejectClientHook, &rejectClient) != MH_OK)
        SPDLOG_LOGGER_DEBUG(m_logger, "failed hooking rejectClient");

    LPVOID commandConnectAddress = (LPVOID)((DWORD64)Util::GetModuleInfo("engine.dll").lpBaseOfDll + 0x76720);
    if (MH_CreateHookEx(commandConnectAddress, &commandConnectHook, &commandConnect) != MH_OK)
        SPDLOG_LOGGER_DEBUG(m_logger, "failed hooking command connect"); 

    LPVOID isFlagSetAddress = (LPVOID)((DWORD64)Util::GetModuleInfo("engine.dll").lpBaseOfDll + 0x417FA0);
    if (MH_CreateHookEx(isFlagSetAddress, &isFlagSetHook, &isFlagSet) != MH_OK)
        SPDLOG_LOGGER_DEBUG(m_logger, "failed hooking convar::isflagset");

    MH_EnableHook(MH_ALL_HOOKS);

    //curl_infof((int64_t)nullptr, "dios mio");

    // Get pointer to d3d device
    char* funcBase = (char*)d3d11DeviceFinder.GetFuncPtr();
    int offset = *(int*)(funcBase + 16);
    m_ppD3D11Device = (ID3D11Device**)(funcBase + 20 + offset);

    SPDLOG_LOGGER_DEBUG(m_logger, "m_ppD3D11Device = {}", (void*)m_ppD3D11Device);
    SPDLOG_LOGGER_DEBUG(m_logger, "pD3D11Device = {}", (void*)*m_ppD3D11Device);

    m_conCommandManager.reset(new ConCommandManager());

    m_fsManager.reset(new FileSystemManager(settings.BasePath, *m_conCommandManager));
    m_sqManager.reset(new SquirrelManager(*m_conCommandManager));
    ////m_uiManager.reset(new UIManager(*m_conCommandManager, *m_sqManager, *m_fsManager, m_ppD3D11Device));
    //m_pakManager.reset(new PakManager(*m_conCommandManager, m_engineServer, *m_sqManager, m_ppD3D11Device));
    m_modManager.reset(new ModManager(*m_conCommandManager, *m_sqManager));
    m_sourceConsole.reset(new SourceConsole(*m_conCommandManager, settings.DeveloperMode ? spdlog::level::debug : spdlog::level::info));

    //m_icepickMenu.reset(new IcepickMenu(*m_conCommandManager, *m_uiManager, *m_sqManager, *m_fsManager));

    IVEngineServer_SpewFunc.Hook(m_engineServer->m_vtable, SpewFuncHook);
    _Host_RunFrame.Hook(WRAPPED_MEMBER(RunFrameHook));
    //engineCompareFunc.Hook(compareFuncHook);

    // we don't want these
    // Patch jump for loading MP maps in single player
    //{
    //    void* ptr = mpJumpPatchFinder.GetFuncPtr();
    //    SPDLOG_LOGGER_DEBUG(m_logger, "mpJumpPatchFinder = {}", ptr);
    //    TempReadWrite rw(ptr);
    //    *(unsigned char*)ptr = 0xEB;
    //}

    // Second patch, changing jz to jnz
    //{
    //    void* ptr = secondMpJumpPatchFinder.GetFuncPtr();
    //    SPDLOG_LOGGER_DEBUG(m_logger, "secondMpJumpPatchFinder = {}", ptr);
    //    TempReadWrite rw(ptr);
    //    *((unsigned char*)ptr + 1) = 0x85;
    //}

    // allow multiple of the same account to connect for testing
    {
        void* ptr = (void*)(((DWORD64)Util::GetModuleInfo("engine.dll").lpBaseOfDll) + 0x114510);
        TempReadWrite rw(ptr);
        *((char*)ptr) = (char)0xEB; // jnz => jmp
    }
    // allow recieving clients regardless of IsSinglePlayerGame()
    {
        void* ptr = (void*)(((DWORD64)Util::GetModuleInfo("engine.dll").lpBaseOfDll) + 0x1145B8);
        TempReadWrite rw(ptr);
        *((char*)ptr) = (char)0xEB; // jnz => jmp
    }
    // TEMP PATCH prevent pausing from working regardless of IsSinglePlayerGame()
    // todo: only do this if >1 players
    {
        void* ptr = (void*)(((DWORD64)Util::GetModuleInfo("engine.dll").lpBaseOfDll) + 0x1167b7);
        TempReadWrite rw(ptr);
        *((char*)ptr) = (char)0xEB; // jnz => jmp
    }
    
    // get around a crash when making custom servers
    {
        // this isn't really necessary now playerdata works but there's not really much point in removing it

        void* ptr = (void*)(((DWORD64)Util::GetModuleInfo("engine.dll").lpBaseOfDll) + 0x10103d);
        TempReadWrite rw(ptr);
        // prevent crashing function from calling
        *((char*)ptr) = (char)0x90;
        *((char*)ptr + 1) = (char)0x90;
        *((char*)ptr + 2) = (char)0x90;
        *((char*)ptr + 3) = (char)0x90;
        *((char*)ptr + 4) = (char)0x90;
        // prevent fairfight kicks due to nop'd function
        *((char*)ptr + 5) = (char)0x30; // test al,al => xor al,al (results in al = 0)
    }

    // temp patch to prevent serverfilter stuff from kicking for playtests
    {
        void* ptr = (void*)(((DWORD64)Util::GetModuleInfo("engine.dll").lpBaseOfDll) + 0x114655);
        TempReadWrite rw(ptr);
        *((char*)ptr) = (char)0xEB; // jz => jmp
    }

    // Add delayed func task
    m_delayedFuncTask = std::make_shared<DelayedFuncTask>();
    AddFrameTask(m_delayedFuncTask);

    // Add squirrel functions for mouse deltas
    m_sqManager->AddFuncRegistration(CONTEXT_CLIENT, "int", "GetMouseDeltaX", "", "", WRAPPED_MEMBER(SQGetMouseDeltaX));
    m_sqManager->AddFuncRegistration(CONTEXT_CLIENT, "int", "GetMouseDeltaY", "", "", WRAPPED_MEMBER(SQGetMouseDeltaY));

    m_sqManager->AddFuncRegistration(CONTEXT_SERVER, "void", "EnableNoclipForEntityIndex", "int entityIndex", "", WRAPPED_MEMBER(SQEnableNoclipForIndex));
    m_sqManager->AddFuncRegistration(CONTEXT_SERVER, "void", "DisableNoclipForEntityIndex", "int entityIndex", "", WRAPPED_MEMBER(SQDisableNoclipForIndex));

    m_sqManager->AddFuncRegistration(CONTEXT_SERVER, "void", "SavePdataForEntityIndex", "int entityIndex", "", WRAPPED_MEMBER(SQSavePdata));
    
    m_conCommandManager->RegisterCommand("noclip_enable", WRAPPED_MEMBER(EnableNoclipCommand), "Enable noclip", 0);
    m_conCommandManager->RegisterCommand("noclip_disable", WRAPPED_MEMBER(DisableNoclipCommand), "Disable noclip", 0);
    m_conCommandManager->RegisterCommand("dump_persistence", WRAPPED_MEMBER(DumpClientPersistenceCommand), "dump mp playerdata to a file", 0);
    m_conCommandManager->RegisterCommand("setplaylist", WRAPPED_MEMBER(SetPlaylistCommand), "set current playlist", 0);

    //StartIPC();
}

FileSystemManager& TTF2SDK::GetFSManager()
{
    return *m_fsManager;
}

SquirrelManager& TTF2SDK::GetSQManager()
{
    return *m_sqManager;
}

PakManager& TTF2SDK::GetPakManager()
{
    return *m_pakManager;
}

ModManager& TTF2SDK::GetModManager()
{
    return *m_modManager;
}

ConCommandManager& TTF2SDK::GetConCommandManager()
{
    return *m_conCommandManager;
}

UIManager& TTF2SDK::GetUIManager()
{
    return *m_uiManager;
}

SourceConsole& TTF2SDK::GetSourceConsole()
{
    return *m_sourceConsole;
}

ID3D11Device** TTF2SDK::GetD3D11DevicePtr()
{
    return m_ppD3D11Device;
}

IcepickMenu& TTF2SDK::GetIcepickMenu()
{
    return *m_icepickMenu;
}

SourceInterface<IVEngineServer>& TTF2SDK::GetEngineServer()
{
    return m_engineServer;
}

SourceInterface<IVEngineClient>& TTF2SDK::GetEngineClient()
{
    return m_engineClient;
}

SourceInterface<IInputSystem>& TTF2SDK::GetInputSystem()
{
    return m_inputSystem;
}

void TTF2SDK::RunFrameHook(double absTime, float frameTime)
{
    static bool translatorUpdated = false;
    if (!translatorUpdated)
    {
        UpdateSETranslator();
        translatorUpdated = true;
    }
    
    for (const auto& frameTask : m_frameTasks)
    {
        frameTask->RunFrame();
    }

    m_frameTasks.erase(std::remove_if(m_frameTasks.begin(), m_frameTasks.end(), [](const std::shared_ptr<IFrameTask>& t)
    { 
        return t->IsFinished();
    }), m_frameTasks.end());

    static bool called = false;
    if (!called)
    {
        m_logger->info("RunFrame called for the first time");
        m_sourceConsole->InitialiseSource();
        //m_pakManager->PreloadAllPaks();
        called = true;
    }
   
    return _Host_RunFrame(absTime, frameTime);
}

void TTF2SDK::AddFrameTask(std::shared_ptr<IFrameTask> task)
{
    m_frameTasks.push_back(std::move(task));
}

void TTF2SDK::AddDelayedFunc(std::function<void()> func, int frames)
{
    m_delayedFuncTask->AddFunc(func, frames);
}

SQInteger TTF2SDK::SQGetMouseDeltaX(HSQUIRRELVM v)
{
    sq_pushinteger.CallClient(v, m_inputSystem->m_analogDeltaX);
    return 1;
}

SQInteger TTF2SDK::SQGetMouseDeltaY(HSQUIRRELVM v)
{
    sq_pushinteger.CallClient(v, m_inputSystem->m_analogDeltaY);
    return 1;
}

SQInteger TTF2SDK::SQEnableNoclipForIndex(HSQUIRRELVM v)
{
    // unsure how to read entities from args so we use indexes instead
    int entityIndex = sq_getinteger.CallServer(v, 1); // first arg
    void* entity = UTIL_EntityByIndex(entityIndex);

    if (entity != nullptr)
        EnableNoclip(entity);
    else
        m_logger->error("failed to find entity to enable noclip given index");

    return 0;
}

SQInteger TTF2SDK::SQDisableNoclipForIndex(HSQUIRRELVM v)
{
    // unsure how to read entities from args so we use indexes instead
    int entityIndex = sq_getinteger.CallServer(v, 1); // first arg
    void* entity = UTIL_EntityByIndex(entityIndex);

    if (entity != nullptr)
        DisableNoclip(entity);
    else
        m_logger->error("failed to find entity to disable noclip by given index");

    return 0;
}

SQInteger TTF2SDK::SQSavePdata(HSQUIRRELVM v)
{
    // unsure how to read entities from args so we use indexes instead
    int playerIndex = sq_getinteger.CallServer(v, 1);
    char* playerBase = (char*)(((DWORD64)Util::GetModuleInfo("engine.dll").lpBaseOfDll) + 0x12a53f90 + (playerIndex * 0x2D728));

    char* uuid = playerBase + 0xf500; // get uuid
    char* playerPdata = playerBase + 0x4fa; // get pdata offset

    if (*uuid) // will be null if not using pdata
    {
        // build path
        std::string path = "playerdata/playerdata_";
        path += uuid;
        path += ".pdata";

        std::fstream pdataStream(path, std::ios_base::out);
        pdataStream.write(playerPdata, pdataLength);
    }

    return 0;
}

void TTF2SDK::EnableNoclipCommand(const CCommand& args)
{
    void* player = UTIL_EntityByIndex(1);
    if (player != nullptr)
    {
        EnableNoclip(player);
    }
    else
    {
        m_logger->error("Failed to find player entity");
    }
}

void TTF2SDK::DisableNoclipCommand(const CCommand& args)
{
    void* player = UTIL_EntityByIndex(1);
    if (player != nullptr)
    {
        DisableNoclip(player);
    }
    else
    {
        m_logger->error("Failed to find player entity");
    }
}

void TTF2SDK::DumpClientPersistenceCommand(const CCommand& args)
{
    int length = *(int32_t*)(((DWORD64)Util::GetModuleInfo("engine.dll").lpBaseOfDll) + 0x1401D438); // const address playerdata length is stored at
    char* playerdataAddress = (char*)(((DWORD64)Util::GetModuleInfo("engine.dll").lpBaseOfDll) + 0x7a6f98); // const address playerdata is stored at
    // TODO calculate playerdata length at runtime using previously read/dumped pdefs, will require parsing but should be easy af

    if (*playerdataAddress != (char)0xE7) // const pdef version for vanilla, this check should be removed at some point
    {
        SPDLOG_LOGGER_ERROR(m_logger, "playerdata's initializedVersion was not 231! playerdata address may be wrong!");
        return;
    }

    std::fstream playerdataStream("dumped_playerdata.bin", std::ios_base::out);
    playerdataStream.write(playerdataAddress, length);

    // write pdef
    std::fstream pdefStream("dumped_pdef.pdef", std::ios_base::out);
    pdefStream.write(pdefBuffer, strlen(pdefBuffer));
}

typedef char(__fastcall setPlaylistFuncType)(char* playlistName);
void TTF2SDK::SetPlaylistCommand(const CCommand& args)
{
    if (args.ArgC() < 2)
        return;

    char* playlistName = (char*)args.Arg(1); // get first arg for name

    setPlaylistFuncType* setPlaylistFuncAddress = (setPlaylistFuncType*)(((DWORD64)Util::GetModuleInfo("engine.dll").lpBaseOfDll) + 0x18eb20); // get ptr to setplaylist func
    setPlaylistFuncAddress(playlistName); // call it
}

void TTF2SDK::StartIPC()
{
    m_stopIpcThread.reset(CreateEvent(NULL, TRUE, FALSE, NULL));
    if (m_stopIpcThread.get() == NULL)
    {
        m_logger->error("Failed to IPC cancellation event - remote commands will not be available");
        return;
    }

    m_ipcPipe.reset(CreateNamedPipe(TEXT("\\\\.\\pipe\\TTF2SDK"),
        PIPE_ACCESS_INBOUND | FILE_FLAG_OVERLAPPED,
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
        1,
        16 * 1024,
        16 * 1024,
        NMPWAIT_USE_DEFAULT_WAIT,
        NULL));

    if (m_ipcPipe.get() == INVALID_HANDLE_VALUE)
    {
        m_logger->error("Failed to create named pipe - remote commands will not be available");
        return;
    }

    m_ipcThread = std::thread(&TTF2SDK::NamedPipeThread, this);
}

bool TTF2SDK::ConnectToIPCClient()
{
    SafeHandle hEvent(CreateEvent(NULL, TRUE, FALSE, NULL));
    if (hEvent.get() == NULL)
    {
        m_logger->error("Failed to create event in ConnectToIPCClient");
        return false;
    }

    OVERLAPPED ol = { 0 };
    ol.hEvent = hEvent.get();
    BOOL connected = ConnectNamedPipe(m_ipcPipe.get(), &ol);

    // Overlapped ConnectNamedPipe should return zero.
    if (connected)
    {
        m_logger->error("ConnectNamedPipe failed with {}", GetLastError());
        return false;
    }

    HANDLE waitHandles[] = { m_stopIpcThread.get(), ol.hEvent };

    DWORD error = GetLastError();
    if (error == ERROR_IO_PENDING)
    {
        DWORD waitResult = WaitForMultipleObjects(2, waitHandles, FALSE, INFINITE);
        if (waitResult == WAIT_OBJECT_0) // Thread cancelled
        {
            CancelIo(m_ipcPipe.get());
            return false;
        }
        else if (waitResult == (WAIT_OBJECT_0 + 1)) // Client connected
        {
            DWORD dwDummy;
            return GetOverlappedResult(m_ipcPipe.get(), &ol, &dwDummy, FALSE);
        }
        else // Something went wrong
        {
            return false;
        }
    }
    else if (error == ERROR_PIPE_CONNECTED)
    {
        return true;
    }
    else
    {
        m_logger->error("ConnectNamedPipe failed with {}", GetLastError());
        return false;
    }
}

void TTF2SDK::HandleIPCData(char* buffer, DWORD bytesRead)
{
    buffer[bytesRead] = 0;
    if (buffer[0] == 'C')
    {
        GetSQManager().ExecuteClientCode(buffer + 1);
    }
    else if (buffer[0] == 'S')
    {
        GetSQManager().ExecuteServerCode(buffer + 1);
    }
    else
    {
        m_logger->error("Received malformed IPC message: must start with either S or C.");
    }
}

void TTF2SDK::NamedPipeThread()
{
    const size_t BUFFER_SIZE = 16 * 1024;
    std::unique_ptr<char[]> buffer(new char[BUFFER_SIZE]);
    DWORD bytesRead;

    while (true)
    {
        bool connected = ConnectToIPCClient();
        if (!connected)
        {
            SPDLOG_LOGGER_DEBUG(m_logger, "ConnectToIPCClient returned false - ending IPC thread");
            return;
        }

        while (true)
        {
            SafeHandle hEvent(CreateEvent(NULL, TRUE, FALSE, NULL));
            if (hEvent.get() == NULL)
            {
                m_logger->error("Failed to create event for ReadFile in IPC");
                return;
            }

            OVERLAPPED ol = { 0 };
            ol.hEvent = hEvent.get();
            BOOL result = ReadFile(m_ipcPipe.get(), buffer.get(), BUFFER_SIZE - 1, &bytesRead, &ol);
            DWORD error = GetLastError();
            if (result)
            {
                if (bytesRead > 1)
                {
                    HandleIPCData(buffer.get(), bytesRead);
                }
            }
            else if (error == ERROR_IO_PENDING)
            {
                HANDLE waitHandles[] = { m_stopIpcThread.get(), ol.hEvent };
                DWORD waitResult = WaitForMultipleObjects(2, waitHandles, FALSE, INFINITE);
                if (waitResult == WAIT_OBJECT_0) // Thread cancelled
                {
                    CancelIo(m_ipcPipe.get());
                    return;
                }
                else if (waitResult == (WAIT_OBJECT_0 + 1)) // Read completed
                {
                    if (GetOverlappedResult(m_ipcPipe.get(), &ol, &bytesRead, FALSE))
                    {
                        if (bytesRead > 1)
                        {
                            HandleIPCData(buffer.get(), bytesRead);
                        }
                    }
                    else
                    {
                        break;
                    }
                }
            }
            else
            {
                break;
            }
        }
        
        DisconnectNamedPipe(m_ipcPipe.get());
    }
}

TTF2SDK::~TTF2SDK()
{
    SetEvent(m_stopIpcThread.get());
    m_ipcThread.join();

    // TODO: Reorder these
    m_sqManager.reset();
    m_conCommandManager.reset();
    m_fsManager.reset();
    m_pakManager.reset();
    m_modManager.reset();
    m_uiManager.reset();
    m_sourceConsole.reset();
    // TODO: Add anything i've missed here
    
    MH_Uninitialize();
}

class flushed_file_sink_mt : public spdlog::sinks::sink
{
public:
    explicit flushed_file_sink_mt(const spdlog::filename_t &filename, bool truncate = false) : file_sink_(filename, truncate)
    {

    }

    void log(const spdlog::details::log_msg &msg) override
    {
        file_sink_.log(msg);
        flush();
    }

    void flush() override
    {
        file_sink_.flush();
    }

    void set_pattern(const std::string &pattern) override
    {
        file_sink_.set_pattern(pattern);
    }

    void set_formatter(std::unique_ptr<spdlog::formatter> sink_formatter) override
    {
        file_sink_.set_formatter(std::move(sink_formatter));
    }

private:
    spdlog::sinks::basic_file_sink_mt file_sink_;
};

void SetupLogger(const std::string& filename, bool enableWindowsConsole)
{
    // Create sinks to file and console
    std::vector<spdlog::sink_ptr> sinks;
    
    if (enableWindowsConsole)
    {
        g_console = std::make_unique<Console>();
        sinks.push_back(std::make_shared<spdlog::sinks::wincolor_stdout_sink_mt>());
    }

    // The file sink could fail so capture the error if so
    std::unique_ptr<std::string> fileError;
    try
    {
        sinks.push_back(std::make_shared<flushed_file_sink_mt>(filename, true));
    }
    catch (spdlog::spdlog_ex& ex)
    {
        fileError = std::make_unique<std::string>(ex.what());
    }

    // Create logger from sinks
    auto logger = std::make_shared<spdlog::logger>("logger", begin(sinks), end(sinks));
    logger->set_pattern("[%T] [thread %t] [%l] %^%v%$");
#ifdef _DEBUG
    logger->set_level(spdlog::level::trace);
#else
    logger->set_level(spdlog::level::debug);
#endif

    if (fileError)
    {
        logger->warn("Failed to initialise file sink, log file will be unavailable ({})", *fileError);
    }

    spdlog::register_logger(logger);
}

bool SetupSDK(const SDKSettings& settings)
{
    // Separate try catch because these are required for logging to work
    try
    {
        fs::path basePath(settings.BasePath);
        SetupLogger((basePath / "TTF2SDK.log").string(), settings.DeveloperMode);
    }
    catch (std::exception& ex)
    {
        std::string message = fmt::format("Failed to initialise Icepick: {}", ex.what());
        MessageBox(NULL, Util::Widen(message).c_str(), L"Error", MB_OK | MB_ICONERROR);
        return false;
    }

    try
    {
        // TODO: Make this smarter (automatically pull DLL we need to load from somewhere)
        Util::WaitForModuleHandle("engine.dll");
        Util::WaitForModuleHandle("client.dll");
        Util::WaitForModuleHandle("server.dll");
        Util::WaitForModuleHandle("vstdlib.dll");
        Util::WaitForModuleHandle("filesystem_stdio.dll");
        Util::WaitForModuleHandle("rtech_game.dll");
        Util::WaitForModuleHandle("studiorender.dll");
        Util::WaitForModuleHandle("materialsystem_dx11.dll");

        Util::ThreadSuspender suspender;

        bool breakpadSuccess = SetupBreakpad(settings);
        if (breakpadSuccess)
        {
            spdlog::get("logger")->info("Breakpad initialised");
        }
        else
        {
            spdlog::get("logger")->info("Breakpad was not initialised");
        }

        g_SDK = std::make_unique<TTF2SDK>(settings);

        return true;
    }
    catch (std::exception& ex)
    {
        std::string message = fmt::format("Failed to initialise Icepick: {}", ex.what());
        spdlog::get("logger")->critical(message);
        MessageBox(NULL, Util::Widen(message).c_str(), L"Error", MB_OK | MB_ICONERROR);
        return false;
    }
}

void FreeSDK()
{
    g_SDK.reset();
}
