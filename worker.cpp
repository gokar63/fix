#include <windows.h>
#include <objbase.h>

#include <psapi.h>
#include <regex>
#include <tlhelp32.h>
#include <fstream>
#include <mutex>

#include <xxhash.h>
#include <zstd.h>

#include "worker.hpp"



std::vector<std::uintptr_t> functions::GetChildrenAddresses(std::uintptr_t address, HANDLE handle) {
    std::vector<std::uintptr_t> children;
    {
        // Inline vector: Instance+0x78 = start ptr, Instance+0x80 = end ptr
        std::uintptr_t childrenStart = read_memory<std::uintptr_t>(address + offsets::Children, handle);
        std::uintptr_t childrenEnd = read_memory<std::uintptr_t>(address + offsets::Children + 0x8, handle);

        if (childrenStart == 0 || childrenEnd == 0 || childrenStart >= childrenEnd)
            return children;
        if (childrenEnd - childrenStart > 0x100000)
            return children;

        // Stride 0x10: each entry is {Instance*, metadata}
        for (std::uintptr_t childAddress = childrenStart; childAddress < childrenEnd; childAddress += 0x10) {
            std::uintptr_t childPtr = read_memory<std::uintptr_t>(childAddress, handle);
            if (childPtr > 0x10000 && childPtr < 0x7FFFFFFFFFFF) {
                children.push_back(childPtr);
            }
        }
    }
    return children;
}

std::string functions::ReadRobloxString(std::uintptr_t address, HANDLE handle) {
    std::uint64_t stringCount = read_memory<std::uint64_t>(address + 0x10, handle);

    if (stringCount > 15000 || stringCount <= 0)
        return "";

    if (stringCount > 15)
        address = read_memory<std::uintptr_t>(address, handle);

    std::string buffer;
    buffer.resize(stringCount);

    MEMORY_BASIC_INFORMATION bi;
    VirtualQueryEx(handle, reinterpret_cast<LPCVOID>(address), &bi, sizeof(bi));

    NtReadVirtualMemory(handle, reinterpret_cast<LPCVOID>(address), buffer.data(), (ULONG)stringCount, nullptr);

    PVOID baddr = bi.AllocationBase;
    SIZE_T size = bi.RegionSize;
    NtUnlockVirtualMemory(handle, &baddr, &size, 1);

    return buffer;
}

std::string Instance::GetBytecode() const {
    if (ClassName() != "LocalScript" && ClassName() != "ModuleScript")
        return "";

    std::uintptr_t embeddedSourceOffset = (ClassName() == "LocalScript") ? offsets::LocalScriptEmbedded : offsets::ModuleScriptEmbedded;
    std::uintptr_t embeddedPtr = read_memory<std::uintptr_t>(_Self + embeddedSourceOffset, handle);

    std::uintptr_t bytecodePtr = read_memory<std::uintptr_t>(embeddedPtr + offsets::Bytecode, handle);
    std::uint64_t bytecodeSize = read_memory<std::uint64_t>(embeddedPtr + offsets::BytecodeSize, handle);

    std::string bytecodeBuffer;
    bytecodeBuffer.resize(bytecodeSize);

    MEMORY_BASIC_INFORMATION bi;
    VirtualQueryEx(handle, reinterpret_cast<LPCVOID>(bytecodePtr), &bi, sizeof(bi));

    NtReadVirtualMemory(handle, reinterpret_cast<LPCVOID>(bytecodePtr), bytecodeBuffer.data(), (ULONG)bytecodeSize, nullptr);

    PVOID baddr = bi.AllocationBase;
    SIZE_T size = bi.RegionSize;
    NtUnlockVirtualMemory(handle, &baddr, &size, 1);

    return decompress(bytecodeBuffer);
}



static std::string generateGUID() {
    GUID guid;
    HRESULT result = CoCreateGuid(&guid);

    if (result != S_OK) {
        throw std::runtime_error("Failed to generate GUID");
    }

    char guidStr[39];
    snprintf(guidStr, sizeof(guidStr), "%08lX-%04X-%04X-%04X-%012llX", guid.Data1,
        guid.Data2, guid.Data3, (guid.Data4[0] << 8) | guid.Data4[1],
        ((static_cast<unsigned long long>(guid.Data4[2]) << 40) |
            (static_cast<unsigned long long>(guid.Data4[3]) << 32) |
            (static_cast<unsigned long long>(guid.Data4[4]) << 24) |
            (static_cast<unsigned long long>(guid.Data4[5]) << 16) |
            (static_cast<unsigned long long>(guid.Data4[6]) << 8) |
            static_cast<unsigned long long>(guid.Data4[7])));

    return std::string(guidStr);
}

static void replaceString(std::string& source, const std::string& toReplace, const std::string& replacement) {
    size_t pos = source.find(toReplace);

    if (pos != std::string::npos) {
        source.replace(pos, toReplace.length(), replacement);
    }
}

RBXClient::RBXClient(DWORD processID) :
    handle(OpenProcess(PROCESS_ALL_ACCESS, TRUE, processID)),
    PID(processID)
{
    if (handle == NULL) {
        return;
    }

    GUID = generateGUID();

    PROCESS_MEMORY_COUNTERS memory_counter;
    K32GetProcessMemoryInfo(handle, &memory_counter, sizeof(memory_counter));
    if (memory_counter.WorkingSetSize < 550000000) {
        while (memory_counter.WorkingSetSize < 550000000) {
            K32GetProcessMemoryInfo(handle, &memory_counter, sizeof(memory_counter));
            Sleep(100);
        }
    }

    RenderView = GetRV(handle);

    std::uintptr_t dataModelAddress = FetchDataModel();
    if (dataModelAddress == 0) {
        std::cerr << "[!] Failed to fetch datamodel\n";
        return;
    }

    Instance DataModel(dataModelAddress, handle);

    std::uintptr_t playersAddr = DataModel.FindFirstChildAddress("Players");
    if (playersAddr == 0) {
        std::cerr << "[!] Players not found\n";
        return;
    }
    std::uintptr_t localPlayerAddr = read_memory<std::uintptr_t>(playersAddr + offsets::LocalPlayer, handle);
    if (localPlayerAddr == 0 || localPlayerAddr < 0x10000) {
        std::cerr << "[!] LocalPlayer not found\n";
        return;
    }
    Instance LocalPlayer(localPlayerAddr, handle);
    Username = LocalPlayer.Name();

    // Need to add checks else the process will crash
    Instance* CoreGui = DataModel.FindFirstChild("CoreGui");
    if (!CoreGui) {
        std::cerr << "[!] Game->CoreGui not found\n";
        return;
    }

    Instance* existingXeno = CoreGui->FindFirstChild("Xeno");
    if (existingXeno) {
        delete existingXeno;
        std::cerr << "[!] Client '" << Username << "' is already attached\n";
        delete CoreGui;
        return;
    }

    Instance* RobloxGui = CoreGui->FindFirstChild("RobloxGui");
    if (!RobloxGui) {
        std::cerr << "[!] CoreGui->RobloxGui not found\n";
        return;
    }
    Instance* Modules = RobloxGui->FindFirstChild("Modules");
    if (!Modules) {
        std::cerr << "[!] RobloxGui->Modules not found\n";
        return;
    }

    Instance* PatchScript = nullptr;
    {
        Instance* Common = Modules->FindFirstChild("Common");
        if (!Common) {
            std::cerr << "[!] Modules->Common not found\n";
            return;
        }
        PatchScript = Common->FindFirstChild("Url");
    }

    if (!PatchScript) {
        std::cerr << "[!] Patch Script was not found\n";
        return;
    }

    extern const char* XENO_CLIENT_SCRIPT;
    std::string clientScript(XENO_CLIENT_SCRIPT);

    replaceString(clientScript, "%XENO_UNIQUE_ID%", GUID);
    replaceString(clientScript, "%XENO_VERSION%", "1.0.0");

    std::string PatchScriptSource = "--!native\n--!optimize 1\n--!nonstrict\nlocal a={}local b=game:GetService(\"ContentProvider\")local function c(d)local e,f=d:find(\"%.\")local g=d:sub(f+1)if g:sub(-1)~=\"/\"then g=g..\"/\"end;return g end;local d=b.BaseUrl;local g=c(d)local h=string.format(\"https://games.%s\",g)local i=string.format(\"https://apis.rcs.%s\",g)local j=string.format(\"https://apis.%s\",g)local k=string.format(\"https://accountsettings.%s\",g)local l=string.format(\"https://gameinternationalization.%s\",g)local m=string.format(\"https://locale.%s\",g)local n=string.format(\"https://users.%s\",g)local o={GAME_URL=h,RCS_URL=i,APIS_URL=j,ACCOUNT_SETTINGS_URL=k,GAME_INTERNATIONALIZATION_URL=l,LOCALE_URL=m,ROLES_URL=n}setmetatable(a,{__newindex=function(p,q,r)end,__index=function(p,r)return o[r]end})return a";

    if (DataModel.Name() == "App") { // In home page
        PatchScript->SetBytecode(Compile("coroutine.wrap(function(...)" + clientScript + "\nend)();" + PatchScriptSource));
        return;
    }

    std::lock_guard<std::mutex> lock(clientsMtx);

    Instance* PlayerListManager = nullptr;
    {
        Instance* PlayerList = Modules->FindFirstChild("PlayerList");
        if (!PlayerList) {
            std::cerr << "[!] Modules->PlayerList not found\n";
            return;
        }
        PlayerListManager = PlayerList->FindFirstChild("PlayerListManager");
    }
    if (!PlayerListManager) {
        std::cerr << "[!] PlayerListManager not found\n";
        return;
    }

    Instance* dropDown = RobloxGui->FindFirstChild("DropDownFullscreenFrame");
    if (dropDown) { delete dropDown; }
    if (!dropDown) { // If the player is joining the game
        RobloxGui->WaitForChildAddress("DropDownFullscreenFrame");
        if (DataModel.Name() == "App") { // In case the player leaves the join page
            PatchScript->SetBytecode(Compile("coroutine.wrap(function(...)" + clientScript + "\nend)();" + PatchScriptSource));
            return;
        }
        Sleep(4500);
    }

    Instance* VRNavigation = nullptr;
    {
        Instance* StarterPlayer = DataModel.FindFirstChildOfClass("StarterPlayer");
        if (!StarterPlayer) {
            std::cerr << "[!] Game->StarterPlayer not found\n";
            return;
        }
        Instance* StarterPlayerScripts = StarterPlayer->FindFirstChild("StarterPlayerScripts");
        if (!StarterPlayerScripts) {
            std::cerr << "[!] StarterPlayer->StarterPlayerScripts not found\n";
            return;
        }
        Instance* PlayerModule = StarterPlayerScripts->FindFirstChild("PlayerModule");
        if (!PlayerModule) {
            std::cerr << "[!] StarterPlayerScripts->PlayerModule not found\n";
            return;
        }
        Instance* ControlModule = PlayerModule->FindFirstChild("ControlModule");
        if (!ControlModule) {
            std::cerr << "[!] PlayerModule->ControlModule not found\n";
            return;
        }
        VRNavigation = ControlModule->FindFirstChild("VRNavigation");
    }

    if (!VRNavigation) {
        std::cerr << "[!] VRNavigation not found (Is the client '" + Username + "' already attached?)\n";
        return;
    }

    VRNavigation->UnlockModule();
    write_memory<std::uintptr_t>(PlayerListManager->Self() + offsets::This, VRNavigation->Self(), handle);

    VRNavigation->SetBytecode(Compile("script.Parent=nil;coroutine.wrap(function(...)" + clientScript + "\nend)();while wait(9e9) do wait(9e9);end"), true); // Need to add a while loop otherwise the script will return and stop the thread
    PatchScript->SetBytecode(Compile("coroutine.wrap(function(...)" + clientScript + "\nend)();" + PatchScriptSource)); // For later use (when player leaves game/teleports)

    HWND robloxHWND = GetHWNDFromPID(GetProcessId(handle));
    if (!robloxHWND) {
        std::cerr << "[!] Roblox HWND not found\n";
        return;
    }

    std::thread([robloxHWND]() {
        HWND previousHWND = GetForegroundWindow();

        while (GetForegroundWindow() != robloxHWND) {
            SetForegroundWindow(robloxHWND);
            Sleep(5);
        }

        keybd_event(VK_ESCAPE, MapVirtualKey(VK_ESCAPE, 0), KEYEVENTF_SCANCODE, 0);
        keybd_event(VK_ESCAPE, MapVirtualKey(VK_ESCAPE, 0), KEYEVENTF_SCANCODE | KEYEVENTF_KEYUP, 0);

        Sleep(100);

        if (previousHWND != nullptr) {
            SetForegroundWindow(previousHWND);
        }
    }).detach();

    Sleep(800);

    write_memory<std::uintptr_t>(PlayerListManager->Self() + offsets::This, PlayerListManager->Self(), handle);
}

inline std::uintptr_t RBXClient::FetchDataModel() const
{
    HMODULE mods[1024]; DWORD needed;
    if (!EnumProcessModules(handle, mods, sizeof(mods), &needed)) return 0;
    std::uintptr_t base = (std::uintptr_t)mods[0];
    fprintf(stderr, "[*] Base: 0x%llx\n", (unsigned long long)base);

    std::uintptr_t ts = read_memory<std::uintptr_t>(base + 0x8B5CEE8, handle);
    if (ts < 0x10000) { fprintf(stderr, "[!] TS invalid\n"); return 0; }
    fprintf(stderr, "[+] TS: 0x%llx\n", (unsigned long long)ts);
    
    std::uintptr_t jobStart = read_memory<std::uintptr_t>(ts + 0xC8, handle);
    std::uintptr_t jobEnd = read_memory<std::uintptr_t>(ts + 0xD0, handle);
    fprintf(stderr, "[*] Jobs: 0x%llx - 0x%llx\n", (unsigned long long)jobStart, (unsigned long long)jobEnd);
    
    if (jobStart == 0 || jobEnd == 0 || jobStart >= jobEnd) return 0;
    
    int jobCount = 0;
    for (std::uintptr_t j = jobStart; j < jobEnd && j < jobStart + 0x4000; j += 8) {
        std::uintptr_t jp = read_memory<std::uintptr_t>(j, handle);
        if (jp < 0x10000 || jp > 0x7FFFFFFFFFFF) continue;
        
        std::uintptr_t namePtr = read_memory<std::uintptr_t>(jp + 0x18, handle);
        std::string jn = functions::ReadRobloxString(namePtr, handle);
        
        if (!jn.empty() && jn.length() < 60) {
            fprintf(stderr, "  job[%d]: %s\n", jobCount, jn.c_str());
        }
        jobCount++;
        
        if (jn.find("Render") != std::string::npos) {
            fprintf(stderr, "[+] RenderJob at 0x%llx\n", (unsigned long long)jp);
            
            std::uintptr_t fdm = read_memory<std::uintptr_t>(jp + 0x38, handle);
            fprintf(stderr, "[*] FDM: 0x%llx\n", (unsigned long long)fdm);
            
            if (fdm > 0x10000 && fdm < 0x7FFFFFFFFFFF) {
                std::uintptr_t dm = read_memory<std::uintptr_t>(fdm + 0x1F8, handle);
                fprintf(stderr, "[+] DM: 0x%llx\n", (unsigned long long)dm);
                if (dm > 0x10000 && dm < 0x7FFFFFFFFFFF) return dm;
            }
            
            std::uintptr_t dm2 = read_memory<std::uintptr_t>(jp + 0x1F0, handle);
            fprintf(stderr, "[*] DM2 (direct): 0x%llx\n", (unsigned long long)dm2);
            if (dm2 > 0x10000) return dm2;
        }
    }
    fprintf(stderr, "[*] Total jobs checked: %d\n", jobCount);
    
    // Fallback: static FDM pointer
    std::uintptr_t fdm = read_memory<std::uintptr_t>(base + 0x8DC2258, handle);
    fprintf(stderr, "[*] Static FDM: 0x%llx\n", (unsigned long long)fdm);
    if (fdm > 0x10000 && fdm < 0x7FFFFFFFFFFF) {
        std::uintptr_t dm = read_memory<std::uintptr_t>(fdm + 0x1F8, handle);
        fprintf(stderr, "[+] DM from static: 0x%llx\n", (unsigned long long)dm);
        if (dm > 0x10000 && dm < 0x7FFFFFFFFFFF) return dm;
    }
    
    fprintf(stderr, "[!] No DataModel found\n");
    return 0;
}

void RBXClient::execute(const std::string& source) const {
    std::uintptr_t dataModel_Address = FetchDataModel();
    if (dataModel_Address == 0) return;

    Instance DataModel(dataModel_Address, handle);
    Instance* CoreGui = DataModel.FindFirstChild("CoreGui");
    if (!CoreGui) return;

    Instance* xenoFolder = CoreGui->FindFirstChild("Xeno");
    if (!xenoFolder)
        return;

    Instance* xenoModules = xenoFolder->FindFirstChild("Scripts");
    if (!xenoModules)
        return;

    Instance* xenoModule = xenoModules->FindFirstChildOfClass("ModuleScript");
    if (!xenoModule)
        return;

    xenoModule->SetBytecode(Compile("return{[\"x e n o\"]=function(...)function c(x,y)z=x;for i,v in y do z[i]=v;end;return z;end;setfenv(1,c(getfenv(1),shared.Xeno))setfenv(0,c(getfenv(0),shared.Xeno))for i,f in shared.Xeno do getfenv(0)[i] = f;getfenv(1)[i]=f;end;setmetatable(shared.Xeno,{__newindex=function(t,i,v)rawset(t,i,v);for i,v in t do getfenv()[i]=v;end;end,__index=function(t,val)return rawget(t,val);end});" + source + "\nend};"), true);
    xenoModule->UnlockModule();

    delete xenoModule;
    delete xenoModules;
    delete xenoFolder;
    delete CoreGui;
}

bool RBXClient::loadstring(const std::string& source, std::string& script_name, std::string& chunk_name) const {
    std::uintptr_t dataModel_Address = FetchDataModel();
    if (dataModel_Address == 0) return false;

    Instance DataModel(dataModel_Address, handle);
    Instance* CoreGui = DataModel.FindFirstChild("CoreGui");
    if (!CoreGui) return false;

    Instance* xenoFolder = CoreGui->FindFirstChild("Xeno");
    if (!xenoFolder)
        return false;

    Instance* cloned_module = xenoFolder->FindFirstChild(script_name);
    if (!cloned_module || cloned_module->Self() == 0)
        return false;

    cloned_module->SetBytecode(Compile("return{[ [[" + chunk_name + "]] ] = function(...)function c(x,y)z=x;for i,v in y do z[i]=v;end;return z;end;setfenv(1,c(getfenv(1),shared.Xeno))setfenv(0,c(getfenv(0),shared.Xeno))for i,f in shared.Xeno do getfenv(0)[i] = f;getfenv(1)[i]=f;end;setmetatable(shared.Xeno,{__newindex=function(t,i,v)rawset(t,i,v);for i,v in t do getfenv()[i]=v;end;end,__index=function(t,val)return rawget(t,val);end});" + source + "\nend};"), true);
    cloned_module->UnlockModule();

    delete cloned_module;
    delete xenoFolder;
    delete CoreGui;
    return true;
}

void RBXClient::UnlockModule(const std::string& script_name) const {
    std::uintptr_t dataModel_Address = FetchDataModel();
    if (dataModel_Address == 0) return;

    Instance DataModel(dataModel_Address, handle);
    Instance* CoreGui = DataModel.FindFirstChild("CoreGui");
    if (!CoreGui) return;

    Instance* xenoFolder = CoreGui->FindFirstChild("Xeno");
    if (!xenoFolder)
        return;

    Instance* cloned_module = xenoFolder->FindFirstChild(script_name);
    if (!cloned_module || cloned_module->Self() == 0) {
        delete cloned_module;
        delete xenoFolder;
        delete CoreGui;
        return;
    }

    cloned_module->UnlockModule();
    delete cloned_module;
    delete xenoFolder;
    delete CoreGui;
}

std::string RBXClient::GetBytecode(const std::string& objectval_name) const {
    std::uintptr_t scriptPtr = RBXClient::GetObjectValuePtr(objectval_name);
    if (scriptPtr == 0)
        return "";

    return Instance(scriptPtr, handle).GetBytecode();
}

std::uintptr_t RBXClient::GetObjectValuePtr(const std::string& objectval_name) const
{
    std::uintptr_t dataModel_Address = FetchDataModel();
    if (dataModel_Address == 0) return 0;

    Instance DataModel(dataModel_Address, handle);
    Instance* CoreGui = DataModel.FindFirstChild("CoreGui");
    if (!CoreGui) return 0;

    Instance* xenoFolder = CoreGui->FindFirstChild("Xeno");
    if (!xenoFolder)
        return 0;

    Instance* objectValContainer = xenoFolder->FindFirstChild("Instance Pointers");
    if (!objectValContainer) {
        delete xenoFolder;
        delete CoreGui;
        return 0;
    }

    std::uintptr_t objectValue = objectValContainer->FindFirstChildAddress(objectval_name);
    std::uintptr_t result = 0;
    if (objectValue != 0)
        result = read_memory<std::uintptr_t>(objectValue + offsets::ObjectValue, handle);

    delete objectValContainer;
    delete xenoFolder;
    delete CoreGui;
    return result;
}

void RBXClient::SpoofInstance(const std::string& objectval_name, std::uintptr_t new_address) const
{
    std::uintptr_t instancePtr = RBXClient::GetObjectValuePtr(objectval_name);
    if (instancePtr == 0)
        return;

    write_memory<std::uintptr_t>(instancePtr + offsets::This, new_address, handle);
}

std::vector<DWORD> GetRobloxClients()
{
    std::vector<DWORD> clients = {};

    HANDLE snap_shot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
    if (snap_shot == INVALID_HANDLE_VALUE)
        return clients;
    PROCESSENTRY32W entry = { sizeof(PROCESSENTRY32W) };

    if (Process32FirstW(snap_shot, &entry) == TRUE) {
        if (_wcsicmp(L"RobloxPlayerBeta.exe", entry.szExeFile) == 0) {
            clients.push_back(entry.th32ProcessID);
        }
        while (Process32NextW(snap_shot, &entry) == TRUE) {
            if (_wcsicmp(L"RobloxPlayerBeta.exe", entry.szExeFile) == 0) {
                clients.push_back(entry.th32ProcessID);
            }
        }
    }

    CloseHandle(snap_shot);
    return clients;
}

std::uintptr_t GetRV(HANDLE handle)
{
    std::filesystem::path localAppData = std::filesystem::temp_directory_path()
        .parent_path()
        .parent_path();

    std::filesystem::path logs = localAppData /= "Roblox";
    logs /= "logs";

    if (!std::filesystem::is_directory(logs)) {
        std::cerr << "[!] Roblox logs directory not found\n";
        return 0;
    }

    int tries = 5;
    while (tries >= 1) {
        tries -= 1;
        std::vector<std::filesystem::path> logFiles;

        for (const std::filesystem::directory_entry& entry : std::filesystem::directory_iterator(logs)) {
            std::filesystem::path path = entry.path();
            if (entry.is_regular_file() && path.extension() == ".log")
                logFiles.push_back(path);
        }

        if (logFiles.empty()) {
            std::cerr << "[!] No Roblox log files found\n";
            return 0;
        }

        std::sort(logFiles.begin(), logFiles.end(), [](const auto& x, const auto& y) {
            return std::filesystem::last_write_time(x) > std::filesystem::last_write_time(y);
        });

        std::vector<std::filesystem::path> lockedFiles;
        for (const std::filesystem::path& logPath : logFiles) {
            try {
                std::filesystem::remove(logPath);
            }
            catch (const std::filesystem::filesystem_error& e) {
                lockedFiles.push_back(logPath);
            }
        }
        if (lockedFiles.empty()) {
            std::cerr << "[!] No log file is being used by another process\n";
            return 0;
        }

        for (const std::filesystem::path& logPath : lockedFiles) {
            std::ifstream logFile(logPath);
            if (!logFile.is_open()) {
                continue;
            }

            std::string renderview;
            std::stringstream buffer;
            buffer << logFile.rdbuf();
            std::string content = buffer.str();

            std::regex rgx(R"(\bSurfaceController\[_:1\]::initialize view\((.*?)\))");
            std::smatch match;

            if (std::regex_search(content, match, rgx)) {
                if (match.size() <= 1)
                    continue;
                renderview = match[1].str();
            }

            std::uintptr_t renderviewAddress = std::strtoull(renderview.c_str(), nullptr, 16);
            std::uintptr_t fakeDataModel = read_memory<std::uintptr_t>(renderviewAddress + 0x118, handle);
            if (fakeDataModel != 0) {
                //return fakeDataModel + 0x1d8; // theo: FakeDataModel::RealDataModel (real datamodel)
                return renderviewAddress;
            }
        }

        Sleep(1000);
    }
    return 0;
}

static std::string compress(const std::string_view bytecode)
{
    const auto data_size = bytecode.size();
    const auto max_size = ZSTD_compressBound(data_size);
    auto buffer = std::vector<char>(max_size + 8);

    memcpy(&buffer[0], "RSB1", 4);
    memcpy(&buffer[4], &data_size, sizeof(data_size));

    const auto compressed_size = ZSTD_compress(&buffer[8], max_size, bytecode.data(), data_size, ZSTD_maxCLevel());
    if (ZSTD_isError(compressed_size))
        return "";

    const auto size = compressed_size + 8;
    const auto key = XXH32(buffer.data(), size, 42u);
    const auto bytes = reinterpret_cast<const uint8_t*>(&key);

    for (auto i = 0u; i < size; ++i)
        buffer[i] ^= bytes[i % 4] + i * 41u;

    return std::string(buffer.data(), size);
}

std::string decompress(const std::string& compressed) {
    const uint8_t bytecodeSignature[4] = { 'R', 'S', 'B', '1' };
    const int bytecodeHashMultiplier = 41;
    const int bytecodeHashSeed = 42;

    if (compressed.size() < 8)
        return "Compressed data too short";

    std::vector<uint8_t> compressedData(compressed.begin(), compressed.end());
    std::vector<uint8_t> headerBuffer(4);

    for (size_t i = 0; i < 4; ++i) {
        headerBuffer[i] = compressedData[i] ^ bytecodeSignature[i];
        headerBuffer[i] = (headerBuffer[i] - i * bytecodeHashMultiplier) % 256;
    }

    for (size_t i = 0; i < compressedData.size(); ++i) {
        compressedData[i] ^= (headerBuffer[i % 4] + i * bytecodeHashMultiplier) % 256;
    }

    uint32_t hashValue = 0;
    for (size_t i = 0; i < 4; ++i) {
        hashValue |= headerBuffer[i] << (i * 8);
    }

    uint32_t rehash = XXH32(compressedData.data(), compressedData.size(), bytecodeHashSeed);
    if (rehash != hashValue)
        return "Hash mismatch during decompression";

    uint32_t decompressedSize = 0;
    for (size_t i = 4; i < 8; ++i) {
        decompressedSize |= compressedData[i] << ((i - 4) * 8);
    }

    compressedData = std::vector<uint8_t>(compressedData.begin() + 8, compressedData.end());
    std::vector<uint8_t> decompressed(decompressedSize);

    size_t const actualDecompressedSize = ZSTD_decompress(decompressed.data(), decompressedSize, compressedData.data(), compressedData.size());
    if (ZSTD_isError(actualDecompressedSize))
        return "ZSTD decompression error: " + std::string(ZSTD_getErrorName(actualDecompressedSize));

    decompressed.resize(actualDecompressedSize);
    return std::string(decompressed.begin(), decompressed.end());
}

std::string compilable(const std::string& source) {
    static bytecode_encoder_t encoder = bytecode_encoder_t();
    std::string bytecode = Luau::compile(source, {}, {}, &encoder);
    if (bytecode[0] == '\0') {
        bytecode.erase(std::remove(bytecode.begin(), bytecode.end(), '\0'), bytecode.end());
        return bytecode;
    }
    return "success";
}

std::string Compile(const std::string& source)
{
    static bytecode_encoder_t encoder = bytecode_encoder_t();
    const std::string bytecode = Luau::compile(source, {}, {}, &encoder);

    if (bytecode[0] == '\0') {
        std::string bytecodeP = bytecode;
        bytecodeP.erase(std::remove(bytecodeP.begin(), bytecodeP.end(), '\0'), bytecodeP.end());
        std::cerr << "Byecode compile failed: " << bytecodeP << std::endl;
    }

    return compress(bytecode);
}

static BOOL CALLBACK EnumWindowsProcMy(HWND hwnd, LPARAM lParam)
{
    DWORD lpdwProcessId;
    GetWindowThreadProcessId(hwnd, &lpdwProcessId);

    std::pair<DWORD, HWND*>* params = reinterpret_cast<std::pair<DWORD, HWND*>*>(lParam);
    DWORD targetProcessId = params->first;
    HWND* resultHWND = params->second;

    if (lpdwProcessId == targetProcessId)
    {
        *resultHWND = hwnd;
        return FALSE;
    }

    return TRUE;
}

HWND GetHWNDFromPID(DWORD process_id) {
    HWND hwnd = nullptr;
    std::pair<DWORD, HWND*> params(process_id, &hwnd);

    EnumWindows(EnumWindowsProcMy, reinterpret_cast<LPARAM>(&params));

    return hwnd;
}

template<typename T>
T read_memory(std::uintptr_t address, HANDLE handle)
{
    T value = 0;
    MEMORY_BASIC_INFORMATION bi;

    VirtualQueryEx(handle, reinterpret_cast<LPCVOID>(address), &bi, sizeof(bi));

    NtReadVirtualMemory(handle, reinterpret_cast<LPCVOID>(address), &value, sizeof(value), nullptr);

    PVOID baddr = bi.AllocationBase;
    SIZE_T size = bi.RegionSize;
    NtUnlockVirtualMemory(handle, &baddr, &size, 1);

    return value;
}

template <typename T>
bool write_memory(std::uintptr_t address, const T& value, HANDLE handle)
{
    SIZE_T bytesWritten;
    DWORD oldProtection;

    if (!VirtualProtectEx(handle, reinterpret_cast<LPVOID>(address), sizeof(value), PAGE_READWRITE, &oldProtection)) {
        return false;
    }

    if (NtWriteVirtualMemory(handle, reinterpret_cast<PVOID>(address), (PVOID)&value, sizeof(value), &bytesWritten) || bytesWritten != sizeof(value)) {
        return false;
    }

    DWORD d;
    if (!VirtualProtectEx(handle, reinterpret_cast<LPVOID>(address), sizeof(value), oldProtection, &d)) {
        return false;
    }

    return true;
}