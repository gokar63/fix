// Xeno Executor — Console Mode (standalone exe)
// Based on ashkirtison's Open-Source-External-Script-Executor
// Offsets updated to theo's version-ddf602d9cfe44005

#include <windows.h>
#include <cstdio>
#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <fstream>
#include <sstream>
#include <memory>

#include "worker.hpp"
#include "ntdll.h"

std::vector<std::shared_ptr<RBXClient>> Clients;
std::mutex clientsMtx;

static std::unordered_set<DWORD> closedClients;
static std::unordered_set<DWORD> initializingClients;

// Embedded client script — replaces resource loading
// This is the Xeno client runtime that sets up shared.Xeno environment
const char* XENO_CLIENT_SCRIPT = R"LUA(
local HttpService = game:GetService("HttpService")
local RunService = game:GetService("RunService")

shared.Xeno = shared.Xeno or {}

-- Setup environment
local env = shared.Xeno
env.game = game
env.workspace = workspace
env.script = script

-- Core functions
env.getgenv = function() return env end
env.getrenv = function() return getfenv(0) end
env.identifyexecutor = function() return "Xeno", "1.0.0-VANTA" end
env.getexecutorname = function() return "Xeno" end

-- Instance utilities
env.fireclickdetector = function(detector, distance)
    if detector and detector:IsA("ClickDetector") then
        fireclickdetector(detector, distance or 0)
    end
end

env.gethui = function()
    return game:GetService("CoreGui")
end

env.getinstances = function()
    return game:GetDescendants()
end

env.getnilinstances = function()
    local instances = {}
    for _, v in pairs(game:GetDescendants()) do
        if v.Parent == nil then
            table.insert(instances, v)
        end
    end
    return instances
end

-- HTTP
env.request = function(options)
    local response = HttpService:RequestAsync(options)
    return response
end
env.http_request = env.request

-- Wait for Xeno folder setup
local CoreGui = game:GetService("CoreGui")
local xenoFolder = Instance.new("Folder")
xenoFolder.Name = "Xeno"
xenoFolder.Parent = CoreGui

local scriptsFolder = Instance.new("Folder")
scriptsFolder.Name = "Scripts"
scriptsFolder.Parent = xenoFolder

local instancePointers = Instance.new("Folder")
instancePointers.Name = "Instance Pointers"
instancePointers.Parent = xenoFolder

-- Module for script execution
local execModule = Instance.new("ModuleScript")
execModule.Name = "XenoModule"
execModule.Parent = scriptsFolder

-- Listen for module changes (execution signal)
local lastSource = ""
RunService.Heartbeat:Connect(function()
    pcall(function()
        local modules = scriptsFolder:GetChildren()
        for _, mod in pairs(modules) do
            if mod:IsA("ModuleScript") then
                local success, result = pcall(require, mod)
                if success and type(result) == "table" then
                    for name, func in pairs(result) do
                        if type(func) == "function" then
                            local ok, err = pcall(func)
                            if not ok then
                                warn("[Xeno] Error: " .. tostring(err))
                            end
                        end
                    end
                end
            end
        end
    end)
end)

print("[Xeno] Client loaded - VANTA build")
)LUA";

static void newClient(DWORD pid) {
    if (closedClients.find(pid) != closedClients.end()) return;
    initializingClients.insert(pid);
    
    printf("[*] Initializing client PID %lu...\n", pid);
    auto client = std::make_shared<RBXClient>(pid);
    
    if (client->Username.empty()) {
        printf("[!] Failed to init client %lu\n", pid);
        closedClients.insert(pid);
        initializingClients.erase(pid);
        return;
    }
    
    std::string username;
    {
        std::lock_guard<std::mutex> lock(clientsMtx);
        Clients.push_back(client);
        initializingClients.erase(pid);
        username = Clients.back()->Username;
    }
    printf("[+] Attached to: %s\n", username.c_str());
}

static void scanLoop() {
    while (true) {
        std::vector<DWORD> pids = GetRobloxClients();
        std::unordered_set<DWORD> current(pids.begin(), pids.end());
        {
            std::lock_guard<std::mutex> lock(clientsMtx);
            Clients.erase(std::remove_if(Clients.begin(), Clients.end(),
                [&](const std::shared_ptr<RBXClient>& c) {
                    if (current.find(c->PID) == current.end() || !c->isProcessAlive()) {
                        closedClients.insert(c->PID);
                        printf("[*] Client disconnected: %s\n", c->Username.c_str());
                        return true;
                    }
                    return false;
                }), Clients.end());

            for (DWORD pid : pids) {
                if (std::none_of(Clients.begin(), Clients.end(),
                    [&](const auto& c) { return c->PID == pid; }) 
                    && initializingClients.find(pid) == initializingClients.end()) {
                    std::thread(newClient, pid).detach();
                }
            }
        }
        Sleep(500);
    }
}

static std::string readFile(const char* path) {
    std::ifstream f(path);
    if (!f) return "";
    return std::string((std::istreambuf_iterator<char>(f)), {});
}

static bool enableDebugPrivilege() {
    HANDLE token;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token))
        return false;
    TOKEN_PRIVILEGES tp{};
    LookupPrivilegeValueA(nullptr, "SeDebugPrivilege", &tp.Privileges[0].Luid);
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    AdjustTokenPrivileges(token, FALSE, &tp, sizeof(tp), nullptr, nullptr);
    CloseHandle(token);
    return GetLastError() == ERROR_SUCCESS;
}

int main() {
    SetConsoleTitleA("VANTA Xeno Executor");
    printf("\n");
    printf("  ╔══════════════════════════════════╗\n");
    printf("  ║   VANTA — Xeno Lua Executor      ║\n");
    printf("  ║   Offsets: theo v-ddf602d9        ║\n");
    printf("  ╚══════════════════════════════════╝\n\n");

    if (enableDebugPrivilege())
        printf("[+] SeDebugPrivilege enabled\n");
    else
        printf("[!] SeDebugPrivilege failed — run as Administrator\n");

    HMODULE ntdll = LoadLibraryA("ntdll.dll");
    if (!ntdll) {
        printf("[!] ntdll.dll load failed\n");
        system("pause");
        return 1;
    }
    NTDLL_INIT_FCNS(ntdll);
    printf("[+] NTDLL functions resolved\n");

    // Start scanner
    printf("[*] Scanning for Roblox clients...\n");
    printf("[*] Launch Roblox and join a game\n\n");
    std::thread(scanLoop).detach();

    // REPL
    printf("Commands:\n");
    printf("  Type Lua script, then ##run to execute on all clients\n");
    printf("  ##file path.lua  — execute a file\n");
    printf("  ##list           — show attached clients\n");
    printf("  ##clear          — clear buffer\n");
    printf("  ##quit           — exit\n\n");

    std::string buffer;
    char line[8192];

    while (true) {
        printf(buffer.empty() ? "lua> " : "...> ");
        if (!fgets(line, sizeof(line), stdin)) break;

        std::string l(line);
        while (!l.empty() && (l.back() == '\n' || l.back() == '\r')) l.pop_back();

        if (l == "##quit" || l == "##exit") break;

        if (l == "##list") {
            std::lock_guard<std::mutex> lock(clientsMtx);
            if (Clients.empty()) {
                printf("[*] No clients attached\n");
            } else {
                for (size_t i = 0; i < Clients.size(); i++) {
                    printf("  [%zu] %s (PID %lu)\n", i, Clients[i]->Username.c_str(), Clients[i]->PID);
                }
            }
            continue;
        }

        if (l == "##clear") { buffer.clear(); printf("[*] cleared\n"); continue; }

        if (l.substr(0, 7) == "##file ") {
            auto src = readFile(l.substr(7).c_str());
            if (src.empty()) { printf("[!] can't read: %s\n", l.substr(7).c_str()); continue; }
            printf("[*] executing %s (%zu bytes)...\n", l.substr(7).c_str(), src.size());
            std::lock_guard<std::mutex> lock(clientsMtx);
            for (auto& c : Clients) {
                c->execute(src);
                printf("[+] executed on %s\n", c->Username.c_str());
            }
            continue;
        }

        if (l == "##run") {
            if (buffer.empty()) { printf("[!] empty\n"); continue; }
            std::lock_guard<std::mutex> lock(clientsMtx);
            if (Clients.empty()) {
                printf("[!] no clients attached — launch Roblox first\n");
            } else {
                for (auto& c : Clients) {
                    c->execute(buffer);
                    printf("[+] executed on %s\n", c->Username.c_str());
                }
            }
            buffer.clear();
            continue;
        }

        buffer += l + "\n";
    }

    return 0;
}
