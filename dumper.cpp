#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>
#include <string>
#include <fstream>
#include <sstream>
#include <regex>
#include <filesystem>
#include <set>

static DWORD find_pid(const wchar_t* n) {
    HANDLE s = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32W pe{}; pe.dwSize = sizeof(pe); DWORD pid = 0;
    if (Process32FirstW(s, &pe)) do {
        if (!_wcsicmp(pe.szExeFile, n)) { pid = pe.th32ProcessID; break; }
    } while (Process32NextW(s, &pe));
    CloseHandle(s); return pid;
}

template<typename T>
T rpm(HANDLE h, uintptr_t a) {
    T v{}; ReadProcessMemory(h, (LPCVOID)a, &v, sizeof(T), nullptr); return v;
}

std::string rstr(HANDLE h, uintptr_t a) {
    if (a < 0x10000 || a > 0x7FFFFFFFFFFF) return "";
    uint64_t len = rpm<uint64_t>(h, a + 0x10);
    if (len == 0 || len > 200) return "";
    uintptr_t buf = (len > 15) ? rpm<uintptr_t>(h, a) : a;
    if (buf < 0x10000) return "";
    char t[201]{}; SIZE_T rd = 0;
    ReadProcessMemory(h, (LPCVOID)buf, t, (len<200?(SIZE_T)len:200), &rd);
    return std::string(t, rd);
}

static void enable_debug() {
    HANDLE t; if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY, &t)) return;
    TOKEN_PRIVILEGES tp{}; LookupPrivilegeValueA(nullptr, "SeDebugPrivilege", &tp.Privileges[0].Luid);
    tp.PrivilegeCount = 1; tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    AdjustTokenPrivileges(t, FALSE, &tp, sizeof(tp), nullptr, nullptr); CloseHandle(t);
}

struct MemRegion { uintptr_t base; size_t size; std::vector<uint8_t> data; };

int main() {
    printf("\n  VANTA Offset Dumper v3\n  =====================\n\n");
    enable_debug();
    
    DWORD pid = find_pid(L"RobloxPlayerBeta.exe");
    if (!pid) { printf("[!] Roblox not found\n"); system("pause"); return 1; }
    printf("[+] PID: %lu\n", pid);
    
    HANDLE proc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!proc) { printf("[!] OpenProcess failed\n"); system("pause"); return 1; }
    
    HMODULE mods[1024]; DWORD needed;
    EnumProcessModules(proc, mods, sizeof(mods), &needed);
    uintptr_t base = (uintptr_t)mods[0];
    MODULEINFO mi{}; GetModuleInformation(proc, mods[0], &mi, sizeof(mi));
    printf("[+] Base: 0x%llX  Size: 0x%llX\n\n", (uint64_t)base, (uint64_t)mi.SizeOfImage);

    // Method 1: Use VirtualQueryEx to read ALL readable memory in process
    printf("[*] Enumerating readable memory regions...\n");
    std::vector<MemRegion> regions;
    size_t total = 0;
    
    MEMORY_BASIC_INFORMATION mbi{};
    uintptr_t addr = 0x10000;
    while (VirtualQueryEx(proc, (LPCVOID)addr, &mbi, sizeof(mbi))) {
        if (mbi.State == MEM_COMMIT && 
            (mbi.Protect & (PAGE_READONLY|PAGE_READWRITE|PAGE_EXECUTE_READ|PAGE_EXECUTE_READWRITE|PAGE_WRITECOPY|PAGE_EXECUTE_WRITECOPY)) &&
            !(mbi.Protect & PAGE_GUARD)) {
            
            MemRegion r;
            r.base = (uintptr_t)mbi.BaseAddress;
            r.size = mbi.RegionSize;
            r.data.resize(r.size);
            SIZE_T rd = 0;
            if (ReadProcessMemory(proc, mbi.BaseAddress, r.data.data(), r.size, &rd) && rd > 0) {
                r.data.resize(rd);
                r.size = rd;
                total += rd;
                regions.push_back(std::move(r));
            }
        }
        addr = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
        if (addr < (uintptr_t)mbi.BaseAddress) break;
    }
    printf("[+] Read %zu regions, %zu MB total\n\n", regions.size(), total/(1024*1024));

    // Collect all potential pointers from readable regions
    // that point into heap (not module) space
    printf("[*] Scanning all regions for TaskScheduler...\n");
    
    int ts_pairs[][2] = { {0xC8,0xD0}, {0x1D0,0x1D8}, {0xD0,0xD8}, {0xC0,0xC8}, {0xD8,0xE0} };
    bool found_ts = false;
    int region_idx = 0;
    
    for (auto& reg : regions) {
        if (reg.size < 16) continue;
        for (size_t off = 0; off + 8 <= reg.size; off += 8) {
            uintptr_t val = *(uintptr_t*)(reg.data.data() + off);
            if (val < 0x10000 || val > 0x7FFFFFFFFFFF) continue;
            
            for (auto& p : ts_pairs) {
                uintptr_t js = rpm<uintptr_t>(proc, val + p[0]);
                uintptr_t je = rpm<uintptr_t>(proc, val + p[1]);
                if (js == 0 || je == 0 || js >= je) continue;
                if (je - js > 0x10000 || je - js < 0x20) continue;
                
                uintptr_t fj = rpm<uintptr_t>(proc, js);
                if (fj < 0x10000 || fj > 0x7FFFFFFFFFFF) continue;
                std::string name = rstr(proc, rpm<uintptr_t>(proc, fj + 0x18));
                if (name.empty() || name.length() > 60) continue;
                
                int jc = 0; bool render = false;
                for (uintptr_t j = js; j < je && j < js + 0x2000; j += 8) {
                    uintptr_t jp = rpm<uintptr_t>(proc, j);
                    if (jp < 0x10000) continue;
                    std::string jn = rstr(proc, rpm<uintptr_t>(proc, jp + 0x18));
                    if (jn.length() > 1 && jn.length() < 60) {
                        jc++;
                        if (jn.find("Render") != std::string::npos) render = true;
                    }
                }
                
                if (jc >= 5 && render) {
                    uintptr_t offset_from_base = (reg.base + off) - base;
                    printf("[+] TaskScheduler::Pointer = 0x%llX", (uint64_t)offset_from_base);
                    if (reg.base >= base && reg.base < base + mi.SizeOfImage)
                        printf(" (in module)");
                    else
                        printf(" (addr: 0x%llX)", (uint64_t)(reg.base + off));
                    printf("\n");
                    printf("[+] TaskScheduler::JobStart = 0x%X\n", p[0]);
                    printf("[+] TaskScheduler::JobEnd = 0x%X\n", p[1]);
                    printf("    (%d jobs)\n", jc);
                    for (uintptr_t j = js; j < je && j < js + 0x1000; j += 8) {
                        uintptr_t jp = rpm<uintptr_t>(proc, j);
                        if (jp < 0x10000) continue;
                        std::string jn = rstr(proc, rpm<uintptr_t>(proc, jp + 0x18));
                        if (!jn.empty()) printf("      %s\n", jn.c_str());
                    }
                    found_ts = true;
                    goto scan_fdm;
                }
            }
        }
        region_idx++;
        if (region_idx % 100 == 0) printf("    %d/%zu regions...\n", region_idx, regions.size());
    }
    printf("[!] TaskScheduler not found\n");

scan_fdm:
    printf("\n[*] Scanning for FakeDataModel...\n");
    int dm_list[] = {0x1F8,0x1D8,0x1B8,0x190,0x1E0,0x1E8,0x210,0x208,0x200};
    int ch_list[] = {0x78,0x80,0x50,0x70,0x88};
    int nm_list[] = {0x70,0x48,0x68,0x50,0x78};
    region_idx = 0;
    
    for (auto& reg : regions) {
        if (reg.size < 16) continue;
        for (size_t off = 0; off + 8 <= reg.size; off += 8) {
            uintptr_t fdm = *(uintptr_t*)(reg.data.data() + off);
            if (fdm < 0x10000 || fdm > 0x7FFFFFFFFFFF) continue;
            
            for (int dm_off : dm_list) {
                uintptr_t dm = fdm + dm_off;
                for (int ch_off : ch_list) {
                    uintptr_t cp = rpm<uintptr_t>(proc, dm + ch_off);
                    if (cp < 0x10000 || cp > 0x7FFFFFFFFFFF) continue;
                    uintptr_t cs = rpm<uintptr_t>(proc, cp);
                    if (cs < 0x10000 || cs > 0x7FFFFFFFFFFF) continue;
                    
                    int known = 0; int fnm = -1;
                    for (int i = 0; i < 25; i++) {
                        uintptr_t c = rpm<uintptr_t>(proc, cs + i * 0x10);
                        if (c < 0x10000) continue;
                        for (int no : nm_list) {
                            std::string n = rstr(proc, rpm<uintptr_t>(proc, c + no));
                            if (n=="Workspace"||n=="Players"||n=="Lighting"||
                                n=="ReplicatedStorage"||n=="StarterGui"||n=="CoreGui"||
                                n=="SoundService"||n=="StarterPlayer") {
                                known++; fnm = no; break;
                            }
                        }
                    }
                    
                    if (known >= 3) {
                        uintptr_t offset_from_base = (reg.base + off) - base;
                        printf("[+] FakeDataModel::Pointer = 0x%llX", (uint64_t)offset_from_base);
                        if (reg.base >= base && reg.base < base + mi.SizeOfImage)
                            printf(" (in module)");
                        else
                            printf(" (addr: 0x%llX)", (uint64_t)(reg.base + off));
                        printf("\n");
                        printf("[+] FakeDataModel::RealDataModel = 0x%X\n", dm_off);
                        printf("[+] Instance::Children = 0x%X\n", ch_off);
                        if (fnm >= 0) printf("[+] Instance::Name = 0x%X\n", fnm);
                        
                        uintptr_t c0 = rpm<uintptr_t>(proc, cs);
                        if (c0 > 0x10000) {
                            int pp[] = {0x68,0x60,0x58,0x70,0x48};
                            for (int p : pp) {
                                if (rpm<uintptr_t>(proc, c0 + p) == dm) {
                                    printf("[+] Instance::Parent = 0x%X\n", p); break;
                                }
                            }
                            // LocalPlayer
                            uintptr_t players = 0;
                            for (int i = 0; i < 25; i++) {
                                uintptr_t c = rpm<uintptr_t>(proc, cs + i*0x10);
                                if (c < 0x10000) continue;
                                if (rstr(proc, rpm<uintptr_t>(proc, c + fnm)) == "Players") { players = c; break; }
                            }
                            if (players) {
                                int lps[] = {0x130,0x100,0x128,0x138,0x140,0x148,0x118,0x120,0x150,0x108,0x110};
                                for (int lp : lps) {
                                    uintptr_t v = rpm<uintptr_t>(proc, players + lp);
                                    if (v > 0x10000 && v < 0x7FFFFFFFFFFF) {
                                        std::string ln = rstr(proc, rpm<uintptr_t>(proc, v + fnm));
                                        if (!ln.empty() && ln.length() < 30 && ln.length() > 2) {
                                            printf("[+] Player::LocalPlayer = 0x%X (\"%s\")\n", lp, ln.c_str());
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                        goto done;
                    }
                }
            }
        }
        region_idx++;
        if (region_idx % 100 == 0) printf("    %d/%zu regions...\n", region_idx, regions.size());
    }
    printf("[!] FakeDataModel not found\n");

done:
    // Also try to parse log files
    printf("\n[*] Checking Roblox logs...\n");
    try {
        std::filesystem::path logs = std::filesystem::temp_directory_path().parent_path().parent_path();
        logs /= "Roblox"; logs /= "logs";
        if (std::filesystem::is_directory(logs)) {
            for (auto& e : std::filesystem::directory_iterator(logs)) {
                if (!e.is_regular_file() || e.path().extension() != ".log") continue;
                std::ifstream f(e.path());
                if (!f) continue;
                std::stringstream buf; buf << f.rdbuf();
                std::string content = buf.str();
                
                // Search for any hex addresses in SurfaceController lines
                std::regex r1(R"(SurfaceController.*?initialize view\((0x[0-9a-fA-F]+)\))");
                std::regex r2(R"(SurfaceController.*?window\s*=\s*(0x[0-9a-fA-F]+))");
                std::regex r3(R"(RenderView created)");
                std::smatch m;
                if (std::regex_search(content, m, r1)) {
                    printf("[+] Log: initialize view = %s\n", m[1].str().c_str());
                } else if (std::regex_search(content, m, r2)) {
                    printf("[+] Log: window = %s\n", m[1].str().c_str());
                }
                if (std::regex_search(content, m, r3)) {
                    printf("[+] Log: RenderView created found\n");
                }
                break;
            }
        }
    } catch(...) {}

    printf("\n========================================\n");
    printf("Copy ALL text above and send it back.\n");
    printf("========================================\n");
    CloseHandle(proc);
    system("pause");
    return 0;
}
