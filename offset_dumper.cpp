// language: C++17, file: offset_dumper.cpp, target: Windows 11, MSVC
// VANTA Offset Extractor — finds all Roblox offsets for the DLL hack
// Outputs offsets.h that the DLL #includes

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
#include <filesystem>
#include <set>
#include <map>
#include <algorithm>

// ================================================================
// HELPERS
// ================================================================
static DWORD find_pid(const wchar_t* name) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32W pe{}; pe.dwSize = sizeof(pe); DWORD pid = 0;
    if (Process32FirstW(snap, &pe)) do {
        if (!_wcsicmp(pe.szExeFile, name)) { pid = pe.th32ProcessID; break; }
    } while (Process32NextW(snap, &pe));
    CloseHandle(snap);
    return pid;
}

static void enable_debug() {
    HANDLE t;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &t)) return;
    TOKEN_PRIVILEGES tp{};
    LookupPrivilegeValueA(nullptr, "SeDebugPrivilege", &tp.Privileges[0].Luid);
    tp.PrivilegeCount = 1; tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    AdjustTokenPrivileges(t, FALSE, &tp, sizeof(tp), nullptr, nullptr);
    CloseHandle(t);
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
    ReadProcessMemory(h, (LPCVOID)buf, t, (len < 200 ? (SIZE_T)len : 200), &rd);
    return std::string(t, rd);
}

struct MemRegion {
    uintptr_t base;
    size_t size;
    std::vector<uint8_t> data;
};

// ================================================================
// FOUND OFFSETS
// ================================================================
struct FoundOffsets {
    // Pointers (absolute or relative to module base)
    uintptr_t render_view_ptr = 0;        // RenderView* — from TaskScheduler
    uintptr_t fake_datamodel_ptr = 0;     // FakeDataModel* pointer

    // Instance offsets
    int instance_name = -1;
    int instance_children = -1;
    int instance_parent = -1;
    int instance_class_descriptor = 0x18;
    int class_descriptor_name = 0x8;

    // DataModel
    int fdm_to_datamodel = -1;

    // Players
    int players_local_player = -1;

    // TaskScheduler
    int ts_jobs_start = -1;
    int ts_jobs_end = -1;

    // Script offsets (from existing worker.hpp defaults)
    int localscript_embedded = 0x190;
    int modulescript_embedded = 0x138;
    int bytecode_ptr = 0x10;
    int bytecode_size = 0x28;

    // Camera (common offsets to probe)
    int camera_viewmatrix = -1;

    // Humanoid
    int humanoid_health = -1;

    // CFrame/Position on BasePart
    int basepart_cframe = -1;

    bool found_ts = false;
    bool found_fdm = false;
    bool found_lp = false;
    std::string local_player_name;
};

static FoundOffsets g_off;

// ================================================================
// SCAN: TaskScheduler
// ================================================================
static void scan_task_scheduler(HANDLE proc, const std::vector<MemRegion>& regions, uintptr_t mod_base) {
    printf("[*] Scanning for TaskScheduler...\n");

    int ts_pairs[][2] = {
        {0xC8, 0xD0}, {0xD0, 0xD8}, {0xD8, 0xE0},
        {0xC0, 0xC8}, {0x1D0, 0x1D8}
    };

    DWORD scan_start = GetTickCount();
    int checked = 0;
    for (auto& reg : regions) {
        if (reg.size < 16) continue;
        // Skip very large non-module regions for TS scan
        if (reg.size > 16 * 1024 * 1024) { checked++; continue; }
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
                    g_off.render_view_ptr = reg.base + off;
                    g_off.ts_jobs_start = p[0];
                    g_off.ts_jobs_end = p[1];
                    g_off.found_ts = true;

                    printf("[+] TaskScheduler found!\n");
                    printf("    Pointer: 0x%llX", (uint64_t)(reg.base + off - mod_base));
                    if (reg.base >= mod_base) printf(" (module+0x%llX)", (uint64_t)(reg.base + off - mod_base));
                    printf("\n");
                    printf("    Jobs: [0x%X, 0x%X] (%d jobs)\n", p[0], p[1], jc);

                    for (uintptr_t j = js; j < je && j < js + 0x1000; j += 8) {
                        uintptr_t jp = rpm<uintptr_t>(proc, j);
                        if (jp < 0x10000) continue;
                        std::string jn = rstr(proc, rpm<uintptr_t>(proc, jp + 0x18));
                        if (!jn.empty()) printf("      %s\n", jn.c_str());
                    }
                    return;
                }
            }
        }
        checked++;
        if (checked % 50 == 0) {
            DWORD elapsed = (GetTickCount() - scan_start) / 1000;
            printf("    %d/%zu regions... (%lus)\n", checked, regions.size(), elapsed);
        }
        // Timeout after 120 seconds
        if ((GetTickCount() - scan_start) > 120000) {
            printf("[!] TaskScheduler scan timeout (120s) — skipping\n");
            break;
        }
    }
    printf("[!] TaskScheduler not found\n");
}

// ================================================================
// SCAN: FakeDataModel + Instance offsets
// ================================================================
static void scan_datamodel(HANDLE proc, const std::vector<MemRegion>& regions, uintptr_t mod_base) {
    printf("\n[*] Scanning for DataModel...\n");

    int dm_list[] = {0x1F8, 0x1D8, 0x1B8, 0x190, 0x1E0, 0x1E8, 0x210, 0x208, 0x200};
    int ch_list[] = {0x78, 0x80, 0x50, 0x70, 0x88};
    int nm_list[] = {0x70, 0x48, 0x68, 0x50, 0x78};

    DWORD dm_scan_start = GetTickCount();
    int checked = 0;
    for (auto& reg : regions) {
        if (reg.size < 16) continue;
        if (reg.size > 16 * 1024 * 1024) { checked++; continue; }
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

                    int known = 0; int found_nm = -1;
                    std::set<std::string> services;
                    for (int i = 0; i < 30; i++) {
                        uintptr_t c = rpm<uintptr_t>(proc, cs + i * 0x10);
                        if (c < 0x10000) continue;
                        for (int no : nm_list) {
                            std::string n = rstr(proc, rpm<uintptr_t>(proc, c + no));
                            if (n == "Workspace" || n == "Players" || n == "Lighting" ||
                                n == "ReplicatedStorage" || n == "StarterGui" || n == "CoreGui" ||
                                n == "SoundService" || n == "StarterPlayer" || n == "Chat") {
                                known++; found_nm = no;
                                services.insert(n);
                                break;
                            }
                        }
                    }

                    if (known >= 4) {
                        g_off.fake_datamodel_ptr = reg.base + off;
                        g_off.fdm_to_datamodel = dm_off;
                        g_off.instance_children = ch_off;
                        g_off.instance_name = found_nm;
                        g_off.found_fdm = true;

                        printf("[+] DataModel found!\n");
                        printf("    FDM Pointer: 0x%llX\n", (uint64_t)(reg.base + off));
                        if (reg.base >= mod_base)
                            printf("    Module offset: 0x%llX\n", (uint64_t)(reg.base + off - mod_base));
                        printf("    FDM→DataModel: 0x%X\n", dm_off);
                        printf("    Instance::Children: 0x%X\n", ch_off);
                        printf("    Instance::Name: 0x%X\n", found_nm);
                        printf("    Services found: ");
                        for (auto& s : services) printf("%s ", s.c_str());
                        printf("\n");

                        // Find Parent offset
                        uintptr_t c0 = rpm<uintptr_t>(proc, cs);
                        if (c0 > 0x10000) {
                            int pp[] = {0x68, 0x60, 0x58, 0x70, 0x48};
                            for (int p : pp) {
                                if (rpm<uintptr_t>(proc, c0 + p) == dm) {
                                    g_off.instance_parent = p;
                                    printf("    Instance::Parent: 0x%X\n", p);
                                    break;
                                }
                            }
                        }

                        // Find LocalPlayer
                        uintptr_t players = 0;
                        for (int i = 0; i < 30; i++) {
                            uintptr_t c = rpm<uintptr_t>(proc, cs + i * 0x10);
                            if (c < 0x10000) continue;
                            if (rstr(proc, rpm<uintptr_t>(proc, c + found_nm)) == "Players") {
                                players = c; break;
                            }
                        }
                        if (players) {
                            int lps[] = {0x130, 0x100, 0x128, 0x138, 0x140, 0x148, 0x118, 0x120, 0x150, 0x108, 0x110};
                            for (int lp : lps) {
                                uintptr_t v = rpm<uintptr_t>(proc, players + lp);
                                if (v > 0x10000 && v < 0x7FFFFFFFFFFF) {
                                    std::string ln = rstr(proc, rpm<uintptr_t>(proc, v + found_nm));
                                    if (!ln.empty() && ln.length() < 30 && ln.length() > 2) {
                                        g_off.players_local_player = lp;
                                        g_off.found_lp = true;
                                        g_off.local_player_name = ln;
                                        printf("    Players::LocalPlayer: 0x%X (\"%s\")\n", lp, ln.c_str());
                                        break;
                                    }
                                }
                            }

                            // Scan for Camera
                            uintptr_t workspace = 0;
                            for (int i = 0; i < 30; i++) {
                                uintptr_t c = rpm<uintptr_t>(proc, cs + i * 0x10);
                                if (c < 0x10000) continue;
                                if (rstr(proc, rpm<uintptr_t>(proc, c + found_nm)) == "Workspace") {
                                    workspace = c; break;
                                }
                            }
                            if (workspace) {
                                // CurrentCamera is usually a child or at a known offset
                                // Probe children for "Camera"
                                uintptr_t wcp = rpm<uintptr_t>(proc, workspace + ch_off);
                                if (wcp > 0x10000) {
                                    uintptr_t wcs = rpm<uintptr_t>(proc, wcp);
                                    for (int i = 0; i < 50; i++) {
                                        uintptr_t c = rpm<uintptr_t>(proc, wcs + i * 0x10);
                                        if (c < 0x10000) continue;
                                        std::string cn = rstr(proc, rpm<uintptr_t>(proc, c + found_nm));
                                        if (cn == "Camera") {
                                            printf("    Camera instance: 0x%llX\n", (uint64_t)c);
                                            // Probe for ViewMatrix (4x4 float matrix = 64 bytes)
                                            // Usually at offset 0x120-0x1F0
                                            for (int vm = 0x100; vm <= 0x200; vm += 8) {
                                                float test[4];
                                                ReadProcessMemory(proc, (LPCVOID)(c + vm), test, 16, nullptr);
                                                // ViewMatrix row should have values between -1 and 1 for rotation part
                                                if (fabsf(test[0]) <= 1.1f && fabsf(test[1]) <= 1.1f &&
                                                    fabsf(test[2]) <= 1.1f &&
                                                    (fabsf(test[0]) > 0.001f || fabsf(test[1]) > 0.001f)) {
                                                    // Check if it's a valid rotation matrix
                                                    float row_len = test[0]*test[0] + test[1]*test[1] + test[2]*test[2];
                                                    if (row_len > 0.8f && row_len < 1.2f) {
                                                        g_off.camera_viewmatrix = vm;
                                                        printf("    Camera::ViewMatrix: 0x%X (probable)\n", vm);
                                                        break;
                                                    }
                                                }
                                            }
                                            break;
                                        }
                                    }
                                }

                                // Probe LocalPlayer → Character → HumanoidRootPart → CFrame
                                if (g_off.found_lp) {
                                    uintptr_t lp = rpm<uintptr_t>(proc, players + g_off.players_local_player);
                                    if (lp > 0x10000) {
                                        uintptr_t lcp = rpm<uintptr_t>(proc, lp + ch_off);
                                        if (lcp > 0x10000) {
                                            // Character is in a child property, not children list
                                            // Probe common offsets for Character ref
                                            for (int co = 0xE0; co <= 0x200; co += 8) {
                                                uintptr_t charPtr = rpm<uintptr_t>(proc, lp + co);
                                                if (charPtr < 0x10000 || charPtr > 0x7FFFFFFFFFFF) continue;
                                                // Check if it's a Model with HumanoidRootPart child
                                                uintptr_t charChildren = rpm<uintptr_t>(proc, charPtr + ch_off);
                                                if (charChildren < 0x10000) continue;
                                                uintptr_t charCS = rpm<uintptr_t>(proc, charChildren);
                                                if (charCS < 0x10000) continue;

                                                bool has_hrp = false;
                                                for (int ci = 0; ci < 20; ci++) {
                                                    uintptr_t cc = rpm<uintptr_t>(proc, charCS + ci * 0x10);
                                                    if (cc < 0x10000) continue;
                                                    std::string ccn = rstr(proc, rpm<uintptr_t>(proc, cc + found_nm));
                                                    if (ccn == "HumanoidRootPart") {
                                                        has_hrp = true;
                                                        // Probe CFrame offset on the part
                                                        for (int cf = 0xE0; cf <= 0x200; cf += 8) {
                                                            float pos[3];
                                                            ReadProcessMemory(proc, (LPCVOID)(cc + cf), pos, 12, nullptr);
                                                            // Valid world position: not zero, within reasonable bounds
                                                            if (fabsf(pos[0]) > 1.0f && fabsf(pos[0]) < 50000.0f &&
                                                                fabsf(pos[1]) > -500.0f && fabsf(pos[1]) < 50000.0f &&
                                                                fabsf(pos[2]) > 1.0f && fabsf(pos[2]) < 50000.0f) {
                                                                g_off.basepart_cframe = cf;
                                                                printf("    BasePart::CFrame: 0x%X (probable, pos=%.1f,%.1f,%.1f)\n",
                                                                       cf, pos[0], pos[1], pos[2]);
                                                                break;
                                                            }
                                                        }

                                                        // Find Humanoid sibling
                                                        for (int hi = 0; hi < 20; hi++) {
                                                            uintptr_t hc = rpm<uintptr_t>(proc, charCS + hi * 0x10);
                                                            if (hc < 0x10000) continue;
                                                            std::string hcn = rstr(proc, rpm<uintptr_t>(proc, hc + found_nm));
                                                            if (hcn == "Humanoid") {
                                                                // Probe Health offset
                                                                for (int ho = 0x1C0; ho <= 0x300; ho += 8) {
                                                                    float hp;
                                                                    ReadProcessMemory(proc, (LPCVOID)(hc + ho), &hp, 4, nullptr);
                                                                    if (hp == 100.0f || (hp > 0.0f && hp <= 100.0f)) {
                                                                        g_off.humanoid_health = ho;
                                                                        printf("    Humanoid::Health: 0x%X (value=%.1f)\n", ho, hp);
                                                                        break;
                                                                    }
                                                                }
                                                                break;
                                                            }
                                                        }
                                                        break;
                                                    }
                                                }
                                                if (has_hrp) {
                                                    printf("    Player::Character offset: 0x%X\n", co);
                                                    break;
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        return;
                    }
                }
            }
        }
        checked++;
        if (checked % 50 == 0) {
            DWORD elapsed = (GetTickCount() - dm_scan_start) / 1000;
            printf("    %d/%zu regions... (%lus)\n", checked, regions.size(), elapsed);
        }
        if ((GetTickCount() - dm_scan_start) > 120000) {
            printf("[!] DataModel scan timeout (120s) — skipping\n");
            break;
        }
    }
    printf("[!] DataModel not found\n");
}

// ================================================================
// WRITE offsets.h
// ================================================================
static void write_offsets_header(const char* path) {
    FILE* f = fopen(path, "w");
    if (!f) { printf("[!] Can't write %s\n", path); return; }

    fprintf(f, "// Auto-generated by VANTA Offset Dumper\n");
    fprintf(f, "// Re-run dumper after each Roblox update\n");
    fprintf(f, "#pragma once\n\n");
    fprintf(f, "#include <cstdint>\n\n");
    fprintf(f, "namespace offsets {\n\n");

    fprintf(f, "// === Instance ===\n");
    fprintf(f, "constexpr int Name = 0x%X;\n", g_off.instance_name >= 0 ? g_off.instance_name : 0x70);
    fprintf(f, "constexpr int Children = 0x%X;\n", g_off.instance_children >= 0 ? g_off.instance_children : 0x78);
    fprintf(f, "constexpr int Parent = 0x%X;\n", g_off.instance_parent >= 0 ? g_off.instance_parent : 0x68);
    fprintf(f, "constexpr int ClassDescriptor = 0x%X;\n", g_off.instance_class_descriptor);
    fprintf(f, "constexpr int ClassName = 0x%X;\n\n", g_off.class_descriptor_name);

    fprintf(f, "// === DataModel ===\n");
    fprintf(f, "constexpr int FDM_DataModel = 0x%X; // %s\n",
            g_off.fdm_to_datamodel >= 0 ? g_off.fdm_to_datamodel : 0x1F8,
            g_off.found_fdm ? "FOUND" : "DEFAULT");
    fprintf(f, "constexpr uintptr_t FDM_Pointer = 0x%llXULL; // %s\n\n",
            (uint64_t)g_off.fake_datamodel_ptr,
            g_off.found_fdm ? "absolute address" : "NOT FOUND");

    fprintf(f, "// === Players ===\n");
    fprintf(f, "constexpr int LocalPlayer = 0x%X; // %s\n\n",
            g_off.players_local_player >= 0 ? g_off.players_local_player : 0x130,
            g_off.found_lp ? "FOUND" : "DEFAULT");

    fprintf(f, "// === TaskScheduler ===\n");
    fprintf(f, "constexpr int TS_JobsStart = 0x%X;\n",
            g_off.ts_jobs_start >= 0 ? g_off.ts_jobs_start : 0xC8);
    fprintf(f, "constexpr int TS_JobsEnd = 0x%X;\n",
            g_off.ts_jobs_end >= 0 ? g_off.ts_jobs_end : 0xD0);
    fprintf(f, "constexpr uintptr_t TS_Pointer = 0x%llXULL;\n\n",
            (uint64_t)g_off.render_view_ptr);

    fprintf(f, "// === Camera ===\n");
    fprintf(f, "constexpr int Camera_ViewMatrix = 0x%X; // %s\n\n",
            g_off.camera_viewmatrix >= 0 ? g_off.camera_viewmatrix : 0x150,
            g_off.camera_viewmatrix >= 0 ? "FOUND" : "DEFAULT — verify");

    fprintf(f, "// === BasePart ===\n");
    fprintf(f, "constexpr int CFrame = 0x%X; // %s\n\n",
            g_off.basepart_cframe >= 0 ? g_off.basepart_cframe : 0x110,
            g_off.basepart_cframe >= 0 ? "FOUND" : "DEFAULT — verify");

    fprintf(f, "// === Humanoid ===\n");
    fprintf(f, "constexpr int Health = 0x%X; // %s\n\n",
            g_off.humanoid_health >= 0 ? g_off.humanoid_health : 0x228,
            g_off.humanoid_health >= 0 ? "FOUND" : "DEFAULT — verify");

    fprintf(f, "// === Script ===\n");
    fprintf(f, "constexpr int LocalScript_Embedded = 0x%X;\n", g_off.localscript_embedded);
    fprintf(f, "constexpr int ModuleScript_Embedded = 0x%X;\n", g_off.modulescript_embedded);
    fprintf(f, "constexpr int Bytecode = 0x%X;\n", g_off.bytecode_ptr);
    fprintf(f, "constexpr int BytecodeSize = 0x%X;\n\n", g_off.bytecode_size);

    fprintf(f, "} // namespace offsets\n");
    fclose(f);
    printf("\n[+] Offsets written to: %s\n", path);
}

// ================================================================
// MAIN
// ================================================================
int main() {
    printf("\n");
    printf("  ╔══════════════════════════════════╗\n");
    printf("  ║  VANTA Offset Extractor          ║\n");
    printf("  ║  Generates offsets.h for DLL     ║\n");
    printf("  ╚══════════════════════════════════╝\n\n");

    enable_debug();

    DWORD pid = find_pid(L"RobloxPlayerBeta.exe");
    if (!pid) {
        printf("[!] Roblox not running. Launch Roblox and join a game first.\n");
        system("pause");
        return 1;
    }
    printf("[+] PID: %lu\n", pid);

    HANDLE proc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!proc) {
        printf("[!] OpenProcess failed — run as Administrator\n");
        system("pause");
        return 1;
    }

    HMODULE mods[1024]; DWORD needed;
    EnumProcessModules(proc, mods, sizeof(mods), &needed);
    uintptr_t base = (uintptr_t)mods[0];
    MODULEINFO mi{};
    GetModuleInformation(proc, mods[0], &mi, sizeof(mi));
    printf("[+] Module base: 0x%llX  Size: 0x%llX\n\n", (uint64_t)base, (uint64_t)mi.SizeOfImage);

    // Read all memory
    printf("[*] Reading process memory...\n");
    std::vector<MemRegion> regions;
    size_t total = 0;

    MEMORY_BASIC_INFORMATION mbi{};
    uintptr_t addr = 0x10000;
    uintptr_t mod_end = base + mi.SizeOfImage;
    while (VirtualQueryEx(proc, (LPCVOID)addr, &mbi, sizeof(mbi))) {
        if (mbi.State == MEM_COMMIT &&
            (mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ |
                            PAGE_EXECUTE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_WRITECOPY)) &&
            !(mbi.Protect & PAGE_GUARD)) {
            uintptr_t rbase = (uintptr_t)mbi.BaseAddress;
            uintptr_t rend = rbase + mbi.RegionSize;
            // Prioritize: module regions first, then heap (skip huge regions > 64MB)
            bool in_module = (rbase >= base && rbase < mod_end);
            if (!in_module && mbi.RegionSize > 64 * 1024 * 1024) {
                addr = rend;
                if (addr < rbase) break;
                continue;
            }
            MemRegion r;
            r.base = rbase;
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
    // Sort: module regions first for faster scanning
    std::sort(regions.begin(), regions.end(), [&](const MemRegion& a, const MemRegion& b) {
        bool a_mod = (a.base >= base && a.base < mod_end);
        bool b_mod = (b.base >= base && b.base < mod_end);
        if (a_mod != b_mod) return a_mod;
        return a.base < b.base;
    });
    printf("[+] Read %zu regions, %zu MB\n\n", regions.size(), total / (1024 * 1024));

    // Scan
    scan_task_scheduler(proc, regions, base);
    scan_datamodel(proc, regions, base);

    // Write header
    printf("\n========================================\n");
    if (g_off.found_fdm) {
        printf("[+] DataModel: FOUND\n");
        printf("[+] Instance offsets: Name=0x%X Children=0x%X Parent=0x%X\n",
               g_off.instance_name, g_off.instance_children, g_off.instance_parent);
    } else {
        printf("[!] DataModel: NOT FOUND — using defaults\n");
    }
    if (g_off.found_lp) {
        printf("[+] LocalPlayer: \"%s\" at offset 0x%X\n",
               g_off.local_player_name.c_str(), g_off.players_local_player);
    }
    if (g_off.found_ts) {
        printf("[+] TaskScheduler: FOUND\n");
    }
    printf("========================================\n");

    write_offsets_header("offsets.h");

    printf("\n[+] Done. Now build the DLL with: cmake --build build --target vanta_dll\n");
    printf("[+] offsets.h generated — rebuild DLL after each Roblox update.\n\n");

    CloseHandle(proc);
    system("pause");
    return 0;
}
