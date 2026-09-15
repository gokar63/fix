// VANTA Roblox Value Editor — scan + modify any in-game value
// Works like Cheat Engine: find your money amount in memory, change it
// No offsets needed. No injection. Just ReadProcessMemory + WriteProcessMemory.

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>
#include <string>
#include <algorithm>

static DWORD find_pid(const wchar_t* n) {
    HANDLE s = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32W pe{}; pe.dwSize = sizeof(pe); DWORD pid = 0;
    if (Process32FirstW(s, &pe)) do {
        if (!_wcsicmp(pe.szExeFile, n)) { pid = pe.th32ProcessID; break; }
    } while (Process32NextW(s, &pe));
    CloseHandle(s); return pid;
}

static void enable_debug() {
    HANDLE t; if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY, &t)) return;
    TOKEN_PRIVILEGES tp{}; LookupPrivilegeValueA(nullptr, "SeDebugPrivilege", &tp.Privileges[0].Luid);
    tp.PrivilegeCount = 1; tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    AdjustTokenPrivileges(t, FALSE, &tp, sizeof(tp), nullptr, nullptr); CloseHandle(t);
}

struct ScanResult { uintptr_t address; };

// Scan all writable memory for a value
template<typename T>
std::vector<ScanResult> scan_value(HANDLE proc, T target) {
    std::vector<ScanResult> results;
    MEMORY_BASIC_INFORMATION mbi{};
    uintptr_t addr = 0x10000;
    
    while (VirtualQueryEx(proc, (LPCVOID)addr, &mbi, sizeof(mbi))) {
        if (mbi.State == MEM_COMMIT &&
            (mbi.Protect & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE | PAGE_WRITECOPY)) &&
            !(mbi.Protect & PAGE_GUARD) &&
            mbi.Type != MEM_MAPPED) {
            
            std::vector<uint8_t> buf(mbi.RegionSize);
            SIZE_T rd = 0;
            if (ReadProcessMemory(proc, mbi.BaseAddress, buf.data(), mbi.RegionSize, &rd) && rd >= sizeof(T)) {
                for (size_t i = 0; i + sizeof(T) <= rd; i += 4) {
                    if (*(T*)(buf.data() + i) == target) {
                        results.push_back({(uintptr_t)mbi.BaseAddress + i});
                    }
                }
            }
        }
        addr = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
        if (addr < (uintptr_t)mbi.BaseAddress) break;
    }
    return results;
}

// Filter existing results — keep only addresses that still match
template<typename T>
std::vector<ScanResult> filter_value(HANDLE proc, const std::vector<ScanResult>& prev, T target) {
    std::vector<ScanResult> results;
    for (auto& r : prev) {
        T val{};
        if (ReadProcessMemory(proc, (LPCVOID)r.address, &val, sizeof(T), nullptr) && val == target) {
            results.push_back(r);
        }
    }
    return results;
}

// Write value to address
template<typename T>
bool write_value(HANDLE proc, uintptr_t addr, T val) {
    DWORD old;
    VirtualProtectEx(proc, (LPVOID)addr, sizeof(T), PAGE_EXECUTE_READWRITE, &old);
    SIZE_T written = 0;
    BOOL ok = WriteProcessMemory(proc, (LPVOID)addr, &val, sizeof(T), &written);
    VirtualProtectEx(proc, (LPVOID)addr, sizeof(T), old, &old);
    return ok && written == sizeof(T);
}

int main() {
    printf("\n");
    printf("  VANTA Value Editor\n");
    printf("  ==================\n\n");
    
    enable_debug();
    DWORD pid = find_pid(L"RobloxPlayerBeta.exe");
    if (!pid) { printf("[!] Roblox not found\n"); system("pause"); return 1; }
    
    HANDLE proc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!proc) { printf("[!] run as admin\n"); system("pause"); return 1; }
    printf("[+] Roblox PID: %lu\n\n", pid);
    
    printf("=== HOW TO USE ===\n");
    printf("1. Look at your money/coins in game (e.g. 500)\n");
    printf("2. Type that number here and press Enter\n");
    printf("3. Go spend some money in game (e.g. now 450)\n");
    printf("4. Type the NEW number here\n");
    printf("5. Repeat until only 1-5 results remain\n");
    printf("6. Type 'set' to change the value\n");
    printf("==================\n\n");
    
    // Choose data type
    printf("Value type:\n");
    printf("  1. Integer (whole numbers: 100, 500, 9999)\n");
    printf("  2. Double  (decimals: 100.0, 49.5)\n");
    printf("  3. Float   (decimals, less precise)\n");
    printf("Choice [1]: ");
    
    char choice[16]; fgets(choice, sizeof(choice), stdin);
    int type = atoi(choice);
    if (type < 1 || type > 3) type = 1;
    
    const char* type_names[] = { "", "int32", "double", "float" };
    printf("[+] Scanning as: %s\n\n", type_names[type]);
    
    std::vector<ScanResult> results;
    bool first_scan = true;
    char line[256];
    
    while (true) {
        if (results.size() > 0 && results.size() <= 20) {
            printf("\n--- Current matches (%zu) ---\n", results.size());
            for (size_t i = 0; i < results.size(); i++) {
                printf("  [%zu] 0x%llX = ", i, (uint64_t)results[i].address);
                if (type == 1) {
                    int32_t v; ReadProcessMemory(proc, (LPCVOID)results[i].address, &v, 4, nullptr);
                    printf("%d\n", v);
                } else if (type == 2) {
                    double v; ReadProcessMemory(proc, (LPCVOID)results[i].address, &v, 8, nullptr);
                    printf("%.2f\n", v);
                } else {
                    float v; ReadProcessMemory(proc, (LPCVOID)results[i].address, &v, 4, nullptr);
                    printf("%.2f\n", v);
                }
            }
        }
        
        printf("\n> Enter value (or 'set' to write, 'freeze' to lock, 'quit' to exit): ");
        if (!fgets(line, sizeof(line), stdin)) break;
        line[strcspn(line, "\r\n")] = 0;
        
        if (!strcmp(line, "quit") || !strcmp(line, "q")) break;
        
        if (!strcmp(line, "set") || !strcmp(line, "s")) {
            if (results.empty()) { printf("[!] no results to modify\n"); continue; }
            printf("  New value: ");
            fgets(line, sizeof(line), stdin);
            line[strcspn(line, "\r\n")] = 0;
            
            int count = 0;
            if (type == 1) {
                int32_t nv = atoi(line);
                for (auto& r : results) { if (write_value(proc, r.address, nv)) count++; }
            } else if (type == 2) {
                double nv = atof(line);
                for (auto& r : results) { if (write_value(proc, r.address, nv)) count++; }
            } else {
                float nv = (float)atof(line);
                for (auto& r : results) { if (write_value(proc, r.address, nv)) count++; }
            }
            printf("[+] Written to %d addresses. Check in-game!\n", count);
            continue;
        }
        
        if (!strcmp(line, "freeze") || !strcmp(line, "f")) {
            if (results.empty()) { printf("[!] no results\n"); continue; }
            printf("  Value to freeze at: ");
            fgets(line, sizeof(line), stdin);
            line[strcspn(line, "\r\n")] = 0;
            
            printf("[*] Freezing... press Ctrl+C to stop\n");
            while (true) {
                if (type == 1) {
                    int32_t nv = atoi(line);
                    for (auto& r : results) write_value(proc, r.address, nv);
                } else if (type == 2) {
                    double nv = atof(line);
                    for (auto& r : results) write_value(proc, r.address, nv);
                } else {
                    float nv = (float)atof(line);
                    for (auto& r : results) write_value(proc, r.address, nv);
                }
                Sleep(50);
            }
            continue;
        }
        
        if (!strcmp(line, "reset") || !strcmp(line, "r")) {
            results.clear();
            first_scan = true;
            printf("[*] Reset. Enter new value to scan.\n");
            continue;
        }
        
        // Scan or filter
        if (first_scan) {
            printf("[*] Scanning entire memory...\n");
            if (type == 1) results = scan_value<int32_t>(proc, atoi(line));
            else if (type == 2) results = scan_value<double>(proc, atof(line));
            else results = scan_value<float>(proc, (float)atof(line));
            first_scan = false;
        } else {
            printf("[*] Filtering...\n");
            if (type == 1) results = filter_value<int32_t>(proc, results, atoi(line));
            else if (type == 2) results = filter_value<double>(proc, results, atof(line));
            else results = filter_value<float>(proc, results, (float)atof(line));
        }
        
        printf("[+] %zu matches found\n", results.size());
        if (results.size() == 0) {
            printf("[!] No matches — type 'reset' and try different value type\n");
        } else if (results.size() <= 5) {
            printf("[+] Ready! Type 'set' to change the value\n");
        } else if (results.size() > 50000) {
            printf("[*] Too many — change money in-game, then enter the NEW amount\n");
        } else {
            printf("[*] Change money in-game, then enter the NEW amount to narrow down\n");
        }
    }
    
    CloseHandle(proc);
    return 0;
}
