// language: C++17, file: injector.cpp, target: Windows 11, MSVC
// VANTA Injector — loads vanta_dll.dll into Roblox

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>
#include <cstdio>
#include <string>
#include <filesystem>

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

int main() {
    printf("\n");
    printf("  +================================+\n");
    printf("  |  VANTA DLL Injector             |\n");
    printf("  |  Injects vanta_dll.dll           |\n");
    printf("  +================================+\n\n");

    enable_debug();

    // Find DLL path — same directory as injector
    char exe_path[MAX_PATH];
    GetModuleFileNameA(nullptr, exe_path, MAX_PATH);
    std::string dir(exe_path);
    size_t sl = dir.find_last_of("\\/");
    if (sl != std::string::npos) dir = dir.substr(0, sl + 1);
    std::string dll_path = dir + "vanta_dll.dll";

    if (!std::filesystem::exists(dll_path)) {
        printf("[!] DLL not found: %s\n", dll_path.c_str());
        printf("[!] Place vanta_dll.dll next to this injector.\n");
        system("pause");
        return 1;
    }
    printf("[+] DLL: %s\n", dll_path.c_str());

    // Find Roblox
    printf("[*] Waiting for Roblox...\n");
    DWORD pid = 0;
    for (int i = 0; i < 120; i++) {
        pid = find_pid(L"RobloxPlayerBeta.exe");
        if (pid) break;
        Sleep(1000);
        if (i % 10 == 9) printf("    Still waiting... (%ds)\n", i + 1);
    }
    if (!pid) {
        printf("[!] Roblox not found after 120s\n");
        system("pause");
        return 1;
    }
    printf("[+] Roblox PID: %lu\n", pid);

    // Wait a few seconds for game to load
    printf("[*] Waiting 5s for game to initialize...\n");
    Sleep(5000);

    HANDLE proc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!proc) {
        printf("[!] OpenProcess failed (error %lu) — run as Administrator\n", GetLastError());
        system("pause");
        return 1;
    }

    // Allocate memory for DLL path in target
    size_t path_len = dll_path.length() + 1;
    LPVOID remote_buf = VirtualAllocEx(proc, nullptr, path_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remote_buf) {
        printf("[!] VirtualAllocEx failed (error %lu)\n", GetLastError());
        CloseHandle(proc);
        system("pause");
        return 1;
    }

    // Write DLL path
    if (!WriteProcessMemory(proc, remote_buf, dll_path.c_str(), path_len, nullptr)) {
        printf("[!] WriteProcessMemory failed (error %lu)\n", GetLastError());
        VirtualFreeEx(proc, remote_buf, 0, MEM_RELEASE);
        CloseHandle(proc);
        system("pause");
        return 1;
    }

    // Get LoadLibraryA address
    FARPROC load_lib = GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
    if (!load_lib) {
        printf("[!] Can't find LoadLibraryA\n");
        VirtualFreeEx(proc, remote_buf, 0, MEM_RELEASE);
        CloseHandle(proc);
        system("pause");
        return 1;
    }

    // Create remote thread
    HANDLE thread = CreateRemoteThread(proc, nullptr, 0,
        (LPTHREAD_START_ROUTINE)load_lib, remote_buf, 0, nullptr);
    if (!thread) {
        printf("[!] CreateRemoteThread failed (error %lu)\n", GetLastError());
        printf("[!] Byfron may be blocking injection.\n");
        printf("[!] Try: disable anticheat, use manual map, or kernel driver.\n");
        VirtualFreeEx(proc, remote_buf, 0, MEM_RELEASE);
        CloseHandle(proc);
        system("pause");
        return 1;
    }

    printf("[+] Injection thread created, waiting...\n");
    WaitForSingleObject(thread, 10000);

    DWORD exit_code = 0;
    GetExitCodeThread(thread, &exit_code);

    if (exit_code != 0 && exit_code != STILL_ACTIVE) {
        printf("[+] DLL loaded at 0x%llX\n", (uint64_t)exit_code);
        printf("[+] Injection successful!\n");
        printf("[+] Press INSERT in-game for the menu.\n");
    } else {
        printf("[!] DLL may not have loaded (exit=0x%lX)\n", exit_code);
        printf("[!] Check if Byfron blocked the injection.\n");
    }

    CloseHandle(thread);
    VirtualFreeEx(proc, remote_buf, 0, MEM_RELEASE);
    CloseHandle(proc);

    printf("\n");
    system("pause");
    return 0;
}
