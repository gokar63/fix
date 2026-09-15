// language: C++17, file: injector.cpp, target: Windows 11 x64, MSVC
// Manual Map Injector — bypasses Byfron code integrity (NtCreateSection check)
// Maps PE sections directly, fixes relocs/imports, calls entry via NtCreateThreadEx

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>
#include <tlhelp32.h>
#include <cstdio>
#include <cstdint>
#include <string>
#include <vector>
#include <filesystem>

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

static std::vector<uint8_t> read_file(const std::string& path) {
    HANDLE hf = CreateFileA(path.c_str(), GENERIC_READ, FILE_SHARE_READ,
        nullptr, OPEN_EXISTING, 0, nullptr);
    if (hf == INVALID_HANDLE_VALUE) return {};
    DWORD sz = GetFileSize(hf, nullptr);
    std::vector<uint8_t> buf(sz);
    DWORD rd; ReadFile(hf, buf.data(), sz, &rd, nullptr);
    CloseHandle(hf);
    return buf;
}

// ================================================================
// SHELLCODE — runs inside target process
// ================================================================
struct MapperData {
    uintptr_t imageBase;
    uintptr_t ntHeadersOffset;
    HMODULE  (WINAPI* fnLoadLibraryA)(LPCSTR);
    FARPROC  (WINAPI* fnGetProcAddress)(HMODULE, LPCSTR);
    BOOLEAN  (WINAPI* fnRtlAddFunctionTable)(PRUNTIME_FUNCTION, DWORD, DWORD64);
};

#pragma optimize("", off)
#pragma runtime_checks("", off)
static DWORD WINAPI ShellcodeLoader(MapperData* d) {
    uintptr_t base = d->imageBase;
    auto nt = (PIMAGE_NT_HEADERS)(base + d->ntHeadersOffset);

    // relocations
    uintptr_t delta = base - nt->OptionalHeader.ImageBase;
    if (delta) {
        auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if (dir.Size) {
            auto blk = (PIMAGE_BASE_RELOCATION)(base + dir.VirtualAddress);
            while (blk->VirtualAddress) {
                DWORD cnt = (blk->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
                WORD* ent = (WORD*)((BYTE*)blk + sizeof(IMAGE_BASE_RELOCATION));
                for (DWORD i = 0; i < cnt; i++) {
                    WORD type = ent[i] >> 12;
                    WORD off  = ent[i] & 0xFFF;
                    if (type == IMAGE_REL_BASED_DIR64)
                        *(uintptr_t*)(base + blk->VirtualAddress + off) += delta;
                    else if (type == IMAGE_REL_BASED_HIGHLOW)
                        *(DWORD*)(base + blk->VirtualAddress + off) += (DWORD)delta;
                }
                blk = (PIMAGE_BASE_RELOCATION)((BYTE*)blk + blk->SizeOfBlock);
            }
        }
    }

    // imports
    auto& impDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (impDir.Size) {
        auto imp = (PIMAGE_IMPORT_DESCRIPTOR)(base + impDir.VirtualAddress);
        while (imp->Name) {
            HMODULE hm = d->fnLoadLibraryA((char*)(base + imp->Name));
            if (hm) {
                auto thk = (PIMAGE_THUNK_DATA)(base + imp->FirstThunk);
                auto ot  = imp->OriginalFirstThunk
                    ? (PIMAGE_THUNK_DATA)(base + imp->OriginalFirstThunk) : thk;
                while (ot->u1.AddressOfData) {
                    if (IMAGE_SNAP_BY_ORDINAL(ot->u1.Ordinal)) {
                        thk->u1.Function = (uintptr_t)d->fnGetProcAddress(
                            hm, (LPCSTR)IMAGE_ORDINAL(ot->u1.Ordinal));
                    } else {
                        auto ibn = (PIMAGE_IMPORT_BY_NAME)(base + ot->u1.AddressOfData);
                        thk->u1.Function = (uintptr_t)d->fnGetProcAddress(hm, ibn->Name);
                    }
                    thk++; ot++;
                }
            }
            imp++;
        }
    }

    // exception table — needed for SEH (__try/__except) in mapped code
    if (d->fnRtlAddFunctionTable) {
        auto& exc = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
        if (exc.Size)
            d->fnRtlAddFunctionTable(
                (PRUNTIME_FUNCTION)(base + exc.VirtualAddress),
                exc.Size / sizeof(RUNTIME_FUNCTION), (DWORD64)base);
    }

    // TLS callbacks
    auto& tlsDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
    if (tlsDir.Size) {
        auto tls = (PIMAGE_TLS_DIRECTORY)(base + tlsDir.VirtualAddress);
        auto cb = (PIMAGE_TLS_CALLBACK*)tls->AddressOfCallBacks;
        if (cb) while (*cb) { (*cb)((PVOID)base, DLL_PROCESS_ATTACH, nullptr); cb++; }
    }

    // DllMain
    if (nt->OptionalHeader.AddressOfEntryPoint) {
        typedef BOOL(WINAPI* fn_t)(HINSTANCE, DWORD, LPVOID);
        auto ep = (fn_t)(base + nt->OptionalHeader.AddressOfEntryPoint);
        ep((HINSTANCE)base, DLL_PROCESS_ATTACH, nullptr);
    }

    return 0;
}
static DWORD WINAPI ShellcodeLoaderEnd() { return 0; }
#pragma runtime_checks("", restore)
#pragma optimize("", on)

// ================================================================
// NtCreateThreadEx — less hooked than CreateRemoteThread
// ================================================================
typedef NTSTATUS(NTAPI* NtCreateThreadEx_t)(
    PHANDLE, ACCESS_MASK, PVOID, HANDLE, PVOID, PVOID,
    ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);

static HANDLE create_remote_thread(HANDLE proc, LPVOID start, LPVOID param) {
    auto ntdll = GetModuleHandleA("ntdll.dll");
    auto fn = (NtCreateThreadEx_t)GetProcAddress(ntdll, "NtCreateThreadEx");
    if (fn) {
        HANDLE thread = nullptr;
        NTSTATUS st = fn(&thread, THREAD_ALL_ACCESS, nullptr, proc,
            start, param, 0, 0, 0x1000, 0x10000, nullptr);
        if (st == 0 && thread) return thread;
        printf("[!] NtCreateThreadEx: 0x%08lX, falling back\n", (unsigned long)st);
    }
    return CreateRemoteThread(proc, nullptr, 0,
        (LPTHREAD_START_ROUTINE)start, param, 0, nullptr);
}

// ================================================================
// MAIN
// ================================================================
int main() {
    printf("\n");
    printf("  +================================+\n");
    printf("  |  VANTA Manual Map Injector      |\n");
    printf("  |  Bypasses code integrity check  |\n");
    printf("  +================================+\n\n");

    enable_debug();

    char exe_path[MAX_PATH];
    GetModuleFileNameA(nullptr, exe_path, MAX_PATH);
    std::string dir(exe_path);
    size_t sl = dir.find_last_of("\\\/");
    if (sl != std::string::npos) dir = dir.substr(0, sl + 1);
    std::string dll_path = dir + "vanta_dll.dll";

    if (!std::filesystem::exists(dll_path)) {
        printf("[!] DLL not found: %s\n", dll_path.c_str());
        system("pause"); return 1;
    }
    printf("[+] DLL: %s\n", dll_path.c_str());

    auto pe_data = read_file(dll_path);
    if (pe_data.empty()) {
        printf("[!] Failed to read DLL\n"); system("pause"); return 1;
    }
    printf("[+] DLL size: %zu bytes\n", pe_data.size());

    // validate PE
    auto dos = (PIMAGE_DOS_HEADER)pe_data.data();
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        printf("[!] Invalid DOS header\n"); system("pause"); return 1;
    }
    auto nt = (PIMAGE_NT_HEADERS)(pe_data.data() + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        printf("[!] Invalid NT header\n"); system("pause"); return 1;
    }
    if (nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) {
        printf("[!] DLL is not x64\n"); system("pause"); return 1;
    }

    printf("[*] Waiting for Roblox...\n");
    DWORD pid = 0;
    for (int i = 0; i < 120; i++) {
        pid = find_pid(L"RobloxPlayerBeta.exe");
        if (pid) break;
        Sleep(1000);
        if (i % 10 == 9) printf("    Still waiting... (%ds)\n", i + 1);
    }
    if (!pid) { printf("[!] Roblox not found\n"); system("pause"); return 1; }
    printf("[+] Roblox PID: %lu\n", pid);

    printf("[*] Waiting 5s for game to initialize...\n");
    Sleep(5000);

    HANDLE proc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!proc) {
        printf("[!] OpenProcess failed (%lu) — run as admin\n", GetLastError());
        system("pause"); return 1;
    }

    // allocate in target
    SIZE_T img_size = nt->OptionalHeader.SizeOfImage;
    LPVOID remote_base = VirtualAllocEx(proc, nullptr, img_size,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remote_base) {
        printf("[!] VirtualAllocEx failed (%lu)\n", GetLastError());
        CloseHandle(proc); system("pause"); return 1;
    }
    printf("[+] Allocated 0x%zX bytes at %p\n", img_size, remote_base);

    // write PE headers
    WriteProcessMemory(proc, remote_base, pe_data.data(),
        nt->OptionalHeader.SizeOfHeaders, nullptr);

    // write sections
    auto sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (sec[i].SizeOfRawData == 0) continue;
        WriteProcessMemory(proc,
            (BYTE*)remote_base + sec[i].VirtualAddress,
            pe_data.data() + sec[i].PointerToRawData,
            sec[i].SizeOfRawData, nullptr);
    }
    printf("[+] PE sections written\n");

    // prepare mapper data
    MapperData md{};
    md.imageBase = (uintptr_t)remote_base;
    md.ntHeadersOffset = (uintptr_t)dos->e_lfanew;
    md.fnLoadLibraryA = (decltype(md.fnLoadLibraryA))
        GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
    md.fnGetProcAddress = (decltype(md.fnGetProcAddress))
        GetProcAddress(GetModuleHandleA("kernel32.dll"), "GetProcAddress");
    md.fnRtlAddFunctionTable = (decltype(md.fnRtlAddFunctionTable))
        GetProcAddress(GetModuleHandleA("kernel32.dll"), "RtlAddFunctionTable");
    if (!md.fnRtlAddFunctionTable)
        md.fnRtlAddFunctionTable = (decltype(md.fnRtlAddFunctionTable))
            GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlAddFunctionTable");

    // write shellcode + data to target
    size_t sc_size = (BYTE*)ShellcodeLoaderEnd - (BYTE*)ShellcodeLoader;
    if (sc_size == 0 || sc_size > 0x10000) sc_size = 0x1000; // safety fallback

    size_t alloc_size = sc_size + sizeof(MapperData) + 64;
    LPVOID remote_sc = VirtualAllocEx(proc, nullptr, alloc_size,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remote_sc) {
        printf("[!] Failed to alloc shellcode space\n");
        VirtualFreeEx(proc, remote_base, 0, MEM_RELEASE);
        CloseHandle(proc); system("pause"); return 1;
    }

    // data at start, shellcode after
    LPVOID remote_data = remote_sc;
    LPVOID remote_code = (BYTE*)remote_sc + sizeof(MapperData) + 16;

    WriteProcessMemory(proc, remote_data, &md, sizeof(md), nullptr);
    WriteProcessMemory(proc, remote_code, ShellcodeLoader, sc_size, nullptr);
    printf("[+] Shellcode written at %p (%zu bytes)\n", remote_code, sc_size);

    // execute
    HANDLE thread = create_remote_thread(proc, remote_code, remote_data);
    if (!thread) {
        printf("[!] Thread creation failed (%lu)\n", GetLastError());
        VirtualFreeEx(proc, remote_base, 0, MEM_RELEASE);
        VirtualFreeEx(proc, remote_sc, 0, MEM_RELEASE);
        CloseHandle(proc); system("pause"); return 1;
    }

    printf("[+] Loader thread started, waiting...\n");
    DWORD wait = WaitForSingleObject(thread, 15000);
    if (wait == WAIT_TIMEOUT) {
        printf("[!] Loader timed out — DLL may still be initializing\n");
    } else {
        DWORD exit_code = 0;
        GetExitCodeThread(thread, &exit_code);
        if (exit_code == 0)
            printf("[+] Manual map successful!\n");
        else
            printf("[!] Loader returned 0x%lX\n", exit_code);
    }

    printf("[+] Press INSERT in-game for the menu.\n");

    // cleanup (leave mapped image + shellcode — DLL is running)
    CloseHandle(thread);
    CloseHandle(proc);

    printf("\n");
    system("pause");
    return 0;
}
