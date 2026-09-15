// language: C++17, file: injector.cpp, target: Windows 11 x64, MSVC
// Manual Map Injector — bypasses Byfron code integrity
// Shellcode resolves imports via PEB walk (no LoadLibraryA/GetProcAddress calls)

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
// Resolves everything via PEB walk, zero calls to hooked APIs
// ================================================================
struct MapperData {
    uintptr_t imageBase;
    uintptr_t ntHeadersOffset;
    uintptr_t originalRip;   // for thread hijack — resume here after loading
    uintptr_t originalRcx;   // preserve original RCX
    volatile LONG  done;     // set to 1 when shellcode finishes
};

#pragma optimize("", off)
#pragma runtime_checks("", off)

// djb2-style hash for case-insensitive module/function name matching
static DWORD sc_hash(const char* s) {
    DWORD h = 5381;
    while (*s) {
        char c = *s++;
        if (c >= 'A' && c <= 'Z') c += 32;
        h = ((h << 5) + h) + (DWORD)c;
    }
    return h;
}

static DWORD sc_hash_w(const wchar_t* s) {
    DWORD h = 5381;
    while (*s) {
        char c = (char)*s++;
        if (c >= 'A' && c <= 'Z') c += 32;
        h = ((h << 5) + h) + (DWORD)c;
    }
    return h;
}

// walk PEB->Ldr to find a loaded module by name hash
static uintptr_t sc_find_module(DWORD name_hash) {
#if defined(_M_X64) || defined(__x86_64__)
    PEB* peb = (PEB*)__readgsqword(0x60);
#else
    PEB* peb = (PEB*)__readfsdword(0x30);
#endif
    auto* ldr = peb->Ldr;
    auto* head = &ldr->InMemoryOrderModuleList;
    for (auto* entry = head->Flink; entry != head; entry = entry->Flink) {
        auto* mod = CONTAINING_RECORD(entry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
        if (mod->FullDllName.Buffer && mod->FullDllName.Length > 0) {
            wchar_t* name = mod->FullDllName.Buffer;
            wchar_t* last_slash = name;
            for (wchar_t* p = name; *p; p++)
                if (*p == '\\' || *p == '/') last_slash = p + 1;
            if (last_slash > name) name = last_slash;
            if (sc_hash_w(name) == name_hash)
                return (uintptr_t)mod->DllBase;
        }
    }
    return 0;
}

// parse a module's export table to find a function by name hash
static uintptr_t sc_find_export(uintptr_t mod_base, DWORD func_hash) {
    auto* dos = (IMAGE_DOS_HEADER*)mod_base;
    auto* nt = (IMAGE_NT_HEADERS*)(mod_base + dos->e_lfanew);
    auto& exp_dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (exp_dir.Size == 0) return 0;

    auto* exp = (IMAGE_EXPORT_DIRECTORY*)(mod_base + exp_dir.VirtualAddress);
    auto* names = (DWORD*)(mod_base + exp->AddressOfNames);
    auto* ords = (WORD*)(mod_base + exp->AddressOfNameOrdinals);
    auto* funcs = (DWORD*)(mod_base + exp->AddressOfFunctions);

    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        const char* fname = (const char*)(mod_base + names[i]);
        if (sc_hash(fname) == func_hash)
            return mod_base + funcs[ords[i]];
    }
    return 0;
}

// pre-computed hashes (djb2 lowercase)
#define H_KERNEL32        0x6DDB9555u
#define H_NTDLL           0x1EDAB0EDu
#define H_RTLADDFUNCTABLE 0xA5670B3Fu

// sc_strlen for import name hashing inside shellcode
static int sc_strlen(const char* s) { int n = 0; while (s[n]) n++; return n; }

// find module in PEB by ASCII name (not hash) — for import table DLL names
static uintptr_t sc_find_module_by_name(const char* dll_name) {
#if defined(_M_X64) || defined(__x86_64__)
    PEB* peb = (PEB*)__readgsqword(0x60);
#else
    PEB* peb = (PEB*)__readfsdword(0x30);
#endif
    auto* ldr = peb->Ldr;
    auto* head = &ldr->InMemoryOrderModuleList;
    for (auto* entry = head->Flink; entry != head; entry = entry->Flink) {
        auto* mod = CONTAINING_RECORD(entry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
        if (!mod->FullDllName.Buffer || mod->FullDllName.Length == 0) continue;
        wchar_t* wname = mod->FullDllName.Buffer;
        wchar_t* last_slash = wname;
        for (wchar_t* p = wname; *p; p++)
            if (*p == '\\' || *p == '/') last_slash = p + 1;
        if (last_slash > wname) wname = last_slash;
        const char* a = dll_name;
        wchar_t* w = wname;
        bool match = true;
        while (*a && *w) {
            char ca = *a; char cw = (char)*w;
            if (ca >= 'A' && ca <= 'Z') ca += 32;
            if (cw >= 'A' && cw <= 'Z') cw += 32;
            if (ca != cw) { match = false; break; }
            a++; w++;
        }
        if (match && *a == 0 && *w == 0) return (uintptr_t)mod->DllBase;
    }
    return 0;
}

// find export by ASCII name (not hash) — for import table function names
static uintptr_t sc_find_export_by_name(uintptr_t mod_base, const char* func_name) {
    auto* dos = (IMAGE_DOS_HEADER*)mod_base;
    auto* nt = (IMAGE_NT_HEADERS*)(mod_base + dos->e_lfanew);
    auto& exp_dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (exp_dir.Size == 0) return 0;
    auto* exp = (IMAGE_EXPORT_DIRECTORY*)(mod_base + exp_dir.VirtualAddress);
    auto* names = (DWORD*)(mod_base + exp->AddressOfNames);
    auto* ords = (WORD*)(mod_base + exp->AddressOfNameOrdinals);
    auto* funcs = (DWORD*)(mod_base + exp->AddressOfFunctions);
    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        const char* fname = (const char*)(mod_base + names[i]);
        const char* a = func_name; const char* b = fname;
        while (*a && *b && *a == *b) { a++; b++; }
        if (*a == 0 && *b == 0)
            return mod_base + funcs[ords[i]];
    }
    return 0;
}

// find export by ordinal
static uintptr_t sc_find_export_by_ordinal(uintptr_t mod_base, WORD ordinal) {
    auto* dos = (IMAGE_DOS_HEADER*)mod_base;
    auto* nt = (IMAGE_NT_HEADERS*)(mod_base + dos->e_lfanew);
    auto& exp_dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (exp_dir.Size == 0) return 0;
    auto* exp = (IMAGE_EXPORT_DIRECTORY*)(mod_base + exp_dir.VirtualAddress);
    auto* funcs = (DWORD*)(mod_base + exp->AddressOfFunctions);
    DWORD idx = ordinal - exp->Base;
    if (idx >= exp->NumberOfFunctions) return 0;
    return mod_base + funcs[idx];
}

// thread hijack shellcode — called with RCX = MapperData*
// after loading, signals done and spins until injector restores context
static void ShellcodeLoader(MapperData* d) {
    uintptr_t base = d->imageBase;
    auto* nt = (IMAGE_NT_HEADERS*)(base + d->ntHeadersOffset);

    uintptr_t kernel32 = sc_find_module(H_KERNEL32);
    uintptr_t ntdll_mod = sc_find_module(H_NTDLL);
    if (!kernel32) { InterlockedExchange(&d->done, 0xDEAD0001); while(d->done != 0xFFFFFFFF){} return; }

    typedef BOOLEAN(WINAPI* RtlAddFunctionTable_t)(PRUNTIME_FUNCTION, DWORD, DWORD64);
    auto pRtlAddFunctionTable = (RtlAddFunctionTable_t)sc_find_export(kernel32, H_RTLADDFUNCTABLE);
    if (!pRtlAddFunctionTable && ntdll_mod)
        pRtlAddFunctionTable = (RtlAddFunctionTable_t)sc_find_export(ntdll_mod, H_RTLADDFUNCTABLE);

    // relocations
    uintptr_t delta = base - nt->OptionalHeader.ImageBase;
    if (delta) {
        auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if (dir.Size) {
            auto* blk = (IMAGE_BASE_RELOCATION*)(base + dir.VirtualAddress);
            while (blk->VirtualAddress) {
                DWORD cnt = (blk->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
                WORD* ent = (WORD*)((BYTE*)blk + sizeof(IMAGE_BASE_RELOCATION));
                for (DWORD i = 0; i < cnt; i++) {
                    WORD type = ent[i] >> 12;
                    WORD off = ent[i] & 0xFFF;
                    if (type == IMAGE_REL_BASED_DIR64)
                        *(uintptr_t*)(base + blk->VirtualAddress + off) += delta;
                    else if (type == IMAGE_REL_BASED_HIGHLOW)
                        *(DWORD*)(base + blk->VirtualAddress + off) += (DWORD)delta;
                }
                blk = (IMAGE_BASE_RELOCATION*)((BYTE*)blk + blk->SizeOfBlock);
            }
        }
    }

    // imports — PURE PEB walk, zero hooked API calls
    auto& impDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (impDir.Size) {
        auto* imp = (IMAGE_IMPORT_DESCRIPTOR*)(base + impDir.VirtualAddress);
        while (imp->Name) {
            const char* dll_name = (const char*)(base + imp->Name);
            uintptr_t mod_base = sc_find_module_by_name(dll_name);
            if (mod_base) {
                auto* thk = (IMAGE_THUNK_DATA*)(base + imp->FirstThunk);
                auto* ot = imp->OriginalFirstThunk
                    ? (IMAGE_THUNK_DATA*)(base + imp->OriginalFirstThunk) : thk;
                while (ot->u1.AddressOfData) {
                    if (IMAGE_SNAP_BY_ORDINAL(ot->u1.Ordinal)) {
                        thk->u1.Function = sc_find_export_by_ordinal(
                            mod_base, (WORD)IMAGE_ORDINAL(ot->u1.Ordinal));
                    } else {
                        auto* ibn = (IMAGE_IMPORT_BY_NAME*)(base + ot->u1.AddressOfData);
                        thk->u1.Function = sc_find_export_by_name(mod_base, ibn->Name);
                    }
                    thk++; ot++;
                }
            } else {
                InterlockedExchange(&d->done, 0xDEAD0003);
                while(d->done != 0xFFFFFFFF){} return;
            }
            imp++;
        }
    }

    // exception table
    if (pRtlAddFunctionTable) {
        auto& exc = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
        if (exc.Size)
            pRtlAddFunctionTable(
                (PRUNTIME_FUNCTION)(base + exc.VirtualAddress),
                exc.Size / sizeof(RUNTIME_FUNCTION), (DWORD64)base);
    }

    // TLS callbacks
    auto& tlsDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
    if (tlsDir.Size) {
        auto* tls = (IMAGE_TLS_DIRECTORY*)(base + tlsDir.VirtualAddress);
        auto* cb = (PIMAGE_TLS_CALLBACK*)tls->AddressOfCallBacks;
        if (cb) while (*cb) { (*cb)((PVOID)base, DLL_PROCESS_ATTACH, nullptr); cb++; }
    }

    // DllMain
    if (nt->OptionalHeader.AddressOfEntryPoint) {
        typedef BOOL(WINAPI* DllMain_t)(HINSTANCE, DWORD, LPVOID);
        auto ep = (DllMain_t)(base + nt->OptionalHeader.AddressOfEntryPoint);
        ep((HINSTANCE)base, DLL_PROCESS_ATTACH, nullptr);
    }

    InterlockedExchange(&d->done, 1);
    // spin until injector restores our context
    while (d->done != 0xFFFFFFFF) { }
}
static void ShellcodeLoaderEnd() { }
#pragma runtime_checks("", restore)
#pragma optimize("", on)

// ================================================================
// Thread hijack — find a thread, suspend, redirect RIP, resume
// Bypasses NtCreateThreadEx code integrity check entirely
// ================================================================
static DWORD find_thread(DWORD pid) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    THREADENTRY32 te{}; te.dwSize = sizeof(te);
    DWORD tid = 0;
    if (Thread32First(snap, &te)) do {
        if (te.th32OwnerProcessID == pid) { tid = te.th32ThreadID; break; }
    } while (Thread32Next(snap, &te));
    CloseHandle(snap);
    return tid;
}

// ================================================================
// MAIN
// ================================================================
int main() {
    printf("\n");
    printf("  +====================================+\n");
    printf("  |  VANTA Manual Map Injector          |\n");
    printf("  |  Thread hijack + PEB-walk (v3)      |\n");
    printf("  +====================================+\n\n");

    enable_debug();

    char exe_path[MAX_PATH];
    GetModuleFileNameA(nullptr, exe_path, MAX_PATH);
    std::string dir(exe_path);
    size_t sl = dir.find_last_of("\\/");
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

    auto* dos = (PIMAGE_DOS_HEADER)pe_data.data();
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        printf("[!] Invalid DOS header\n"); system("pause"); return 1;
    }
    auto* nt = (PIMAGE_NT_HEADERS)(pe_data.data() + dos->e_lfanew);
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

    // map PE sections
    SIZE_T img_size = nt->OptionalHeader.SizeOfImage;
    LPVOID remote_base = VirtualAllocEx(proc, nullptr, img_size,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remote_base) {
        printf("[!] VirtualAllocEx failed (%lu)\n", GetLastError());
        CloseHandle(proc); system("pause"); return 1;
    }
    printf("[+] Allocated 0x%zX bytes at %p\n", img_size, remote_base);

    WriteProcessMemory(proc, remote_base, pe_data.data(),
        nt->OptionalHeader.SizeOfHeaders, nullptr);

    auto* sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (sec[i].SizeOfRawData == 0) continue;
        WriteProcessMemory(proc,
            (BYTE*)remote_base + sec[i].VirtualAddress,
            pe_data.data() + sec[i].PointerToRawData,
            sec[i].SizeOfRawData, nullptr);
    }
    printf("[+] PE sections written\n");

    // shellcode size
    size_t sc_size = (BYTE*)ShellcodeLoaderEnd - (BYTE*)ShellcodeLoader;
    if (sc_size == 0 || sc_size > 0x10000) sc_size = 0x4000;
    printf("[+] Shellcode size: %zu bytes\n", sc_size);

    // allocate shellcode + data region
    size_t alloc_size = sc_size + sizeof(MapperData) + 64;
    LPVOID remote_sc = VirtualAllocEx(proc, nullptr, alloc_size,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remote_sc) {
        printf("[!] Failed to alloc shellcode space\n");
        VirtualFreeEx(proc, remote_base, 0, MEM_RELEASE);
        CloseHandle(proc); system("pause"); return 1;
    }

    LPVOID remote_data = remote_sc;
    LPVOID remote_code = (BYTE*)remote_sc + sizeof(MapperData) + 16;

    // find a thread to hijack
    DWORD tid = find_thread(pid);
    if (!tid) {
        printf("[!] No threads found in target\n");
        VirtualFreeEx(proc, remote_base, 0, MEM_RELEASE);
        VirtualFreeEx(proc, remote_sc, 0, MEM_RELEASE);
        CloseHandle(proc); system("pause"); return 1;
    }
    printf("[+] Target thread: %lu\n", tid);

    HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, tid);
    if (!hThread) {
        printf("[!] OpenThread failed (%lu)\n", GetLastError());
        VirtualFreeEx(proc, remote_base, 0, MEM_RELEASE);
        VirtualFreeEx(proc, remote_sc, 0, MEM_RELEASE);
        CloseHandle(proc); system("pause"); return 1;
    }

    // suspend thread and grab context
    SuspendThread(hThread);
    CONTEXT ctx{};
    ctx.ContextFlags = CONTEXT_FULL;
    if (!GetThreadContext(hThread, &ctx)) {
        printf("[!] GetThreadContext failed (%lu)\n", GetLastError());
        ResumeThread(hThread);
        CloseHandle(hThread);
        VirtualFreeEx(proc, remote_base, 0, MEM_RELEASE);
        VirtualFreeEx(proc, remote_sc, 0, MEM_RELEASE);
        CloseHandle(proc); system("pause"); return 1;
    }
    printf("[+] Thread suspended, RIP = 0x%llX\n", (unsigned long long)ctx.Rip);

    // write mapper data with original context info
    MapperData md{};
    md.imageBase = (uintptr_t)remote_base;
    md.ntHeadersOffset = (uintptr_t)dos->e_lfanew;
    md.originalRip = ctx.Rip;
    md.originalRcx = ctx.Rcx;
    md.done = 0;

    WriteProcessMemory(proc, remote_data, &md, sizeof(md), nullptr);
    WriteProcessMemory(proc, remote_code, (void*)ShellcodeLoader, sc_size, nullptr);
    printf("[+] Shellcode written at %p\n", remote_code);

    // hijack: set RCX = data pointer, RIP = shellcode
    ctx.Rcx = (DWORD64)remote_data;
    ctx.Rip = (DWORD64)remote_code;
    if (!SetThreadContext(hThread, &ctx)) {
        printf("[!] SetThreadContext failed (%lu)\n", GetLastError());
        ctx.Rip = md.originalRip;
        ctx.Rcx = md.originalRcx;
        SetThreadContext(hThread, &ctx);
        ResumeThread(hThread);
        CloseHandle(hThread);
        VirtualFreeEx(proc, remote_base, 0, MEM_RELEASE);
        VirtualFreeEx(proc, remote_sc, 0, MEM_RELEASE);
        CloseHandle(proc); system("pause"); return 1;
    }

    // resume and poll for completion
    ResumeThread(hThread);
    printf("[+] Thread resumed with hijacked RIP, waiting...\n");

    LONG result = 0;
    for (int i = 0; i < 300; i++) {
        Sleep(100);
        MapperData check{};
        SIZE_T rd2 = 0;
        ReadProcessMemory(proc, remote_data, &check, sizeof(check), &rd2);
        if (check.done != 0) {
            result = check.done;
            break;
        }
        if (i == 299) {
            printf("[!] Timed out waiting for shellcode (30s)\n");
            result = -1;
        }
    }

    // restore original thread context — shellcode is spinning waiting for this
    SuspendThread(hThread);
    CONTEXT restore_ctx{};
    restore_ctx.ContextFlags = CONTEXT_FULL;
    GetThreadContext(hThread, &restore_ctx);
    restore_ctx.Rip = md.originalRip;
    restore_ctx.Rcx = md.originalRcx;
    SetThreadContext(hThread, &restore_ctx);
    LONG release = 0xFFFFFFFF;
    WriteProcessMemory(proc, (BYTE*)remote_data + offsetof(MapperData, done),
        &release, sizeof(release), nullptr);
    ResumeThread(hThread);
    printf("[+] Thread context restored\n");

    if (result == 1)
        printf("[+] Manual map successful!\n");
    else if (result == -1)
        printf("[!] Shellcode did not signal completion\n");
    else
        printf("[!] Shellcode error: 0x%lX\n", (unsigned long)result);

    printf("[+] Press INSERT in-game for the menu.\n");

    CloseHandle(hThread);
    CloseHandle(proc);

    printf("\n");
    system("pause");
    return 0;
}
