// language: C++17, file: vanta_dll.cpp, target: Windows 11 x64, MSVC
// VANTA Internal DLL — DX11 Present hook + ImGui overlay
// Injected via manual mapper, renders ESP/aimbot/menu through game's own DX11

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdint>
#include <cstdio>
#include <cmath>
#include <string>
#include <vector>
#include <thread>
#include <atomic>
#include <mutex>

#include <d3d11.h>
#include <dxgi.h>
#pragma comment(lib, "d3d11.lib")
#pragma comment(lib, "dxgi.lib")

#include "imgui.h"
#include "imgui_impl_win32.h"
#include "imgui_impl_dx11.h"

extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(
    HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

// ================================================================
// OFFSETS
// ================================================================
namespace off {
    int Name = 0x70;
    int Children = 0x78;
    int Parent = 0x68;
    int ClassDescriptor = 0x18;
    int ClassName = 0x8;

    int FDM_Pointer = 0x8E42C98;
    int FDM_DataModel = 0x1F8;

    int LocalPlayer = 0x130;
    int Workspace_CurrentCamera = 0x4B8;

    int Camera_Position = 0xFC;
    int Camera_Rotation = 0xD8;

    int BasePart_Primitive = 0x188;
    int Primitive_Position = 0xD4;
    int Primitive_Rotation = 0xB0;

    int Health = 0x190;
    int MaxHealth = 0x1A8;
    int Walkspeed = 0x1D0;

    int Player_Character = 0x298;

    int VE_ViewMatrix = 0x1B0;
    int VE_Pointer = 0x846F768;
}

static void load_offsets_config() {
    char path[MAX_PATH];
    GetModuleFileNameA(nullptr, path, MAX_PATH);
    std::string dir(path);
    size_t sl = dir.find_last_of("\\/");
    if (sl != std::string::npos) dir = dir.substr(0, sl + 1);
    std::string cfg = dir + "vanta_offsets.ini";

    FILE* f = fopen(cfg.c_str(), "r");
    if (!f) return;
    char line[256];
    while (fgets(line, sizeof(line), f)) {
        char key[64]; int val;
        if (sscanf(line, "%63[^=]=%i", key, &val) == 2) {
            std::string k(key);
            if (k == "FDM_Pointer") off::FDM_Pointer = val;
            else if (k == "FDM_DataModel") off::FDM_DataModel = val;
            else if (k == "LocalPlayer") off::LocalPlayer = val;
            else if (k == "Workspace_CurrentCamera") off::Workspace_CurrentCamera = val;
            else if (k == "BasePart_Primitive") off::BasePart_Primitive = val;
            else if (k == "Primitive_Position") off::Primitive_Position = val;
            else if (k == "Health") off::Health = val;
            else if (k == "MaxHealth") off::MaxHealth = val;
            else if (k == "Player_Character") off::Player_Character = val;
            else if (k == "VE_ViewMatrix") off::VE_ViewMatrix = val;
            else if (k == "VE_Pointer") off::VE_Pointer = val;
        }
    }
    fclose(f);
}

// ================================================================
// INTERNAL MEMORY — direct pointer dereference with SEH
// ================================================================
template<typename T>
static T mem(uintptr_t addr) {
    __try { return *(T*)addr; }
    __except (EXCEPTION_EXECUTE_HANDLER) { return T{}; }
}

static bool read_rstr_raw(uintptr_t addr, char* out, size_t* out_len) {
    __try {
        uint64_t len = *(uint64_t*)(addr + 0x10);
        if (len == 0 || len > 200) return false;
        const char* buf = (len > 15) ? (const char*)*(uintptr_t*)addr : (const char*)addr;
        if ((uintptr_t)buf < 0x10000) return false;
        size_t copy = (len < 200) ? (size_t)len : 200;
        for (size_t i = 0; i < copy; i++) out[i] = buf[i];
        *out_len = copy;
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}

static std::string read_rstr(uintptr_t addr) {
    if (addr < 0x10000) return "";
    char buf[201]; size_t len = 0;
    if (read_rstr_raw(addr, buf, &len)) return std::string(buf, len);
    return "";
}

static std::string inst_name(uintptr_t inst) {
    return read_rstr(mem<uintptr_t>(inst + off::Name));
}

static std::string inst_classname(uintptr_t inst) {
    uintptr_t cd = mem<uintptr_t>(inst + off::ClassDescriptor);
    if (cd < 0x10000) return "";
    return read_rstr(mem<uintptr_t>(cd + off::ClassName));
}

static std::vector<uintptr_t> get_children(uintptr_t inst) {
    std::vector<uintptr_t> out;
    uintptr_t cp = mem<uintptr_t>(inst + off::Children);
    if (cp < 0x10000) return out;
    uintptr_t start = mem<uintptr_t>(cp);
    uintptr_t end = mem<uintptr_t>(cp + 8);
    if (start < 0x10000 || end <= start || end - start > 0x50000) return out;
    for (uintptr_t p = start; p < end; p += 0x10) {
        uintptr_t c = mem<uintptr_t>(p);
        if (c > 0x10000) out.push_back(c);
    }
    return out;
}

static uintptr_t find_child(uintptr_t inst, const std::string& name) {
    for (uintptr_t c : get_children(inst))
        if (inst_name(c) == name) return c;
    return 0;
}

static uintptr_t find_child_class(uintptr_t inst, const std::string& cls) {
    for (uintptr_t c : get_children(inst))
        if (inst_classname(c) == cls) return c;
    return 0;
}

// ================================================================
// MATH
// ================================================================
struct Vec3 { float x, y, z; };
struct Vec2 { float x, y; };
struct Matrix4 { float m[4][4]; };

static Vec3 get_part_position(uintptr_t part) {
    uintptr_t prim = mem<uintptr_t>(part + off::BasePart_Primitive);
    if (prim < 0x10000) return {0, 0, 0};
    return mem<Vec3>(prim + off::Primitive_Position);
}

static Vec2 world_to_screen(const Vec3& pos, const Matrix4& vm, int w, int h) {
    float cx = vm.m[0][0]*pos.x + vm.m[1][0]*pos.y + vm.m[2][0]*pos.z + vm.m[3][0];
    float cy = vm.m[0][1]*pos.x + vm.m[1][1]*pos.y + vm.m[2][1]*pos.z + vm.m[3][1];
    float cw = vm.m[0][3]*pos.x + vm.m[1][3]*pos.y + vm.m[2][3]*pos.z + vm.m[3][3];
    if (cw < 0.001f) return {-1, -1};
    float nx = cx / cw;
    float ny = cy / cw;
    return { (1.0f + nx) * 0.5f * w, (1.0f - ny) * 0.5f * h };
}

static float dist3d(Vec3 a, Vec3 b) {
    float dx = a.x-b.x, dy = a.y-b.y, dz = a.z-b.z;
    return sqrtf(dx*dx + dy*dy + dz*dz);
}

// ================================================================
// PLAYER DATA
// ================================================================
struct PlayerInfo {
    std::string name;
    Vec3 position;
    float health;
    float max_health;
    Vec2 screen;
    bool on_screen;
    float distance;
};

// ================================================================
// GLOBALS
// ================================================================
static std::atomic<bool> g_running{true};
static std::mutex g_mtx;
static std::vector<PlayerInfo> g_players;

static std::atomic<bool> g_esp{true};
static std::atomic<bool> g_aimbot{false};
static std::atomic<bool> g_names{true};
static std::atomic<bool> g_health_bar{true};
static std::atomic<bool> g_boxes{true};
static std::atomic<bool> g_snaplines{false};
static std::atomic<bool> g_distance{true};
static std::atomic<float> g_aim_fov{200.0f};
static std::atomic<bool> g_menu_open{false};
static int g_screen_w = 1920, g_screen_h = 1080;

// DX11
static ID3D11Device*           g_device  = nullptr;
static ID3D11DeviceContext*    g_context = nullptr;
static ID3D11RenderTargetView* g_rtv     = nullptr;
static HWND                    g_game_hwnd = nullptr;
static WNDPROC                 g_orig_wndproc = nullptr;
static bool                    g_imgui_init = false;

// hook storage
using Present_t       = HRESULT(__stdcall*)(IDXGISwapChain*, UINT, UINT);
using ResizeBuffers_t = HRESULT(__stdcall*)(IDXGISwapChain*, UINT, UINT, UINT, DXGI_FORMAT, UINT);
static Present_t       g_orig_present = nullptr;
static ResizeBuffers_t g_orig_resize  = nullptr;

static HMODULE g_dll_module = nullptr;

// ================================================================
// DX11 VTABLE HOOK — inline detour (14-byte x64 absolute jmp)
// ================================================================
struct Detour {
    void*  target;
    void*  hook;
    void*  trampoline;
    BYTE   original[32];

    bool install(void* target_fn, void* hook_fn) {
        target = target_fn;
        hook = hook_fn;
        trampoline = VirtualAlloc(nullptr, 64, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!trampoline) return false;

        memcpy(original, target, 14);

        // trampoline: original bytes + jmp back to target+14
        memcpy(trampoline, original, 14);
        BYTE* tp = (BYTE*)trampoline + 14;
        tp[0] = 0xFF; tp[1] = 0x25;
        *(DWORD*)(tp + 2) = 0;
        *(uintptr_t*)(tp + 6) = (uintptr_t)target + 14;

        // patch target: jmp to hook
        DWORD old;
        VirtualProtect(target, 14, PAGE_EXECUTE_READWRITE, &old);
        BYTE* t = (BYTE*)target;
        t[0] = 0xFF; t[1] = 0x25;
        *(DWORD*)(t + 2) = 0;
        *(uintptr_t*)(t + 6) = (uintptr_t)hook;
        VirtualProtect(target, 14, old, &old);
        return true;
    }

    void remove() {
        if (!target) return;
        DWORD old;
        VirtualProtect(target, 14, PAGE_EXECUTE_READWRITE, &old);
        memcpy(target, original, 14);
        VirtualProtect(target, 14, old, &old);
        if (trampoline) { VirtualFree(trampoline, 0, MEM_RELEASE); trampoline = nullptr; }
    }
};

static Detour g_present_detour;
static Detour g_resize_detour;

// ================================================================
// DATAMODEL FINDER
// ================================================================
static uintptr_t find_datamodel() {
    HMODULE hmod = GetModuleHandleA(nullptr);
    if (!hmod) return 0;
    uintptr_t base = (uintptr_t)hmod;

    uintptr_t fdm_ptr = mem<uintptr_t>(base + off::FDM_Pointer);
    if (fdm_ptr > 0x10000 && fdm_ptr < 0x7FFFFFFFFFFF) {
        uintptr_t dm = mem<uintptr_t>(fdm_ptr + off::FDM_DataModel);
        if (dm > 0x10000) {
            auto ch = get_children(dm);
            int known = 0;
            for (auto c : ch) {
                std::string n = inst_name(c);
                if (n == "Workspace" || n == "Players" || n == "Lighting" ||
                    n == "ReplicatedStorage" || n == "StarterGui")
                    known++;
            }
            if (known >= 3) return dm;
        }
    }

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(base + dos->e_lfanew);
    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (memcmp(sec[i].Name, ".data", 5) == 0 || memcmp(sec[i].Name, ".rdata", 6) == 0) {
            uintptr_t start = base + sec[i].VirtualAddress;
            uintptr_t size = sec[i].Misc.VirtualSize;
            for (uintptr_t a = start; a + 8 < start + size; a += 8) {
                uintptr_t fdm = mem<uintptr_t>(a);
                if (fdm < 0x10000 || fdm > 0x7FFFFFFFFFFF) continue;
                uintptr_t dm = mem<uintptr_t>(fdm + off::FDM_DataModel);
                if (dm < 0x10000) continue;
                auto ch = get_children(dm);
                int known = 0;
                for (auto c : ch) {
                    std::string n = inst_name(c);
                    if (n == "Workspace" || n == "Players" || n == "Lighting" ||
                        n == "ReplicatedStorage" || n == "StarterGui")
                        known++;
                }
                if (known >= 3) return dm;
            }
        }
    }
    return 0;
}

// ================================================================
// SCANNER THREAD
// ================================================================
static void scanner_thread() {
    uintptr_t dm = 0;
    while (g_running) {
        if (!dm) { dm = find_datamodel(); if (!dm) { Sleep(1000); continue; } }

        {
            auto ch = get_children(dm);
            bool has = false;
            for (auto c : ch) if (inst_name(c) == "Players") { has = true; break; }
            if (!has) { dm = 0; continue; }
        }

        uintptr_t players = find_child(dm, "Players");
        uintptr_t workspace = find_child(dm, "Workspace");
        if (!players || !workspace) { Sleep(500); continue; }

        uintptr_t local_player = mem<uintptr_t>(players + off::LocalPlayer);
        if (local_player < 0x10000) { Sleep(200); continue; }
        std::string local_name = inst_name(local_player);

        uintptr_t camera = mem<uintptr_t>(workspace + off::Workspace_CurrentCamera);
        if (camera < 0x10000) camera = find_child_class(workspace, "Camera");
        Matrix4 vm{};
        Vec3 cam_pos{};
        if (camera > 0x10000) {
            cam_pos = mem<Vec3>(camera + off::Camera_Position);
            HMODULE hmod = GetModuleHandleA(nullptr);
            if (hmod) {
                uintptr_t ve = mem<uintptr_t>((uintptr_t)hmod + off::VE_Pointer);
                if (ve > 0x10000) vm = mem<Matrix4>(ve + off::VE_ViewMatrix);
            }
        }

        std::vector<PlayerInfo> new_players;
        for (uintptr_t p : get_children(players)) {
            std::string pname = inst_name(p);
            if (pname.empty() || pname == local_name) continue;

            uintptr_t character = mem<uintptr_t>(p + off::Player_Character);
            if (character < 0x10000) continue;

            uintptr_t hrp = find_child(character, "HumanoidRootPart");
            if (!hrp) continue;

            Vec3 pos = get_part_position(hrp);
            if (pos.x == 0.0f && pos.y == 0.0f && pos.z == 0.0f) continue;

            uintptr_t humanoid = find_child(character, "Humanoid");
            float hp = 100.0f, max_hp = 100.0f;
            if (humanoid) {
                hp = mem<float>(humanoid + off::Health);
                max_hp = mem<float>(humanoid + off::MaxHealth);
                if (max_hp <= 0.0f) max_hp = 100.0f;
                if (hp < 0.0f) hp = 0.0f;
            }

            Vec2 scr = world_to_screen(pos, vm, g_screen_w, g_screen_h);
            bool on = (scr.x >= 0 && scr.x < g_screen_w && scr.y >= 0 && scr.y < g_screen_h);

            Vec3 local_pos{};
            uintptr_t lchar = mem<uintptr_t>(local_player + off::Player_Character);
            if (lchar > 0x10000) {
                uintptr_t lhrp = find_child(lchar, "HumanoidRootPart");
                if (lhrp) local_pos = get_part_position(lhrp);
            }

            PlayerInfo pi;
            pi.name = pname;
            pi.position = pos;
            pi.health = hp;
            pi.max_health = max_hp;
            pi.screen = scr;
            pi.on_screen = on;
            pi.distance = dist3d(pos, local_pos);
            new_players.push_back(pi);
        }

        { std::lock_guard<std::mutex> lk(g_mtx); g_players = std::move(new_players); }
        Sleep(16);
    }
}

// ================================================================
// IMGUI RENDERING
// ================================================================
static void render_esp() {
    auto* dl = ImGui::GetBackgroundDrawList();
    std::lock_guard<std::mutex> lk(g_mtx);

    for (const auto& p : g_players) {
        if (!p.on_screen) continue;

        float sx = p.screen.x, sy = p.screen.y;
        float scale = 1000.0f / (p.distance + 100.0f);
        float bw = 40.0f * scale, bh = 90.0f * scale;
        if (bw < 10) bw = 10; if (bh < 20) bh = 20;
        if (bw > 200) bw = 200; if (bh > 400) bh = 400;

        float ratio = (p.max_health > 0) ? p.health / p.max_health : 1.0f;
        if (ratio > 1.0f) ratio = 1.0f;
        ImU32 col = (ratio > 0.5f) ? IM_COL32(0,255,0,255)
                  : (ratio > 0.25f) ? IM_COL32(255,255,0,255)
                  : IM_COL32(255,0,0,255);

        float bx = sx - bw * 0.5f, by = sy - bh;

        if (g_boxes)
            dl->AddRect(ImVec2(bx, by), ImVec2(bx + bw, by + bh), col, 0, 0, 2.0f);

        if (g_names) {
            char buf[128];
            if (g_distance)
                snprintf(buf, sizeof(buf), "%s [%.0fm]", p.name.c_str(), p.distance);
            else
                snprintf(buf, sizeof(buf), "%s", p.name.c_str());
            ImVec2 tsz = ImGui::CalcTextSize(buf);
            dl->AddText(ImVec2(sx - tsz.x * 0.5f, by - 18), IM_COL32(255,255,255,255), buf);
        }

        if (g_health_bar) {
            float bar_x = bx - 6;
            dl->AddRectFilled(ImVec2(bar_x, by), ImVec2(bar_x + 4, by + bh), IM_COL32(40,40,40,200));
            int gh = (int)(ratio * 255), rh = (int)((1 - ratio) * 255);
            dl->AddRectFilled(ImVec2(bar_x, by + bh * (1 - ratio)),
                ImVec2(bar_x + 4, by + bh), IM_COL32(rh, gh, 0, 255));
        }

        if (g_snaplines)
            dl->AddLine(ImVec2((float)g_screen_w * 0.5f, (float)g_screen_h),
                ImVec2(sx, sy), col, 1.0f);
    }
}

static void render_menu() {
    ImGui::SetNextWindowSize(ImVec2(320, 400), ImGuiCond_FirstUseEver);
    bool open = g_menu_open.load();
    ImGui::Begin("VANTA", &open, ImGuiWindowFlags_NoCollapse);
    g_menu_open = open;

    ImGui::TextColored(ImVec4(0.8f, 0.4f, 1.0f, 1.0f), "VANTA DLL");
    ImGui::Separator();

    bool v;
    v = g_esp.load();       if (ImGui::Checkbox("ESP", &v))          g_esp = v;
    v = g_aimbot.load();    if (ImGui::Checkbox("Aimbot", &v))       g_aimbot = v;
    v = g_names.load();     if (ImGui::Checkbox("Names", &v))        g_names = v;
    v = g_health_bar.load();if (ImGui::Checkbox("Health Bars", &v))  g_health_bar = v;
    v = g_boxes.load();     if (ImGui::Checkbox("Boxes", &v))        g_boxes = v;
    v = g_snaplines.load(); if (ImGui::Checkbox("Snaplines", &v))    g_snaplines = v;
    v = g_distance.load();  if (ImGui::Checkbox("Distance", &v))     g_distance = v;

    float fov = g_aim_fov.load();
    if (ImGui::SliderFloat("Aim FOV", &fov, 50.0f, 500.0f)) g_aim_fov = fov;

    ImGui::Separator();
    {
        std::lock_guard<std::mutex> lk(g_mtx);
        ImGui::Text("Players: %d", (int)g_players.size());
    }
    ImGui::TextColored(ImVec4(0.6f, 0.6f, 0.6f, 1.0f), "[INSERT] Toggle Menu");
    ImGui::TextColored(ImVec4(1.0f, 0.4f, 0.4f, 1.0f), "[END] Eject");

    ImGui::End();
}

static void aimbot_tick() {
    if (!g_aimbot || !(GetAsyncKeyState(VK_RBUTTON) & 0x8000)) return;

    float best_dist = g_aim_fov.load();
    Vec2 best_pos = {-1, -1};
    {
        std::lock_guard<std::mutex> lk(g_mtx);
        for (const auto& p : g_players) {
            if (!p.on_screen || p.health <= 0) continue;
            float dx = p.screen.x - g_screen_w * 0.5f;
            float dy = p.screen.y - g_screen_h * 0.5f;
            float d = sqrtf(dx * dx + dy * dy);
            if (d < best_dist) { best_dist = d; best_pos = p.screen; }
        }
    }

    if (best_pos.x >= 0) {
        float dx = best_pos.x - g_screen_w * 0.5f;
        float dy = best_pos.y - g_screen_h * 0.5f;
        int mx = (int)(dx / 5.0f), my = (int)(dy / 5.0f);
        if (mx || my) mouse_event(MOUSEEVENTF_MOVE, mx, my, 0, 0);
    }
}

// ================================================================
// DX11 HOOKS
// ================================================================
static void init_imgui_style() {
    auto& s = ImGui::GetStyle();
    s.WindowRounding = 6.0f;
    s.FrameRounding = 4.0f;
    s.GrabRounding = 4.0f;
    s.WindowBorderSize = 1.0f;

    auto* c = s.Colors;
    c[ImGuiCol_WindowBg]        = ImVec4(0.06f, 0.06f, 0.10f, 0.94f);
    c[ImGuiCol_TitleBg]         = ImVec4(0.20f, 0.00f, 0.40f, 1.00f);
    c[ImGuiCol_TitleBgActive]   = ImVec4(0.35f, 0.00f, 0.60f, 1.00f);
    c[ImGuiCol_FrameBg]         = ImVec4(0.15f, 0.10f, 0.25f, 0.54f);
    c[ImGuiCol_FrameBgHovered]  = ImVec4(0.30f, 0.15f, 0.50f, 0.40f);
    c[ImGuiCol_CheckMark]       = ImVec4(0.70f, 0.30f, 1.00f, 1.00f);
    c[ImGuiCol_SliderGrab]      = ImVec4(0.50f, 0.20f, 0.80f, 1.00f);
    c[ImGuiCol_SliderGrabActive]= ImVec4(0.65f, 0.30f, 1.00f, 1.00f);
    c[ImGuiCol_Button]          = ImVec4(0.30f, 0.10f, 0.50f, 0.40f);
    c[ImGuiCol_ButtonHovered]   = ImVec4(0.40f, 0.15f, 0.65f, 1.00f);
    c[ImGuiCol_Header]          = ImVec4(0.30f, 0.10f, 0.50f, 0.31f);
    c[ImGuiCol_HeaderHovered]   = ImVec4(0.40f, 0.15f, 0.65f, 0.80f);
    c[ImGuiCol_Separator]       = ImVec4(0.40f, 0.15f, 0.65f, 0.50f);
}

static void create_render_target(IDXGISwapChain* sc) {
    ID3D11Texture2D* buf = nullptr;
    sc->GetBuffer(0, __uuidof(ID3D11Texture2D), (void**)&buf);
    if (buf) {
        g_device->CreateRenderTargetView(buf, nullptr, &g_rtv);
        buf->Release();
    }
}

static LRESULT CALLBACK hk_wndproc(HWND h, UINT m, WPARAM w, LPARAM l) {
    if (ImGui_ImplWin32_WndProcHandler(h, m, w, l)) return 1;
    if (m == WM_KEYDOWN && w == VK_INSERT) g_menu_open = !g_menu_open.load();
    if (m == WM_KEYDOWN && w == VK_END)    g_running = false;
    if (g_menu_open && m >= WM_MOUSEFIRST && m <= WM_MOUSELAST) return 0;
    if (g_menu_open && (m == WM_KEYDOWN || m == WM_KEYUP || m == WM_CHAR)) return 0;
    return CallWindowProcA(g_orig_wndproc, h, m, w, l);
}

static HRESULT __stdcall hk_present(IDXGISwapChain* sc, UINT sync, UINT flags) {
    if (!g_imgui_init) {
        sc->GetDevice(__uuidof(ID3D11Device), (void**)&g_device);
        if (g_device) {
            g_device->GetImmediateContext(&g_context);

            DXGI_SWAP_CHAIN_DESC desc{};
            sc->GetDesc(&desc);
            g_game_hwnd = desc.OutputWindow;
            g_screen_w = desc.BufferDesc.Width;
            g_screen_h = desc.BufferDesc.Height;

            ImGui::CreateContext();
            ImGuiIO& io = ImGui::GetIO();
            io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
            init_imgui_style();

            ImGui_ImplWin32_Init(g_game_hwnd);
            ImGui_ImplDX11_Init(g_device, g_context);

            create_render_target(sc);

            g_orig_wndproc = (WNDPROC)SetWindowLongPtrA(
                g_game_hwnd, GWLP_WNDPROC, (LONG_PTR)hk_wndproc);

            g_imgui_init = true;
        }
    }

    if (!g_imgui_init) return g_orig_present(sc, sync, flags);

    // update screen dimensions
    DXGI_SWAP_CHAIN_DESC desc{};
    sc->GetDesc(&desc);
    g_screen_w = desc.BufferDesc.Width;
    g_screen_h = desc.BufferDesc.Height;

    ImGui_ImplDX11_NewFrame();
    ImGui_ImplWin32_NewFrame();
    ImGui::NewFrame();

    if (g_esp) render_esp();
    if (g_menu_open) render_menu();
    aimbot_tick();

    ImGui::Render();

    if (g_rtv) {
        g_context->OMSetRenderTargets(1, &g_rtv, nullptr);
        ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());
    }

    return g_orig_present(sc, sync, flags);
}

static HRESULT __stdcall hk_resize(IDXGISwapChain* sc, UINT count, UINT w, UINT h,
    DXGI_FORMAT fmt, UINT flags) {
    if (g_rtv) { g_rtv->Release(); g_rtv = nullptr; }

    HRESULT hr = g_orig_resize(sc, count, w, h, fmt, flags);

    create_render_target(sc);
    g_screen_w = w; g_screen_h = h;
    return hr;
}

// ================================================================
// DX11 VTABLE DISCOVERY — dummy device to get function addresses
// ================================================================
static bool find_dx11_vtable(void** out_present, void** out_resize) {
    WNDCLASSEXA wc{};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = DefWindowProcA;
    wc.hInstance = GetModuleHandleA(nullptr);
    wc.lpszClassName = "VantaDummy";
    RegisterClassExA(&wc);

    HWND dummy = CreateWindowExA(0, "VantaDummy", "", WS_OVERLAPPED,
        0, 0, 1, 1, nullptr, nullptr, wc.hInstance, nullptr);
    if (!dummy) return false;

    DXGI_SWAP_CHAIN_DESC sd{};
    sd.BufferCount = 1;
    sd.BufferDesc.Width = 2;
    sd.BufferDesc.Height = 2;
    sd.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    sd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    sd.OutputWindow = dummy;
    sd.SampleDesc.Count = 1;
    sd.Windowed = TRUE;
    sd.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;

    IDXGISwapChain* sc = nullptr;
    ID3D11Device* dev = nullptr;
    D3D_FEATURE_LEVEL fl;
    HRESULT hr = D3D11CreateDeviceAndSwapChain(nullptr, D3D_DRIVER_TYPE_HARDWARE,
        nullptr, 0, nullptr, 0, D3D11_SDK_VERSION, &sd, &sc, &dev, &fl, nullptr);

    if (FAILED(hr)) {
        DestroyWindow(dummy); UnregisterClassA("VantaDummy", wc.hInstance);
        return false;
    }

    void** vtable = *(void***)sc;
    *out_present = vtable[8];
    *out_resize = vtable[13];

    sc->Release();
    dev->Release();
    DestroyWindow(dummy);
    UnregisterClassA("VantaDummy", wc.hInstance);
    return true;
}

// ================================================================
// INIT / CLEANUP
// ================================================================
static void cleanup() {
    g_running = false;
    Sleep(100);

    if (g_imgui_init) {
        ImGui_ImplDX11_Shutdown();
        ImGui_ImplWin32_Shutdown();
        ImGui::DestroyContext();
    }

    g_present_detour.remove();
    g_resize_detour.remove();

    if (g_orig_wndproc && g_game_hwnd)
        SetWindowLongPtrA(g_game_hwnd, GWLP_WNDPROC, (LONG_PTR)g_orig_wndproc);

    if (g_rtv) g_rtv->Release();
    if (g_context) g_context->Release();
    if (g_device) g_device->Release();
}

static void log_to_file(const char* msg) {
    FILE* lf = nullptr;
    fopen_s(&lf, "C:\\vanta_log.txt", "a");
    if (lf) { fprintf(lf, "%s\n", msg); fclose(lf); }
}

static DWORD WINAPI main_thread(LPVOID param) {
    log_to_file("=== VANTA DLL LOADED (DX11 build) ===");
    load_offsets_config();

    void* fn_present = nullptr;
    void* fn_resize = nullptr;

    // wait for DX11 to be ready
    for (int i = 0; i < 30 && g_running; i++) {
        if (find_dx11_vtable(&fn_present, &fn_resize)) break;
        Sleep(1000);
    }

    if (!fn_present) {
        log_to_file("FAILED: could not find DX11 Present");
        return 1;
    }
    log_to_file("DX11 vtable found, installing hooks");

    if (!g_present_detour.install(fn_present, hk_present)) {
        log_to_file("FAILED: Present hook install");
        return 1;
    }
    g_orig_present = (Present_t)g_present_detour.trampoline;

    if (fn_resize && g_resize_detour.install(fn_resize, hk_resize))
        g_orig_resize = (ResizeBuffers_t)g_resize_detour.trampoline;

    log_to_file("Hooks installed, starting scanner");

    std::thread scanner(scanner_thread);

    while (g_running) Sleep(100);

    if (scanner.joinable()) scanner.join();
    cleanup();
    log_to_file("=== VANTA EJECTED ===");
    return 0;
}

// ================================================================
// DLL ENTRY
// ================================================================
BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
        g_dll_module = hModule;
        log_to_file("DllMain: ATTACH");
        CreateThread(nullptr, 0, main_thread, hModule, 0, nullptr);
    }
    return TRUE;
}
