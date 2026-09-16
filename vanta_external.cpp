// language: C++17, file: vanta_external.cpp, target: Windows 11 x64, MSVC
// fully external — RPM-based memory read + transparent DX11 overlay
// bypasses Byfron entirely: zero code inside Roblox process

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <dwmapi.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <d3d11.h>
#include <dxgi.h>
#include <cstdint>
#include <cstdio>
#include <cmath>
#include <string>
#include <vector>
#include <thread>
#include <atomic>
#include <mutex>

#pragma comment(lib, "d3d11.lib")
#pragma comment(lib, "dxgi.lib")
#pragma comment(lib, "dwmapi.lib")
#pragma comment(lib, "psapi.lib")

#include "imgui.h"
#include "imgui_impl_win32.h"
#include "imgui_impl_dx11.h"

extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(
    HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

// ================================================================
// OFFSETS — version-4310300497aa4917
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

static void load_offsets_config(const std::string& dir) {
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
// PROCESS HELPERS
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

static uintptr_t get_module_base(DWORD pid, const wchar_t* mod_name) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    MODULEENTRY32W me{}; me.dwSize = sizeof(me);
    uintptr_t base = 0;
    if (Module32FirstW(snap, &me)) do {
        if (!_wcsicmp(me.szModule, mod_name)) { base = (uintptr_t)me.modBaseAddr; break; }
    } while (Module32NextW(snap, &me));
    CloseHandle(snap);
    return base;
}

// ================================================================
// RPM — external memory read via ReadProcessMemory
// ================================================================
static HANDLE g_proc = nullptr;

template<typename T>
static T rpm(uintptr_t addr) {
    T val{};
    ReadProcessMemory(g_proc, (LPCVOID)addr, &val, sizeof(T), nullptr);
    return val;
}

static bool rpm_buf(uintptr_t addr, void* buf, size_t sz) {
    SIZE_T rd = 0;
    return ReadProcessMemory(g_proc, (LPCVOID)addr, buf, sz, &rd) && rd == sz;
}

static std::string read_rstr(uintptr_t addr) {
    if (addr < 0x10000) return "";
    uint64_t len = rpm<uint64_t>(addr + 0x10);
    if (len == 0 || len > 200) return "";
    char buf[201]{};
    if (len > 15) {
        uintptr_t ptr = rpm<uintptr_t>(addr);
        if (ptr < 0x10000) return "";
        rpm_buf(ptr, buf, (len < 200) ? (size_t)len : 200);
    } else {
        rpm_buf(addr, buf, (len < 200) ? (size_t)len : 200);
    }
    return std::string(buf, (len < 200) ? (size_t)len : 200);
}

static std::string inst_name(uintptr_t inst) {
    return read_rstr(rpm<uintptr_t>(inst + off::Name));
}

static std::string inst_classname(uintptr_t inst) {
    uintptr_t cd = rpm<uintptr_t>(inst + off::ClassDescriptor);
    if (cd < 0x10000) return "";
    return read_rstr(rpm<uintptr_t>(cd + off::ClassName));
}

static std::vector<uintptr_t> get_children(uintptr_t inst) {
    std::vector<uintptr_t> out;
    uintptr_t cp = rpm<uintptr_t>(inst + off::Children);
    if (cp < 0x10000) return out;
    uintptr_t start = rpm<uintptr_t>(cp);
    uintptr_t end = rpm<uintptr_t>(cp + 8);
    if (start < 0x10000 || end <= start || end - start > 0x50000) return out;
    size_t count = (end - start) / 0x10;
    if (count > 500) return out;
    for (uintptr_t p = start; p < end; p += 0x10) {
        uintptr_t c = rpm<uintptr_t>(p);
        if (c > 0x10000) out.push_back(c);
    }
    return out;
}

static uintptr_t find_child(uintptr_t inst, const std::string& name) {
    for (uintptr_t c : get_children(inst))
        if (inst_name(c) == name) return c;
    return 0;
}

// ================================================================
// MATH
// ================================================================
struct Vec3 { float x, y, z; };
struct Vec2 { float x, y; };
struct Matrix4 { float m[4][4]; };

static Vec3 get_part_position(uintptr_t part) {
    uintptr_t prim = rpm<uintptr_t>(part + off::BasePart_Primitive);
    if (prim < 0x10000) return {0, 0, 0};
    return rpm<Vec3>(prim + off::Primitive_Position);
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
// PLAYER DATA + GLOBALS
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

static std::atomic<bool> g_running{true};
static std::mutex g_mtx;
static std::vector<PlayerInfo> g_players;
static uintptr_t g_roblox_base = 0;

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

// DX11 — our own device, not hooked
static ID3D11Device*           g_device  = nullptr;
static ID3D11DeviceContext*    g_context = nullptr;
static IDXGISwapChain*         g_swapchain = nullptr;
static ID3D11RenderTargetView* g_rtv     = nullptr;
static HWND g_overlay_hwnd = nullptr;
static HWND g_game_hwnd = nullptr;

// ================================================================
// DATAMODEL FINDER (external via RPM)
// ================================================================
static uintptr_t find_datamodel() {
    if (!g_roblox_base) return 0;

    uintptr_t fdm_ptr = rpm<uintptr_t>(g_roblox_base + off::FDM_Pointer);
    if (fdm_ptr > 0x10000 && fdm_ptr < 0x7FFFFFFFFFFF) {
        uintptr_t dm = rpm<uintptr_t>(fdm_ptr + off::FDM_DataModel);
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
    return 0;
}

// ================================================================
// SCANNER THREAD — reads game state via RPM
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

        uintptr_t local_player = rpm<uintptr_t>(players + off::LocalPlayer);
        if (local_player < 0x10000) { Sleep(200); continue; }
        std::string local_name = inst_name(local_player);

        uintptr_t camera = rpm<uintptr_t>(workspace + off::Workspace_CurrentCamera);
        Matrix4 vm{};
        if (camera > 0x10000) {
            uintptr_t ve = rpm<uintptr_t>(g_roblox_base + off::VE_Pointer);
            if (ve > 0x10000) vm = rpm<Matrix4>(ve + off::VE_ViewMatrix);
        }

        std::vector<PlayerInfo> new_players;
        for (uintptr_t p : get_children(players)) {
            std::string pname = inst_name(p);
            if (pname.empty() || pname == local_name) continue;

            uintptr_t character = rpm<uintptr_t>(p + off::Player_Character);
            if (character < 0x10000) continue;

            uintptr_t hrp = find_child(character, "HumanoidRootPart");
            if (!hrp) continue;

            Vec3 pos = get_part_position(hrp);
            if (pos.x == 0.0f && pos.y == 0.0f && pos.z == 0.0f) continue;

            uintptr_t humanoid = find_child(character, "Humanoid");
            float hp = 100.0f, max_hp = 100.0f;
            if (humanoid) {
                hp = rpm<float>(humanoid + off::Health);
                max_hp = rpm<float>(humanoid + off::MaxHealth);
                if (max_hp <= 0.0f) max_hp = 100.0f;
                if (hp < 0.0f) hp = 0.0f;
            }

            Vec2 scr = world_to_screen(pos, vm, g_screen_w, g_screen_h);
            bool on = (scr.x >= 0 && scr.x < g_screen_w && scr.y >= 0 && scr.y < g_screen_h);

            Vec3 local_pos{};
            uintptr_t lchar = rpm<uintptr_t>(local_player + off::Player_Character);
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

    ImGui::TextColored(ImVec4(0.8f, 0.4f, 1.0f, 1.0f), "VANTA External");
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
    ImGui::TextColored(ImVec4(1.0f, 0.4f, 0.4f, 1.0f), "[END] Exit");

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
// IMGUI STYLE
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

// ================================================================
// OVERLAY WINDOW
// ================================================================
static LRESULT CALLBACK overlay_wndproc(HWND h, UINT m, WPARAM w, LPARAM l) {
    if (g_menu_open && ImGui_ImplWin32_WndProcHandler(h, m, w, l)) return 0;
    if (m == WM_KEYDOWN && w == VK_INSERT) g_menu_open = !g_menu_open.load();
    if (m == WM_KEYDOWN && w == VK_END) { g_running = false; PostQuitMessage(0); }
    if (m == WM_DESTROY) { g_running = false; PostQuitMessage(0); return 0; }
    return DefWindowProcA(h, m, w, l);
}

static bool create_overlay(HINSTANCE hInst) {
    WNDCLASSEXA wc{};
    wc.cbSize = sizeof(wc);
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = overlay_wndproc;
    wc.hInstance = hInst;
    wc.lpszClassName = "VantaOverlay";
    RegisterClassExA(&wc);

    RECT rc;
    GetWindowRect(g_game_hwnd, &rc);
    int w = rc.right - rc.left;
    int h = rc.bottom - rc.top;
    g_screen_w = w;
    g_screen_h = h;

    g_overlay_hwnd = CreateWindowExA(
        WS_EX_TOPMOST | WS_EX_TRANSPARENT | WS_EX_LAYERED,
        "VantaOverlay", "VANTA",
        WS_POPUP,
        rc.left, rc.top, w, h,
        nullptr, nullptr, hInst, nullptr);

    if (!g_overlay_hwnd) return false;

    SetLayeredWindowAttributes(g_overlay_hwnd, RGB(0, 0, 0), 255, LWA_ALPHA);
    MARGINS margin = {-1};
    DwmExtendFrameIntoClientArea(g_overlay_hwnd, &margin);

    ShowWindow(g_overlay_hwnd, SW_SHOW);
    UpdateWindow(g_overlay_hwnd);
    return true;
}

static bool create_dx11_device() {
    DXGI_SWAP_CHAIN_DESC sd{};
    sd.BufferCount = 2;
    sd.BufferDesc.Width = g_screen_w;
    sd.BufferDesc.Height = g_screen_h;
    sd.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    sd.BufferDesc.RefreshRate.Numerator = 60;
    sd.BufferDesc.RefreshRate.Denominator = 1;
    sd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    sd.OutputWindow = g_overlay_hwnd;
    sd.SampleDesc.Count = 1;
    sd.Windowed = TRUE;
    sd.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;
    sd.Flags = DXGI_SWAP_CHAIN_FLAG_ALLOW_MODE_SWITCH;

    D3D_FEATURE_LEVEL fl;
    HRESULT hr = D3D11CreateDeviceAndSwapChain(nullptr, D3D_DRIVER_TYPE_HARDWARE,
        nullptr, 0, nullptr, 0, D3D11_SDK_VERSION,
        &sd, &g_swapchain, &g_device, &fl, &g_context);
    if (FAILED(hr)) return false;

    ID3D11Texture2D* buf = nullptr;
    g_swapchain->GetBuffer(0, __uuidof(ID3D11Texture2D), (void**)&buf);
    if (buf) {
        g_device->CreateRenderTargetView(buf, nullptr, &g_rtv);
        buf->Release();
    }
    return true;
}

// ================================================================
// MAIN
// ================================================================
int main() {
    printf("\n");
    printf("  +====================================+\n");
    printf("  |  VANTA External Overlay              |\n");
    printf("  |  RPM + Transparent DX11 Overlay      |\n");
    printf("  +====================================+\n\n");

    char exe_path[MAX_PATH];
    GetModuleFileNameA(nullptr, exe_path, MAX_PATH);
    std::string dir(exe_path);
    size_t sl = dir.find_last_of("\\/");
    if (sl != std::string::npos) dir = dir.substr(0, sl + 1);
    load_offsets_config(dir);

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

    g_proc = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!g_proc) {
        printf("[!] OpenProcess failed (%lu) — run as admin\n", GetLastError());
        system("pause"); return 1;
    }

    g_roblox_base = get_module_base(pid, L"RobloxPlayerBeta.exe");
    if (!g_roblox_base) {
        printf("[!] Failed to get Roblox base address\n");
        CloseHandle(g_proc); system("pause"); return 1;
    }
    printf("[+] Roblox base: 0x%llX\n", (unsigned long long)g_roblox_base);

    g_game_hwnd = nullptr;
    for (int i = 0; i < 30; i++) {
        g_game_hwnd = FindWindowA(nullptr, "Roblox");
        if (g_game_hwnd) break;
        Sleep(1000);
    }
    if (!g_game_hwnd) {
        printf("[!] Roblox window not found\n");
        CloseHandle(g_proc); system("pause"); return 1;
    }
    printf("[+] Roblox window found\n");

    HINSTANCE hInst = GetModuleHandleA(nullptr);

    if (!create_overlay(hInst)) {
        printf("[!] Failed to create overlay\n");
        CloseHandle(g_proc); system("pause"); return 1;
    }
    printf("[+] Overlay created (%dx%d)\n", g_screen_w, g_screen_h);

    if (!create_dx11_device()) {
        printf("[!] Failed to create DX11 device\n");
        CloseHandle(g_proc); system("pause"); return 1;
    }
    printf("[+] DX11 initialized\n");

    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO();
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
    init_imgui_style();
    ImGui_ImplWin32_Init(g_overlay_hwnd);
    ImGui_ImplDX11_Init(g_device, g_context);
    printf("[+] ImGui initialized\n");

    std::thread scanner(scanner_thread);
    printf("[+] Scanner started\n");
    printf("[+] Press INSERT for menu, END to exit\n\n");

    MSG msg{};
    while (g_running) {
        while (PeekMessageA(&msg, nullptr, 0, 0, PM_REMOVE)) {
            TranslateMessage(&msg);
            DispatchMessageA(&msg);
            if (msg.message == WM_QUIT) g_running = false;
        }
        if (!g_running) break;

        // check if Roblox is still running
        DWORD exitCode = 0;
        if (!GetExitCodeProcess(g_proc, &exitCode) || exitCode != STILL_ACTIVE) {
            printf("[*] Roblox closed\n");
            break;
        }

        // track Roblox window position/size
        RECT rc;
        if (GetWindowRect(g_game_hwnd, &rc)) {
            int w = rc.right - rc.left;
            int h = rc.bottom - rc.top;
            MoveWindow(g_overlay_hwnd, rc.left, rc.top, w, h, FALSE);
            g_screen_w = w;
            g_screen_h = h;
        }

        // toggle click-through based on menu state
        LONG_PTR exStyle = GetWindowLongPtrA(g_overlay_hwnd, GWL_EXSTYLE);
        if (g_menu_open) {
            if (exStyle & WS_EX_TRANSPARENT)
                SetWindowLongPtrA(g_overlay_hwnd, GWL_EXSTYLE, exStyle & ~WS_EX_TRANSPARENT);
        } else {
            if (!(exStyle & WS_EX_TRANSPARENT))
                SetWindowLongPtrA(g_overlay_hwnd, GWL_EXSTYLE, exStyle | WS_EX_TRANSPARENT);
        }

        // render
        ImGui_ImplDX11_NewFrame();
        ImGui_ImplWin32_NewFrame();
        ImGui::NewFrame();

        if (g_esp) render_esp();
        if (g_menu_open) render_menu();
        aimbot_tick();

        ImGui::Render();

        float clear[4] = {0, 0, 0, 0};
        g_context->OMSetRenderTargets(1, &g_rtv, nullptr);
        g_context->ClearRenderTargetView(g_rtv, clear);
        ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());
        g_swapchain->Present(1, 0);

        // register INSERT globally even when not focused
        if (GetAsyncKeyState(VK_INSERT) & 1) g_menu_open = !g_menu_open.load();
        if (GetAsyncKeyState(VK_END) & 1) { g_running = false; break; }
    }

    g_running = false;
    if (scanner.joinable()) scanner.join();

    ImGui_ImplDX11_Shutdown();
    ImGui_ImplWin32_Shutdown();
    ImGui::DestroyContext();

    if (g_rtv) g_rtv->Release();
    if (g_swapchain) g_swapchain->Release();
    if (g_context) g_context->Release();
    if (g_device) g_device->Release();
    if (g_overlay_hwnd) DestroyWindow(g_overlay_hwnd);

    CloseHandle(g_proc);
    printf("[+] VANTA exited cleanly\n");
    return 0;
}
