// language: C++17, file: vanta_external.cpp, target: Windows 11 x64, MSVC
// fully external — RPM + transparent DX11 overlay, bypasses Byfron

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
// OFFSETS — theo's dump, version-4310300497aa4917 (15/09/2026)
// ================================================================
namespace off {
    int NameContainer      = 0x70;
    int NameOffset         = 0x8;
    int ChildrenStart      = 0x78;
    int ChildrenEnd        = 0x8;
    int Parent             = 0x68;
    int ClassDescriptor    = 0x18;
    int ClassName          = 0x8;

    int FDM_Pointer        = 0x8e42c98;
    int FDM_DataModel      = 0x1f8;

    int LocalPlayer        = 0x130;
    int ModelInstance       = 0x298;

    int CurrentCamera      = 0x4b8;

    int CameraPos          = 0xfc;
    int CameraRotation     = 0xd8;

    int BasePart_Primitive = 0x188;
    int Primitive_Position = 0xd4;
    int Primitive_Rotation = 0xb0;

    int Health             = 0x190;
    int MaxHealth          = 0x1a8;
    int Walkspeed          = 0x1d0;

    int VE_Pointer         = 0x846f768;
    int VE_ViewMatrix      = 0x1b0;
    int VE_Dimensions      = 0xb10;
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
            if (k == "NameContainer") off::NameContainer = val;
            else if (k == "NameOffset") off::NameOffset = val;
            else if (k == "ChildrenStart") off::ChildrenStart = val;
            else if (k == "ChildrenEnd") off::ChildrenEnd = val;
            else if (k == "Parent") off::Parent = val;
            else if (k == "FDM_Pointer") off::FDM_Pointer = val;
            else if (k == "FDM_DataModel") off::FDM_DataModel = val;
            else if (k == "LocalPlayer") off::LocalPlayer = val;
            else if (k == "CurrentCamera") off::CurrentCamera = val;
            else if (k == "BasePart_Primitive") off::BasePart_Primitive = val;
            else if (k == "Primitive_Position") off::Primitive_Position = val;
            else if (k == "Primitive_Rotation") off::Primitive_Rotation = val;
            else if (k == "Health") off::Health = val;
            else if (k == "MaxHealth") off::MaxHealth = val;
            else if (k == "Walkspeed") off::Walkspeed = val;
            else if (k == "ModelInstance") off::ModelInstance = val;
            else if (k == "VE_Pointer") off::VE_Pointer = val;
            else if (k == "VE_ViewMatrix") off::VE_ViewMatrix = val;
            else if (k == "VE_Dimensions") off::VE_Dimensions = val;
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
// RPM — external memory read
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

// SSO-aware string read: len < 16 = inline, else heap pointer
static std::string read_rstr(uintptr_t addr) {
    if (addr < 0x10000) return "";
    uint64_t len = rpm<uint64_t>(addr + 0x10);
    if (len == 0 || len > 200) return "";
    char buf[201]{};
    if (len >= 16) {
        uintptr_t ptr = rpm<uintptr_t>(addr);
        if (ptr < 0x10000) return "";
        rpm_buf(ptr, buf, (len < 200) ? (size_t)len : 200);
    } else {
        rpm_buf(addr, buf, (size_t)len);
    }
    return std::string(buf, (len < 200) ? (size_t)len : 200);
}

// theo's two-level name read: inst+0x70 -> NameContainer, +0x8 -> string ptr
static std::string inst_name(uintptr_t inst) {
    uintptr_t nc = rpm<uintptr_t>(inst + off::NameContainer);
    if (nc < 0x10000) return "";
    return read_rstr(rpm<uintptr_t>(nc + off::NameOffset));
}

static std::string inst_classname(uintptr_t inst) {
    uintptr_t cd = rpm<uintptr_t>(inst + off::ClassDescriptor);
    if (cd < 0x10000) return "";
    return read_rstr(rpm<uintptr_t>(cd + off::ClassName));
}

// theo's children layout: ChildrenStart(0x78) -> container, start at +0, end at +8, stride 0x10
static std::vector<uintptr_t> get_children(uintptr_t inst) {
    std::vector<uintptr_t> out;
    uintptr_t cp = rpm<uintptr_t>(inst + off::ChildrenStart);
    if (cp < 0x10000) return out;
    uintptr_t start = rpm<uintptr_t>(cp);
    uintptr_t end = rpm<uintptr_t>(cp + off::ChildrenEnd);
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

static uintptr_t find_child_of_class(uintptr_t inst, const std::string& cls) {
    for (uintptr_t c : get_children(inst))
        if (inst_classname(c) == cls) return c;
    return 0;
}

// ================================================================
// MATH
// ================================================================
struct Vec3 { float x, y, z; };
struct Vec2 { float x, y; };
struct ViewMatrix { float data[16]; };

static Vec3 get_part_position(uintptr_t part) {
    uintptr_t prim = rpm<uintptr_t>(part + off::BasePart_Primitive);
    if (prim < 0x10000) return {0, 0, 0};
    return rpm<Vec3>(prim + off::Primitive_Position);
}

static Vec2 world_to_screen(const Vec3& world, const ViewMatrix& vm, float dims_x, float dims_y) {
    float qx = (world.x * vm.data[0]) + (world.y * vm.data[1]) + (world.z * vm.data[2]) + vm.data[3];
    float qy = (world.x * vm.data[4]) + (world.y * vm.data[5]) + (world.z * vm.data[6]) + vm.data[7];
    float qw = (world.x * vm.data[12]) + (world.y * vm.data[13]) + (world.z * vm.data[14]) + vm.data[15];

    if (qw < 0.1f) return {-1, -1};

    float inv_w = 1.0f / qw;
    float ndc_x = qx * inv_w;
    float ndc_y = qy * inv_w;

    float screen_x = (dims_x * 0.5f * ndc_x) + (ndc_x + dims_x * 0.5f);
    float screen_y = -(dims_y * 0.5f * ndc_y) + (ndc_y + dims_y * 0.5f);

    return { screen_x, screen_y };
}

static float dist3d(Vec3 a, Vec3 b) {
    float dx = a.x - b.x, dy = a.y - b.y, dz = a.z - b.z;
    return sqrtf(dx * dx + dy * dy + dz * dz);
}

// ================================================================
// PLAYER DATA + GLOBALS
// ================================================================
struct PlayerInfo {
    std::string name;
    Vec3 head_pos;
    Vec3 root_pos;
    float health;
    float max_health;
    Vec2 head_screen;
    Vec2 feet_screen;
    Vec2 root_screen;
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
static float g_screen_w = 1920.0f, g_screen_h = 1080.0f;

static ID3D11Device*           g_device    = nullptr;
static ID3D11DeviceContext*    g_context   = nullptr;
static IDXGISwapChain*         g_swapchain = nullptr;
static ID3D11RenderTargetView* g_rtv       = nullptr;
static HWND g_overlay_hwnd = nullptr;
static HWND g_game_hwnd    = nullptr;

// ================================================================
// DATAMODEL — FakeDataModelPointer path (DEBUG BUILD)
// ================================================================
static uintptr_t find_datamodel() {
    if (!g_roblox_base) return 0;

    printf("[DBG] base=0x%llX, FDM_Pointer offset=0x%X\n",
        (unsigned long long)g_roblox_base, off::FDM_Pointer);

    uintptr_t fdm_ptr = rpm<uintptr_t>(g_roblox_base + off::FDM_Pointer);
    printf("[DBG] fdm_ptr=0x%llX\n", (unsigned long long)fdm_ptr);
    if (fdm_ptr < 0x10000 || fdm_ptr > 0x7FFFFFFFFFFF) {
        printf("[DBG] fdm_ptr INVALID — chain broken at step 1\n");
        return 0;
    }

    uintptr_t dm = rpm<uintptr_t>(fdm_ptr + off::FDM_DataModel);
    printf("[DBG] dm=0x%llX (fdm_ptr+0x%X)\n", (unsigned long long)dm, off::FDM_DataModel);
    if (dm < 0x10000) {
        printf("[DBG] dm INVALID — chain broken at step 2\n");
        return 0;
    }

    auto ch = get_children(dm);
    printf("[DBG] dm children count: %d\n", (int)ch.size());
    int known = 0;
    for (auto c : ch) {
        std::string n = inst_name(c);
        if (!n.empty()) printf("[DBG]   child: '%s'\n", n.c_str());
        if (n == "Workspace" || n == "Players" || n == "Lighting" ||
            n == "ReplicatedStorage" || n == "StarterGui")
            known++;
    }
    printf("[DBG] known services: %d\n", known);
    return (known >= 3) ? dm : 0;
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
        if (!players) { Sleep(500); continue; }

        uintptr_t local_player = rpm<uintptr_t>(players + off::LocalPlayer);
        if (local_player < 0x10000) { Sleep(200); continue; }
        std::string local_name = inst_name(local_player);

        uintptr_t ve = rpm<uintptr_t>(g_roblox_base + off::VE_Pointer);
        ViewMatrix vm{};
        if (ve > 0x10000) {
            vm = rpm<ViewMatrix>(ve + off::VE_ViewMatrix);
        }

        Vec2 dims = {g_screen_w, g_screen_h};
        if (ve > 0x10000) {
            float dw = rpm<float>(ve + off::VE_Dimensions);
            float dh = rpm<float>(ve + off::VE_Dimensions + 4);
            if (dw > 100 && dh > 100) { dims.x = dw; dims.y = dh; }
        }

        Vec3 local_pos{};
        uintptr_t lchar = rpm<uintptr_t>(local_player + off::ModelInstance);
        if (lchar > 0x10000) {
            uintptr_t lhrp = find_child(lchar, "HumanoidRootPart");
            if (lhrp) local_pos = get_part_position(lhrp);
        }

        std::vector<PlayerInfo> new_players;
        for (uintptr_t p : get_children(players)) {
            std::string pname = inst_name(p);
            if (pname.empty() || pname == local_name) continue;

            uintptr_t character = rpm<uintptr_t>(p + off::ModelInstance);
            if (character < 0x10000) continue;

            uintptr_t head = find_child(character, "Head");
            uintptr_t hrp = find_child(character, "HumanoidRootPart");
            if (!hrp) continue;

            Vec3 root_pos = get_part_position(hrp);
            if (root_pos.x == 0.0f && root_pos.y == 0.0f && root_pos.z == 0.0f) continue;

            Vec3 head_pos = head ? get_part_position(head) : root_pos;
            Vec3 head_top = { head_pos.x, head_pos.y + 2.5f, head_pos.z };
            Vec3 feet_pos = { root_pos.x, root_pos.y - 3.5f, root_pos.z };

            uintptr_t humanoid = find_child(character, "Humanoid");
            float hp = 100.0f, max_hp = 100.0f;
            if (humanoid) {
                hp = rpm<float>(humanoid + off::Health);
                max_hp = rpm<float>(humanoid + off::MaxHealth);
                if (max_hp <= 0.0f) max_hp = 100.0f;
                if (hp < 0.0f) hp = 0.0f;
            }

            Vec2 head_scr = world_to_screen(head_top, vm, dims.x, dims.y);
            Vec2 feet_scr = world_to_screen(feet_pos, vm, dims.x, dims.y);
            Vec2 root_scr = world_to_screen(root_pos, vm, dims.x, dims.y);

            bool on = (head_scr.x >= 0 && feet_scr.x >= 0 &&
                       head_scr.x < dims.x && head_scr.y >= 0 &&
                       feet_scr.y < dims.y);

            PlayerInfo pi;
            pi.name = pname;
            pi.head_pos = head_pos;
            pi.root_pos = root_pos;
            pi.health = hp;
            pi.max_health = max_hp;
            pi.head_screen = head_scr;
            pi.feet_screen = feet_scr;
            pi.root_screen = root_scr;
            pi.on_screen = on;
            pi.distance = dist3d(root_pos, local_pos);
            new_players.push_back(pi);
        }

        { std::lock_guard<std::mutex> lk(g_mtx); g_players = std::move(new_players); }
        Sleep(16);
    }
}

// ================================================================
// ESP RENDERING
// ================================================================
static void draw_outlined_text(ImDrawList* dl, ImVec2 pos, ImU32 col, const char* text) {
    ImU32 shadow = IM_COL32(0, 0, 0, 200);
    for (int dx = -1; dx <= 1; dx++)
        for (int dy = -1; dy <= 1; dy++)
            if (dx || dy)
                dl->AddText(ImVec2(pos.x + dx, pos.y + dy), shadow, text);
    dl->AddText(pos, col, text);
}

static void render_esp() {
    auto* dl = ImGui::GetBackgroundDrawList();
    std::lock_guard<std::mutex> lk(g_mtx);

    for (const auto& p : g_players) {
        if (!p.on_screen) continue;

        float box_height = p.feet_screen.y - p.head_screen.y;
        if (box_height < 10.0f) continue;
        float box_width = box_height / 1.6f;

        float cx = (p.head_screen.x + p.feet_screen.x) * 0.5f;
        float bx = cx - box_width * 0.5f;
        float by = p.head_screen.y;

        float ratio = (p.max_health > 0) ? p.health / p.max_health : 1.0f;
        if (ratio > 1.0f) ratio = 1.0f;
        ImU32 col = (ratio > 0.5f) ? IM_COL32(0, 255, 0, 255)
                  : (ratio > 0.25f) ? IM_COL32(255, 255, 0, 255)
                  : IM_COL32(255, 0, 0, 255);

        if (g_boxes) {
            dl->AddRect(ImVec2(bx - 1, by - 1),
                        ImVec2(bx + box_width + 1, by + box_height + 1),
                        IM_COL32(0, 0, 0, 180), 0, 0, 3.0f);
            dl->AddRect(ImVec2(bx, by),
                        ImVec2(bx + box_width, by + box_height),
                        col, 0, 0, 1.5f);
        }

        if (g_names) {
            char buf[128];
            if (g_distance)
                snprintf(buf, sizeof(buf), "%s [%.0fm]", p.name.c_str(), p.distance);
            else
                snprintf(buf, sizeof(buf), "%s", p.name.c_str());
            ImVec2 tsz = ImGui::CalcTextSize(buf);
            draw_outlined_text(dl, ImVec2(cx - tsz.x * 0.5f, by - 18), IM_COL32(255, 255, 255, 255), buf);
        }

        if (g_health_bar) {
            float bar_x = bx - 6;
            dl->AddRectFilled(ImVec2(bar_x, by), ImVec2(bar_x + 4, by + box_height), IM_COL32(40, 40, 40, 200));
            int gh = (int)(ratio * 255), rh = (int)((1 - ratio) * 255);
            dl->AddRectFilled(ImVec2(bar_x, by + box_height * (1 - ratio)),
                ImVec2(bar_x + 4, by + box_height), IM_COL32(rh, gh, 0, 255));
        }

        if (g_snaplines)
            dl->AddLine(ImVec2(g_screen_w * 0.5f, g_screen_h),
                ImVec2(p.root_screen.x, p.root_screen.y), col, 1.0f);
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
    ImGui::TextColored(ImVec4(0.6f, 0.6f, 0.6f, 1.0f), "[DELETE] Toggle Menu");
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
            float dx = p.head_screen.x - g_screen_w * 0.5f;
            float dy = p.head_screen.y - g_screen_h * 0.5f;
            float d = sqrtf(dx * dx + dy * dy);
            if (d < best_dist) { best_dist = d; best_pos = p.head_screen; }
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
    if (m == WM_DESTROY) { g_running = false; PostQuitMessage(0); return 0; }
    return DefWindowProcA(h, m, w, l);
}

static bool is_fullscreen(HWND hwnd) {
    RECT wr;
    GetWindowRect(hwnd, &wr);
    HMONITOR mon = MonitorFromWindow(hwnd, MONITOR_DEFAULTTONEAREST);
    MONITORINFO mi{}; mi.cbSize = sizeof(mi);
    GetMonitorInfo(mon, &mi);
    return (wr.left == mi.rcMonitor.left && wr.top == mi.rcMonitor.top &&
            wr.right == mi.rcMonitor.right && wr.bottom == mi.rcMonitor.bottom);
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
    if (is_fullscreen(g_game_hwnd)) {
        HMONITOR mon = MonitorFromWindow(g_game_hwnd, MONITOR_DEFAULTTONEAREST);
        MONITORINFO mi{}; mi.cbSize = sizeof(mi);
        GetMonitorInfo(mon, &mi);
        rc = mi.rcMonitor;
    } else {
        GetWindowRect(g_game_hwnd, &rc);
    }

    int w = rc.right - rc.left;
    int h = rc.bottom - rc.top;
    g_screen_w = (float)w;
    g_screen_h = (float)h;

    g_overlay_hwnd = CreateWindowExA(
        WS_EX_TOPMOST | WS_EX_TRANSPARENT | WS_EX_LAYERED | WS_EX_NOACTIVATE | WS_EX_TOOLWINDOW,
        "VantaOverlay", "",
        WS_POPUP,
        rc.left, rc.top, w, h,
        nullptr, nullptr, hInst, nullptr);

    if (!g_overlay_hwnd) return false;

    SetLayeredWindowAttributes(g_overlay_hwnd, RGB(0, 0, 0), 255, LWA_ALPHA);
    MARGINS margin = {-1};
    DwmExtendFrameIntoClientArea(g_overlay_hwnd, &margin);

    ShowWindow(g_overlay_hwnd, SW_SHOWNOACTIVATE);
    UpdateWindow(g_overlay_hwnd);
    return true;
}

static bool create_dx11_device() {
    DXGI_SWAP_CHAIN_DESC sd{};
    sd.BufferCount = 2;
    sd.BufferDesc.Width = (UINT)g_screen_w;
    sd.BufferDesc.Height = (UINT)g_screen_h;
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
    printf("  |  DEBUG BUILD — theo offsets           |\n");
    printf("  +====================================+\n\n");

    char exe_path[MAX_PATH];
    GetModuleFileNameA(nullptr, exe_path, MAX_PATH);
    std::string dir(exe_path);
    size_t sl = dir.find_last_of("\\\/");
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
    printf("[+] Overlay created (%.0fx%.0f)\n", g_screen_w, g_screen_h);

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
    printf("[+] Press DELETE for menu, END to exit\n\n");

    MSG msg{};
    while (g_running) {
        while (PeekMessageA(&msg, nullptr, 0, 0, PM_REMOVE)) {
            TranslateMessage(&msg);
            DispatchMessageA(&msg);
            if (msg.message == WM_QUIT) g_running = false;
        }
        if (!g_running) break;

        DWORD exitCode = 0;
        if (!GetExitCodeProcess(g_proc, &exitCode) || exitCode != STILL_ACTIVE) {
            printf("[*] Roblox closed\n");
            break;
        }

        HWND fg = GetForegroundWindow();
        if (fg != g_game_hwnd && fg != g_overlay_hwnd) {
            ShowWindow(g_overlay_hwnd, SW_HIDE);
            Sleep(100);
            continue;
        }
        if (!IsWindowVisible(g_overlay_hwnd))
            ShowWindow(g_overlay_hwnd, SW_SHOWNOACTIVATE);

        RECT rc;
        if (is_fullscreen(g_game_hwnd)) {
            HMONITOR mon = MonitorFromWindow(g_game_hwnd, MONITOR_DEFAULTTONEAREST);
            MONITORINFO mi{}; mi.cbSize = sizeof(mi);
            GetMonitorInfo(mon, &mi);
            rc = mi.rcMonitor;
        } else {
            GetWindowRect(g_game_hwnd, &rc);
        }
        int w = rc.right - rc.left;
        int h = rc.bottom - rc.top;
        MoveWindow(g_overlay_hwnd, rc.left, rc.top, w, h, FALSE);
        g_screen_w = (float)w;
        g_screen_h = (float)h;

        if (GetAsyncKeyState(VK_DELETE) & 1) g_menu_open = !g_menu_open.load();
        if (GetAsyncKeyState(VK_END) & 1) { g_running = false; break; }

        LONG_PTR exStyle = GetWindowLongPtrA(g_overlay_hwnd, GWL_EXSTYLE);
        if (g_menu_open) {
            if (exStyle & WS_EX_TRANSPARENT)
                SetWindowLongPtrA(g_overlay_hwnd, GWL_EXSTYLE, exStyle & ~WS_EX_TRANSPARENT);
        } else {
            if (!(exStyle & WS_EX_TRANSPARENT))
                SetWindowLongPtrA(g_overlay_hwnd, GWL_EXSTYLE, exStyle | WS_EX_TRANSPARENT);
        }

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
