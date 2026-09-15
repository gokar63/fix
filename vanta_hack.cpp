// language: C++17, file: vanta_hack.cpp, target: Windows 11, MSVC
// VANTA Roblox Suite — integrated external hack
// ESP + Aimbot + Radar + Lua Executor + Value Editor
// External only — no injection, no DLL, reads screen pixels + process memory

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <dwmapi.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <cstdint>
#include <cstdio>
#include <cmath>
#include <cstring>
#include <vector>
#include <string>
#include <algorithm>
#include <thread>
#include <mutex>
#include <atomic>
#include <fstream>
#include <sstream>
#include <functional>

#pragma comment(lib, "dwmapi.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "advapi32.lib")

// forward — Lua executor from worker
int executor_main();

// ================================================================
// GLOBALS
// ================================================================
struct HackConfig {
    // ESP
    std::atomic<bool> esp_enabled{true};
    int esp_box_size = 60;
    int esp_r = 255, esp_g = 0, esp_b = 0;

    // Aimbot
    std::atomic<bool> aim_enabled{true};
    float smoothing = 3.0f;
    float aim_speed = 0.7f;
    int fov = 300;
    int aim_key = VK_RBUTTON;

    // Color detection
    int target_r = 255, target_g = 0, target_b = 0;
    int tolerance = 40;
    int scan_step = 4;
    int min_cluster = 8;

    // Radar
    std::atomic<bool> radar_enabled{true};
    int radar_size = 180;
    int radar_x = 20, radar_y = 80;

    // Master
    std::atomic<bool> active{true};
    std::atomic<bool> overlay_running{true};
    std::atomic<bool> show_menu{false};
};

static HackConfig cfg;

// ================================================================
// SCREEN CAPTURE
// ================================================================
struct ScreenCap {
    HDC sdc = nullptr, mdc = nullptr;
    HBITMAP bmp = nullptr, old_bmp = nullptr;
    uint8_t* px = nullptr;
    int w = 0, h = 0;
    BITMAPINFO bi{};

    bool init() {
        sdc = GetDC(nullptr);
        w = GetSystemMetrics(SM_CXSCREEN);
        h = GetSystemMetrics(SM_CYSCREEN);
        mdc = CreateCompatibleDC(sdc);
        memset(&bi, 0, sizeof(bi));
        bi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
        bi.bmiHeader.biWidth = w;
        bi.bmiHeader.biHeight = -h;
        bi.bmiHeader.biPlanes = 1;
        bi.bmiHeader.biBitCount = 32;
        bi.bmiHeader.biCompression = BI_RGB;
        bmp = CreateDIBSection(mdc, &bi, DIB_RGB_COLORS, (void**)&px, nullptr, 0);
        if (!bmp || !px) return false;
        old_bmp = (HBITMAP)SelectObject(mdc, bmp);
        return true;
    }

    void capture() {
        BitBlt(mdc, 0, 0, w, h, sdc, 0, 0, SRCCOPY);
    }

    void get(int x, int y, uint8_t& r, uint8_t& g, uint8_t& b) const {
        if (x < 0 || x >= w || y < 0 || y >= h) { r = g = b = 0; return; }
        int i = (y * w + x) * 4;
        b = px[i]; g = px[i + 1]; r = px[i + 2];
    }

    void cleanup() {
        if (mdc) { SelectObject(mdc, old_bmp); DeleteDC(mdc); }
        if (bmp) DeleteObject(bmp);
        if (sdc) ReleaseDC(nullptr, sdc);
    }
};

// ================================================================
// TARGET DETECTION
// ================================================================
struct Target {
    int cx, cy, bw, bh, pixels;
    float dist;
};

static bool color_match(uint8_t r, uint8_t g, uint8_t b) {
    int dr = (int)r - cfg.target_r;
    int dg = (int)g - cfg.target_g;
    int db = (int)b - cfg.target_b;
    return (int)sqrt((double)(dr*dr + dg*dg + db*db)) <= cfg.tolerance;
}

static std::vector<Target> find_targets(const ScreenCap& sc) {
    int mx = sc.w / 2, my = sc.h / 2;
    int left   = (std::max)(0, mx - cfg.fov);
    int right  = (std::min)(sc.w - 1, mx + cfg.fov);
    int top    = (std::max)(0, my - cfg.fov);
    int bottom = (std::min)(sc.h - 1, my + cfg.fov);

    const int CELL = 18;
    int gw = (right - left) / CELL + 1;
    int gh = (bottom - top) / CELL + 1;

    struct Cell { int sx, sy, c; };
    std::vector<Cell> grid(gw * gh, {0, 0, 0});

    for (int y = top; y <= bottom; y += cfg.scan_step) {
        for (int x = left; x <= right; x += cfg.scan_step) {
            int dx = x - mx, dy = y - my;
            if (dx*dx + dy*dy > cfg.fov * cfg.fov) continue;
            uint8_t r, g, b;
            sc.get(x, y, r, g, b);
            if (color_match(r, g, b)) {
                int gx = (x - left) / CELL, gy = (y - top) / CELL;
                if (gx >= 0 && gx < gw && gy >= 0 && gy < gh) {
                    auto& c = grid[gy * gw + gx];
                    c.sx += x; c.sy += y; c.c++;
                }
            }
        }
    }

    std::vector<Target> targets;
    std::vector<bool> vis(gw * gh, false);

    for (int gy = 0; gy < gh; gy++) {
        for (int gx = 0; gx < gw; gx++) {
            int idx = gy * gw + gx;
            if (vis[idx] || grid[idx].c < 2) continue;

            int tx = 0, ty = 0, tc = 0;
            int xmin = 99999, xmax = 0, ymin = 99999, ymax = 0;
            std::vector<int> stk = {idx};
            vis[idx] = true;

            while (!stk.empty()) {
                int ci = stk.back(); stk.pop_back();
                tx += grid[ci].sx; ty += grid[ci].sy; tc += grid[ci].c;
                int cgx = ci % gw, cgy = ci / gw;
                int px = left + cgx * CELL + CELL / 2;
                int py = top + cgy * CELL + CELL / 2;
                if (px < xmin) xmin = px; if (px > xmax) xmax = px;
                if (py < ymin) ymin = py; if (py > ymax) ymax = py;

                for (int dy = -1; dy <= 1; dy++) {
                    for (int dx = -1; dx <= 1; dx++) {
                        int nx = cgx + dx, ny = cgy + dy;
                        if (nx < 0 || nx >= gw || ny < 0 || ny >= gh) continue;
                        int ni = ny * gw + nx;
                        if (!vis[ni] && grid[ni].c >= 1) {
                            vis[ni] = true;
                            stk.push_back(ni);
                        }
                    }
                }
            }

            if (tc >= cfg.min_cluster) {
                Target t;
                t.cx = tx / tc; t.cy = ty / tc; t.pixels = tc;
                t.bw = (std::max)(cfg.esp_box_size, (xmax - xmin) + CELL * 2);
                t.bh = (std::max)(cfg.esp_box_size, (ymax - ymin) + CELL * 2);
                int ddx = t.cx - mx, ddy = t.cy - my;
                t.dist = sqrtf((float)(ddx*ddx + ddy*ddy));
                targets.push_back(t);
            }
        }
    }

    std::sort(targets.begin(), targets.end(),
        [](const Target& a, const Target& b) { return a.dist < b.dist; });
    return targets;
}

// ================================================================
// SMOOTH AIM
// ================================================================
static void smooth_aim(int tx, int ty, int cx, int cy) {
    float dx = (float)(tx - cx) / cfg.smoothing * cfg.aim_speed;
    float dy = (float)(ty - cy) / cfg.smoothing * cfg.aim_speed;
    if (fabsf(dx) < 0.5f && fabsf(dy) < 0.5f) return;

    INPUT inp{};
    inp.type = INPUT_MOUSE;
    inp.mi.dx = (LONG)dx;
    inp.mi.dy = (LONG)dy;
    inp.mi.dwFlags = MOUSEEVENTF_MOVE;
    SendInput(1, &inp, sizeof(INPUT));
}

// ================================================================
// OVERLAY WINDOW
// ================================================================
static LRESULT CALLBACK OvlProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    if (msg == WM_DESTROY) { PostQuitMessage(0); return 0; }
    return DefWindowProcA(hwnd, msg, wp, lp);
}

static HWND create_overlay(int w, int h) {
    WNDCLASSEXA wc = {sizeof(wc)};
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = OvlProc;
    wc.hInstance = GetModuleHandle(nullptr);
    wc.lpszClassName = "VANTA_OVERLAY";
    RegisterClassExA(&wc);

    HWND hwnd = CreateWindowExA(
        WS_EX_TOPMOST | WS_EX_TRANSPARENT | WS_EX_LAYERED | WS_EX_TOOLWINDOW,
        "VANTA_OVERLAY", "", WS_POPUP,
        0, 0, w, h,
        nullptr, nullptr, wc.hInstance, nullptr);

    SetLayeredWindowAttributes(hwnd, RGB(0, 0, 0), 0, LWA_COLORKEY);
    MARGINS m = {-1};
    DwmExtendFrameIntoClientArea(hwnd, &m);
    ShowWindow(hwnd, SW_SHOW);
    UpdateWindow(hwnd);
    return hwnd;
}

// ================================================================
// DRAW — ESP + RADAR + HUD
// ================================================================
static void draw_frame(HWND ovl, const std::vector<Target>& targets, int sw, int sh) {
    HDC hdc = GetDC(ovl);
    RECT rc = {0, 0, sw, sh};
    FillRect(hdc, &rc, (HBRUSH)GetStockObject(BLACK_BRUSH));

    int cx = sw / 2, cy = sh / 2;

    // --- FOV circle ---
    HPEN fovPen = CreatePen(PS_SOLID, 1, cfg.active ? RGB(0, 255, 0) : RGB(100, 100, 100));
    SelectObject(hdc, fovPen);
    SelectObject(hdc, GetStockObject(NULL_BRUSH));
    Ellipse(hdc, cx - cfg.fov, cy - cfg.fov, cx + cfg.fov, cy + cfg.fov);

    // --- Crosshair ---
    HPEN crossPen = CreatePen(PS_SOLID, 2, RGB(0, 255, 0));
    SelectObject(hdc, crossPen);
    MoveToEx(hdc, cx - 14, cy, nullptr); LineTo(hdc, cx + 14, cy);
    MoveToEx(hdc, cx, cy - 14, nullptr); LineTo(hdc, cx, cy + 14);

    // --- ESP boxes ---
    if (cfg.esp_enabled) {
        HPEN boxPen = CreatePen(PS_SOLID, 2, RGB(cfg.esp_r, cfg.esp_g, cfg.esp_b));
        SelectObject(hdc, boxPen);

        for (size_t i = 0; i < targets.size(); i++) {
            auto& t = targets[i];
            int bx = t.cx - t.bw / 2, by = t.cy - t.bh / 2;
            Rectangle(hdc, bx, by, bx + t.bw, by + t.bh);

            // distance label
            char buf[32];
            sprintf(buf, "%.0f", t.dist);
            SetTextColor(hdc, RGB(cfg.esp_r, cfg.esp_g, cfg.esp_b));
            SetBkMode(hdc, TRANSPARENT);
            TextOutA(hdc, bx, by - 16, buf, (int)strlen(buf));

            // aim line to closest
            if (i == 0 && cfg.aim_enabled) {
                HPEN linePen = CreatePen(PS_SOLID, 1, RGB(255, 255, 0));
                SelectObject(hdc, linePen);
                MoveToEx(hdc, cx, cy, nullptr);
                LineTo(hdc, t.cx, t.cy);
                SelectObject(hdc, boxPen);
                DeleteObject(linePen);
            }
        }
        DeleteObject(boxPen);
    }

    // --- RADAR minimap ---
    if (cfg.radar_enabled && !targets.empty()) {
        int rx = cfg.radar_x, ry = cfg.radar_y;
        int rs = cfg.radar_size;

        // radar background
        HBRUSH radarBg = CreateSolidBrush(RGB(10, 10, 10));
        RECT radarRect = {rx, ry, rx + rs, ry + rs};
        FillRect(hdc, &radarRect, radarBg);
        DeleteObject(radarBg);

        // radar border
        HPEN radarBorder = CreatePen(PS_SOLID, 2, RGB(0, 200, 0));
        SelectObject(hdc, radarBorder);
        SelectObject(hdc, GetStockObject(NULL_BRUSH));
        Rectangle(hdc, rx, ry, rx + rs, ry + rs);

        // radar grid lines
        HPEN gridPen = CreatePen(PS_SOLID, 1, RGB(30, 60, 30));
        SelectObject(hdc, gridPen);
        MoveToEx(hdc, rx + rs/2, ry, nullptr); LineTo(hdc, rx + rs/2, ry + rs);
        MoveToEx(hdc, rx, ry + rs/2, nullptr); LineTo(hdc, rx + rs, ry + rs/2);

        // "RADAR" label
        SetTextColor(hdc, RGB(0, 200, 0));
        SetBkMode(hdc, TRANSPARENT);
        TextOutA(hdc, rx + 4, ry + 2, "RADAR", 5);

        // you = center dot
        HBRUSH selfDot = CreateSolidBrush(RGB(0, 255, 0));
        RECT selfR = {rx + rs/2 - 3, ry + rs/2 - 3, rx + rs/2 + 3, ry + rs/2 + 3};
        FillRect(hdc, &selfR, selfDot);
        DeleteObject(selfDot);

        // enemy dots — mapped from screen position to radar
        float scale = (float)rs / (float)(cfg.fov * 2);
        HBRUSH enemyDot = CreateSolidBrush(RGB(255, 0, 0));
        for (auto& t : targets) {
            int dx = t.cx - cx, dy = t.cy - cy;
            int rdx = rx + rs/2 + (int)(dx * scale);
            int rdy = ry + rs/2 + (int)(dy * scale);
            if (rdx >= rx + 4 && rdx <= rx + rs - 4 && rdy >= ry + 4 && rdy <= ry + rs - 4) {
                RECT dot = {rdx - 3, rdy - 3, rdx + 3, rdy + 3};
                FillRect(hdc, &dot, enemyDot);
            }
        }
        DeleteObject(enemyDot);

        DeleteObject(radarBorder);
        DeleteObject(gridPen);
    }

    // --- HUD status bar ---
    SetTextColor(hdc, RGB(0, 255, 0));
    SetBkMode(hdc, TRANSPARENT);
    char status[256];
    sprintf(status,
        "VANTA | ESP:%s  AIM:%s  RADAR:%s | Targets:%d | FOV:%d | Smooth:%.1f",
        cfg.esp_enabled.load() ? "ON" : "OFF",
        cfg.aim_enabled.load() ? "ON" : "OFF",
        cfg.radar_enabled.load() ? "ON" : "OFF",
        (int)targets.size(), cfg.fov, cfg.smoothing);
    TextOutA(hdc, 10, 10, status, (int)strlen(status));

    // --- Hotkey help ---
    const char* help =
        "F1:Master  F2:PickColor  F3/F4:FOV  F5/F6:Smooth  F7:ESP  F8:AIM  F9:Radar  F10:Executor  END:Quit";
    TextOutA(hdc, 10, sh - 22, help, (int)strlen(help));

    // --- Menu overlay ---
    if (cfg.show_menu) {
        HBRUSH menuBg = CreateSolidBrush(RGB(15, 15, 15));
        RECT menuR = {sw/2 - 200, sh/2 - 160, sw/2 + 200, sh/2 + 160};
        FillRect(hdc, &menuR, menuBg);
        DeleteObject(menuBg);

        HPEN menuBorder = CreatePen(PS_SOLID, 2, RGB(0, 255, 0));
        SelectObject(hdc, menuBorder);
        Rectangle(hdc, sw/2 - 200, sh/2 - 160, sw/2 + 200, sh/2 + 160);

        SetTextColor(hdc, RGB(0, 255, 0));
        int my = sh/2 - 140;
        const char* lines[] = {
            "===== VANTA MENU (INSERT to close) =====",
            "",
            "  [F1]  Master Toggle",
            "  [F2]  Pick Color Under Crosshair",
            "  [F3]  FOV -50    [F4] FOV +50",
            "  [F5]  Smooth -   [F6] Smooth +",
            "  [F7]  Toggle ESP",
            "  [F8]  Toggle Aimbot",
            "  [F9]  Toggle Radar",
            "  [F10] Open Lua Executor (console)",
            "  [F11] Open Value Editor (console)",
            "",
            "  [END] Quit",
            "",
            "  Right Click = Aim at target",
        };
        for (auto& line : lines) {
            TextOutA(hdc, sw/2 - 180, my, line, (int)strlen(line));
            my += 18;
        }
        DeleteObject(menuBorder);
    }

    DeleteObject(fovPen);
    DeleteObject(crossPen);
    ReleaseDC(ovl, hdc);
}

// ================================================================
// VALUE EDITOR (console thread)
// ================================================================
namespace valeditor {

static DWORD find_roblox_pid() {
    HANDLE s = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32W pe{}; pe.dwSize = sizeof(pe); DWORD pid = 0;
    if (Process32FirstW(s, &pe)) do {
        if (!_wcsicmp(pe.szExeFile, L"RobloxPlayerBeta.exe")) { pid = pe.th32ProcessID; break; }
    } while (Process32NextW(s, &pe));
    CloseHandle(s); return pid;
}

struct ScanResult { uintptr_t address; };

template<typename T>
std::vector<ScanResult> scan_value(HANDLE proc, T target) {
    std::vector<ScanResult> results;
    MEMORY_BASIC_INFORMATION mbi{};
    uintptr_t addr = 0x10000;
    while (VirtualQueryEx(proc, (LPCVOID)addr, &mbi, sizeof(mbi))) {
        if (mbi.State == MEM_COMMIT &&
            (mbi.Protect & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE | PAGE_WRITECOPY)) &&
            !(mbi.Protect & PAGE_GUARD) && mbi.Type != MEM_MAPPED) {
            std::vector<uint8_t> buf(mbi.RegionSize);
            SIZE_T rd = 0;
            if (ReadProcessMemory(proc, mbi.BaseAddress, buf.data(), mbi.RegionSize, &rd) && rd >= sizeof(T)) {
                for (size_t i = 0; i + sizeof(T) <= rd; i += 4) {
                    if (*(T*)(buf.data() + i) == target)
                        results.push_back({(uintptr_t)mbi.BaseAddress + i});
                }
            }
        }
        addr = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
        if (addr < (uintptr_t)mbi.BaseAddress) break;
    }
    return results;
}

template<typename T>
std::vector<ScanResult> filter_value(HANDLE proc, const std::vector<ScanResult>& prev, T target) {
    std::vector<ScanResult> results;
    for (auto& r : prev) {
        T val{};
        if (ReadProcessMemory(proc, (LPCVOID)r.address, &val, sizeof(T), nullptr) && val == target)
            results.push_back(r);
    }
    return results;
}

template<typename T>
bool write_value(HANDLE proc, uintptr_t addr, T val) {
    DWORD old;
    VirtualProtectEx(proc, (LPVOID)addr, sizeof(T), PAGE_EXECUTE_READWRITE, &old);
    SIZE_T written = 0;
    BOOL ok = WriteProcessMemory(proc, (LPVOID)addr, &val, sizeof(T), &written);
    VirtualProtectEx(proc, (LPVOID)addr, sizeof(T), old, &old);
    return ok && written == sizeof(T);
}

static void run_editor() {
    printf("\n  === VANTA Value Editor ===\n\n");

    DWORD pid = find_roblox_pid();
    if (!pid) { printf("[!] Roblox not found\n"); return; }

    HANDLE proc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!proc) { printf("[!] OpenProcess failed — run as admin\n"); return; }
    printf("[+] Roblox PID: %lu\n", pid);
    printf("  Type a number to scan, 'set' to write, 'back' to return\n\n");

    std::vector<ScanResult> results;
    bool first = true;
    char line[256];

    while (true) {
        if (!results.empty() && results.size() <= 20) {
            printf("\n--- %zu matches ---\n", results.size());
            for (size_t i = 0; i < results.size(); i++) {
                int32_t v; ReadProcessMemory(proc, (LPCVOID)results[i].address, &v, 4, nullptr);
                printf("  [%zu] 0x%llX = %d\n", i, (uint64_t)results[i].address, v);
            }
        }
        printf("\n> ");
        if (!fgets(line, sizeof(line), stdin)) break;
        line[strcspn(line, "\r\n")] = 0;

        if (!strcmp(line, "back") || !strcmp(line, "b")) break;
        if (!strcmp(line, "reset") || !strcmp(line, "r")) {
            results.clear(); first = true;
            printf("[*] Reset\n"); continue;
        }
        if (!strcmp(line, "set") || !strcmp(line, "s")) {
            if (results.empty()) { printf("[!] no results\n"); continue; }
            printf("  New value: "); fgets(line, sizeof(line), stdin);
            line[strcspn(line, "\r\n")] = 0;
            int32_t nv = atoi(line); int count = 0;
            for (auto& r : results) if (write_value(proc, r.address, nv)) count++;
            printf("[+] Written to %d addresses\n", count);
            continue;
        }
        if (!strcmp(line, "freeze") || !strcmp(line, "f")) {
            if (results.empty()) { printf("[!] no results\n"); continue; }
            printf("  Value to freeze: "); fgets(line, sizeof(line), stdin);
            line[strcspn(line, "\r\n")] = 0;
            int32_t nv = atoi(line);
            printf("[*] Freezing... press Ctrl+C to stop\n");
            while (!(GetAsyncKeyState(VK_F11) & 0x8000)) {
                for (auto& r : results) write_value(proc, r.address, nv);
                Sleep(50);
            }
            continue;
        }

        if (first) {
            printf("[*] Scanning...\n");
            results = scan_value<int32_t>(proc, atoi(line));
            first = false;
        } else {
            printf("[*] Filtering...\n");
            results = filter_value<int32_t>(proc, results, atoi(line));
        }
        printf("[+] %zu matches\n", results.size());
    }
    CloseHandle(proc);
}

} // namespace valeditor

// ================================================================
// COLOR PICKER
// ================================================================
static void pick_color(const ScreenCap& sc) {
    uint8_t r, g, b;
    sc.get(sc.w / 2, sc.h / 2, r, g, b);
    cfg.target_r = r; cfg.target_g = g; cfg.target_b = b;
    printf("[+] Color picked: RGB(%d, %d, %d)\n", r, g, b);
}

// ================================================================
// OVERLAY THREAD — runs ESP + aimbot + radar loop
// ================================================================
static void overlay_thread() {
    ScreenCap sc;
    if (!sc.init()) {
        printf("[!] Screen capture failed\n");
        return;
    }

    HWND ovl = create_overlay(sc.w, sc.h);
    printf("[+] Overlay started: %dx%d\n", sc.w, sc.h);

    bool kf1 = false, kf2 = false, kf3 = false, kf4 = false;
    bool kf5 = false, kf6 = false, kf7 = false, kf8 = false;
    bool kf9 = false, kins = false;
    int frame = 0;

    while (cfg.overlay_running) {
        if (GetAsyncKeyState(VK_END) & 0x8000) {
            cfg.overlay_running = false;
            break;
        }

        // INSERT = toggle menu
        bool ins = GetAsyncKeyState(VK_INSERT) & 0x8000;
        if (ins && !kins) cfg.show_menu = !cfg.show_menu.load();
        kins = ins;

        // F1 = master toggle
        bool f1 = GetAsyncKeyState(VK_F1) & 0x8000;
        if (f1 && !kf1) {
            cfg.active = !cfg.active.load();
            printf("[*] %s\n", cfg.active.load() ? "ACTIVE" : "PAUSED");
        }
        kf1 = f1;

        // F3/F4 = FOV
        bool f3 = GetAsyncKeyState(VK_F3) & 0x8000;
        if (f3 && !kf3) { cfg.fov = (std::max)(50, cfg.fov - 50); printf("[*] FOV: %d\n", cfg.fov); }
        kf3 = f3;
        bool f4 = GetAsyncKeyState(VK_F4) & 0x8000;
        if (f4 && !kf4) { cfg.fov = (std::min)(800, cfg.fov + 50); printf("[*] FOV: %d\n", cfg.fov); }
        kf4 = f4;

        // F5/F6 = smoothing
        bool f5 = GetAsyncKeyState(VK_F5) & 0x8000;
        if (f5 && !kf5) { cfg.smoothing = (std::max)(1.0f, cfg.smoothing - 0.5f); printf("[*] Smooth: %.1f\n", cfg.smoothing); }
        kf5 = f5;
        bool f6 = GetAsyncKeyState(VK_F6) & 0x8000;
        if (f6 && !kf6) { cfg.smoothing = (std::min)(10.0f, cfg.smoothing + 0.5f); printf("[*] Smooth: %.1f\n", cfg.smoothing); }
        kf6 = f6;

        // F7 = ESP toggle
        bool f7 = GetAsyncKeyState(VK_F7) & 0x8000;
        if (f7 && !kf7) { cfg.esp_enabled = !cfg.esp_enabled.load(); printf("[*] ESP: %s\n", cfg.esp_enabled.load() ? "ON" : "OFF"); }
        kf7 = f7;

        // F8 = AIM toggle
        bool f8 = GetAsyncKeyState(VK_F8) & 0x8000;
        if (f8 && !kf8) { cfg.aim_enabled = !cfg.aim_enabled.load(); printf("[*] AIM: %s\n", cfg.aim_enabled.load() ? "ON" : "OFF"); }
        kf8 = f8;

        // F9 = Radar toggle
        bool f9 = GetAsyncKeyState(VK_F9) & 0x8000;
        if (f9 && !kf9) { cfg.radar_enabled = !cfg.radar_enabled.load(); printf("[*] RADAR: %s\n", cfg.radar_enabled.load() ? "ON" : "OFF"); }
        kf9 = f9;

        if (!cfg.active) {
            draw_frame(ovl, {}, sc.w, sc.h);
            Sleep(50);
            continue;
        }

        sc.capture();

        // F2 = color picker
        bool f2 = GetAsyncKeyState(VK_F2) & 0x8000;
        if (f2 && !kf2) pick_color(sc);
        kf2 = f2;

        auto targets = find_targets(sc);

        // Aimbot
        if (cfg.aim_enabled && (GetAsyncKeyState(cfg.aim_key) & 0x8000) && !targets.empty()) {
            smooth_aim(targets[0].cx, targets[0].cy, sc.w / 2, sc.h / 2);
        }

        // Draw everything
        draw_frame(ovl, targets, sc.w, sc.h);

        if (frame % 60 == 0 && !targets.empty()) {
            printf("\r[*] %zu targets | closest: %.0fpx  ", targets.size(), targets[0].dist);
        }

        frame++;
        Sleep(5);
    }

    sc.cleanup();
    DestroyWindow(ovl);
}

// ================================================================
// MAIN
// ================================================================
int main() {
    SetConsoleTitleA("VANTA Roblox Suite");

    // Enable debug privilege
    {
        HANDLE t;
        if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &t)) {
            TOKEN_PRIVILEGES tp{};
            LookupPrivilegeValueA(nullptr, "SeDebugPrivilege", &tp.Privileges[0].Luid);
            tp.PrivilegeCount = 1;
            tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
            AdjustTokenPrivileges(t, FALSE, &tp, sizeof(tp), nullptr, nullptr);
            CloseHandle(t);
        }
    }

    printf("\n");
    printf("  ╔═══════════════════════════════════════╗\n");
    printf("  ║         VANTA — Roblox Suite          ║\n");
    printf("  ║   ESP + Aimbot + Radar + Executor     ║\n");
    printf("  ╚═══════════════════════════════════════╝\n\n");

    printf("  [!] Run as Administrator\n\n");

    // Color selection
    printf("  Target color:\n");
    printf("    [1] Red (default — use with ESP highlights)\n");
    printf("    [2] Green\n");
    printf("    [3] Purple\n");
    printf("    [4] Yellow\n");
    printf("    [5] White (nametags)\n");
    printf("  > ");
    char ch[16]; fgets(ch, sizeof(ch), stdin);
    switch (ch[0]) {
        case '2': cfg.target_r=0;   cfg.target_g=255; cfg.target_b=0;   break;
        case '3': cfg.target_r=170; cfg.target_g=0;   cfg.target_b=255; break;
        case '4': cfg.target_r=255; cfg.target_g=255; cfg.target_b=0;   break;
        case '5': cfg.target_r=255; cfg.target_g=255; cfg.target_b=255;
                  cfg.tolerance=30; cfg.min_cluster=4; break;
        default:  break;
    }
    printf("\n  [+] Color: RGB(%d,%d,%d)\n", cfg.target_r, cfg.target_g, cfg.target_b);

    printf("\n  Starting overlay...\n");
    printf("  ─────────────────────────────────\n");
    printf("  INSERT     = open/close menu\n");
    printf("  F1         = master toggle\n");
    printf("  F2         = pick color under crosshair\n");
    printf("  F3/F4      = FOV -/+\n");
    printf("  F5/F6      = smoothing -/+\n");
    printf("  F7         = toggle ESP\n");
    printf("  F8         = toggle aimbot\n");
    printf("  F9         = toggle radar\n");
    printf("  F10        = open Lua executor\n");
    printf("  F11        = open value editor\n");
    printf("  Right Click= aim at closest target\n");
    printf("  END        = quit\n");
    printf("  ─────────────────────────────────\n\n");

    // Start overlay in background thread
    std::thread ovl_thread(overlay_thread);
    ovl_thread.detach();

    Sleep(500);

    // Console command loop — for Lua executor and value editor access
    printf("[+] Overlay running. Type commands here:\n");
    printf("    'exec' or press F10  = Lua Executor\n");
    printf("    'edit' or press F11  = Value Editor\n");
    printf("    'quit'               = Exit\n\n");

    bool kf10 = false, kf11 = false;

    while (cfg.overlay_running) {
        // Check F10/F11 hotkeys
        bool f10 = GetAsyncKeyState(VK_F10) & 0x8000;
        if (f10 && !kf10) {
            printf("\n[*] Opening Lua Executor...\n");
            executor_main();
            printf("\n[*] Back to main. Overlay still running.\n");
        }
        kf10 = f10;

        bool f11 = GetAsyncKeyState(VK_F11) & 0x8000;
        if (f11 && !kf11) {
            printf("\n[*] Opening Value Editor...\n");
            valeditor::run_editor();
            printf("\n[*] Back to main. Overlay still running.\n");
        }
        kf11 = f11;

        // Check console input (non-blocking would be ideal but fgets blocks)
        // So we just poll hotkeys here
        Sleep(100);
    }

    printf("\n[*] Shutting down...\n");
    Sleep(300);
    return 0;
}
