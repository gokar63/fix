// VANTA Roblox AI Aim Tracker — color-based external aimbot
// No injection. No offsets. Reads screen pixels, moves mouse.
// Detects player name tags (white text) or health bars (green/red)
// or custom highlight color. Smooth aim movement.

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdint>
#include <cstdio>
#include <cmath>
#include <vector>
#include <algorithm>
#include <cstring>

namespace aimbot_ns {

// ================================================================
// CONFIG
// ================================================================

struct Config {
    // Target color (default: red highlight — run ESP script first)
    int target_r = 255;
    int target_g = 0;
    int target_b = 0;
    int color_tolerance = 40;    // how close a pixel must be to target color
    
    // Aim settings
    float smoothing = 3.0f;      // 1.0 = instant snap, 5.0 = very smooth
    int fov_radius = 300;        // only aim at targets within this radius from crosshair
    float aim_speed = 0.7f;      // 0.0-1.0, how fast to move per frame
    
    // Scan settings  
    int scan_step = 4;           // check every Nth pixel (lower = more accurate, slower)
    int min_cluster = 8;         // minimum pixels of target color to count as a player
    
    // Controls
    int aim_key = VK_RBUTTON;    // right mouse button to aim
    int toggle_key = VK_F1;      // F1 to toggle on/off
    int quit_key = VK_END;       // END to quit
    int color_key = VK_F2;       // F2 to pick color under crosshair
    
    bool enabled = true;
    bool show_info = true;
};

static Config cfg;

// ================================================================
// SCREEN CAPTURE
// ================================================================

struct ScreenCapture {
    HDC screen_dc;
    HDC mem_dc;
    HBITMAP bmp;
    HBITMAP old_bmp;
    int width, height;
    uint8_t* pixels;
    BITMAPINFO bmi;
    
    bool init() {
        screen_dc = GetDC(nullptr);
        width = GetSystemMetrics(SM_CXSCREEN);
        height = GetSystemMetrics(SM_CYSCREEN);
        
        mem_dc = CreateCompatibleDC(screen_dc);
        
        memset(&bmi, 0, sizeof(bmi));
        bmi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
        bmi.bmiHeader.biWidth = width;
        bmi.bmiHeader.biHeight = -height; // top-down
        bmi.bmiHeader.biPlanes = 1;
        bmi.bmiHeader.biBitCount = 32;
        bmi.bmiHeader.biCompression = BI_RGB;
        
        bmp = CreateDIBSection(mem_dc, &bmi, DIB_RGB_COLORS, (void**)&pixels, nullptr, 0);
        if (!bmp || !pixels) return false;
        old_bmp = (HBITMAP)SelectObject(mem_dc, bmp);
        return true;
    }
    
    void capture() {
        BitBlt(mem_dc, 0, 0, width, height, screen_dc, 0, 0, SRCCOPY);
    }
    
    // Get pixel at (x, y) — returns BGR
    void get_pixel(int x, int y, uint8_t& r, uint8_t& g, uint8_t& b) const {
        if (x < 0 || x >= width || y < 0 || y >= height) { r=g=b=0; return; }
        int idx = (y * width + x) * 4;
        b = pixels[idx];
        g = pixels[idx + 1];
        r = pixels[idx + 2];
    }
    
    void cleanup() {
        SelectObject(mem_dc, old_bmp);
        DeleteObject(bmp);
        DeleteDC(mem_dc);
        ReleaseDC(nullptr, screen_dc);
    }
};

// ================================================================
// COLOR MATCHING
// ================================================================

static inline bool color_match(uint8_t r, uint8_t g, uint8_t b) {
    int dr = (int)r - cfg.target_r;
    int dg = (int)g - cfg.target_g;
    int db = (int)b - cfg.target_b;
    int dist = (int)sqrt((double)(dr*dr + dg*dg + db*db));
    return dist <= cfg.color_tolerance;
}

// ================================================================
// TARGET DETECTION — finds clusters of target-colored pixels
// ================================================================

struct Target {
    int cx, cy;     // center x, y
    int pixel_count;
    float distance;  // from crosshair
};

static std::vector<Target> find_targets(const ScreenCapture& sc) {
    int cx = sc.width / 2;
    int cy = sc.height / 2;
    
    // Scan area = FOV circle around crosshair
    int left   = std::max(0, cx - cfg.fov_radius);
    int right  = std::min(sc.width - 1, cx + cfg.fov_radius);
    int top    = std::max(0, cy - cfg.fov_radius);
    int bottom = std::min(sc.height - 1, cy + cfg.fov_radius);
    
    // Grid-based clustering: divide scan area into cells
    const int CELL = 20;
    int grid_w = (right - left) / CELL + 1;
    int grid_h = (bottom - top) / CELL + 1;
    
    struct Cell { int sum_x, sum_y, count; };
    std::vector<Cell> grid(grid_w * grid_h, {0, 0, 0});
    
    for (int y = top; y <= bottom; y += cfg.scan_step) {
        for (int x = left; x <= right; x += cfg.scan_step) {
            // Check if within FOV circle
            int dx = x - cx, dy = y - cy;
            if (dx*dx + dy*dy > cfg.fov_radius * cfg.fov_radius) continue;
            
            uint8_t r, g, b;
            sc.get_pixel(x, y, r, g, b);
            
            if (color_match(r, g, b)) {
                int gx = (x - left) / CELL;
                int gy = (y - top) / CELL;
                if (gx >= 0 && gx < grid_w && gy >= 0 && gy < grid_h) {
                    auto& c = grid[gy * grid_w + gx];
                    c.sum_x += x;
                    c.sum_y += y;
                    c.count++;
                }
            }
        }
    }
    
    // Merge adjacent cells into targets
    std::vector<Target> targets;
    std::vector<bool> visited(grid_w * grid_h, false);
    
    for (int gy = 0; gy < grid_h; gy++) {
        for (int gx = 0; gx < grid_w; gx++) {
            int idx = gy * grid_w + gx;
            if (visited[idx] || grid[idx].count < 2) continue;
            
            // Flood fill adjacent cells
            int total_x = 0, total_y = 0, total_count = 0;
            std::vector<int> stack = {idx};
            visited[idx] = true;
            
            while (!stack.empty()) {
                int ci = stack.back(); stack.pop_back();
                total_x += grid[ci].sum_x;
                total_y += grid[ci].sum_y;
                total_count += grid[ci].count;
                
                int cgx = ci % grid_w, cgy = ci / grid_w;
                for (int dy = -1; dy <= 1; dy++) {
                    for (int dx = -1; dx <= 1; dx++) {
                        int nx = cgx + dx, ny = cgy + dy;
                        if (nx < 0 || nx >= grid_w || ny < 0 || ny >= grid_h) continue;
                        int ni = ny * grid_w + nx;
                        if (!visited[ni] && grid[ni].count >= 1) {
                            visited[ni] = true;
                            stack.push_back(ni);
                        }
                    }
                }
            }
            
            if (total_count >= cfg.min_cluster) {
                Target t;
                t.cx = total_x / total_count;
                t.cy = total_y / total_count;
                t.pixel_count = total_count;
                int ddx = t.cx - cx, ddy = t.cy - cy;
                t.distance = sqrtf((float)(ddx*ddx + ddy*ddy));
                targets.push_back(t);
            }
        }
    }
    
    // Sort by distance from crosshair
    std::sort(targets.begin(), targets.end(), 
        [](const Target& a, const Target& b) { return a.distance < b.distance; });
    
    return targets;
}

// ================================================================
// SMOOTH AIM — moves mouse gradually toward target
// ================================================================

static void smooth_aim(int target_x, int target_y, int screen_cx, int screen_cy) {
    float dx = (float)(target_x - screen_cx);
    float dy = (float)(target_y - screen_cy);
    
    // Apply smoothing
    float move_x = dx / cfg.smoothing * cfg.aim_speed;
    float move_y = dy / cfg.smoothing * cfg.aim_speed;
    
    // Minimum movement threshold
    if (fabsf(move_x) < 0.5f && fabsf(move_y) < 0.5f) return;
    
    // Move mouse using relative movement
    INPUT input{};
    input.type = INPUT_MOUSE;
    input.mi.dx = (LONG)move_x;
    input.mi.dy = (LONG)move_y;
    input.mi.dwFlags = MOUSEEVENTF_MOVE;
    SendInput(1, &input, sizeof(INPUT));
}

// ================================================================
// OVERLAY — simple crosshair + FOV circle
// ================================================================

static void draw_overlay(int targets_found) {
    HDC hdc = GetDC(nullptr);
    int cx = GetSystemMetrics(SM_CXSCREEN) / 2;
    int cy = GetSystemMetrics(SM_CYSCREEN) / 2;
    
    // FOV circle
    HPEN pen = CreatePen(PS_SOLID, 1, cfg.enabled ? RGB(0, 255, 0) : RGB(255, 0, 0));
    HPEN old = (HPEN)SelectObject(hdc, pen);
    HBRUSH oldBrush = (HBRUSH)SelectObject(hdc, GetStockObject(NULL_BRUSH));
    
    Ellipse(hdc, cx - cfg.fov_radius, cy - cfg.fov_radius,
            cx + cfg.fov_radius, cy + cfg.fov_radius);
    
    // Crosshair
    MoveToEx(hdc, cx - 10, cy, nullptr); LineTo(hdc, cx + 10, cy);
    MoveToEx(hdc, cx, cy - 10, nullptr); LineTo(hdc, cx, cy + 10);
    
    SelectObject(hdc, oldBrush);
    SelectObject(hdc, old);
    DeleteObject(pen);
    ReleaseDC(nullptr, hdc);
}

// ================================================================
// COLOR PICKER — press F2 to grab color under crosshair
// ================================================================

static void pick_color(const ScreenCapture& sc) {
    int cx = sc.width / 2;
    int cy = sc.height / 2;
    uint8_t r, g, b;
    sc.get_pixel(cx, cy, r, g, b);
    cfg.target_r = r;
    cfg.target_g = g;
    cfg.target_b = b;
    printf("[+] Color picked: RGB(%d, %d, %d)\n", r, g, b);
}

// ================================================================
// MAIN
// ================================================================

int aimbot_main_impl() {
    printf("\n");
    printf("  VANTA Aim Tracker\n");
    printf("  =================\n\n");
    printf("  Controls:\n");
    printf("    Right Mouse  — aim at target\n");
    printf("    F1           — toggle on/off\n");
    printf("    F2           — pick color under crosshair\n");
    printf("    F3/F4        — decrease/increase FOV\n");
    printf("    F5/F6        — decrease/increase smoothing\n");
    printf("    END          — quit\n\n");
    
    printf("  Setup:\n");
    printf("    1. In Roblox, open settings -> set Graphics to LOW\n");
    printf("    2. Default target: RED (255,0,0)\n");
    printf("    3. For best results: use ESP script that puts\n");
    printf("       red highlights on enemies, then this locks on\n");
    printf("    4. Or press F2 on an enemy to pick their color\n\n");
    
    printf("  Color? [1=red 2=green 3=purple 4=yellow 5=white/nametag]: ");
    char ch[16]; fgets(ch, sizeof(ch), stdin);
    switch (atoi(ch)) {
        case 2: cfg.target_r=0;   cfg.target_g=255; cfg.target_b=0;   break;
        case 3: cfg.target_r=170; cfg.target_g=0;   cfg.target_b=255; break;
        case 4: cfg.target_r=255; cfg.target_g=255; cfg.target_b=0;   break;
        case 5: cfg.target_r=255; cfg.target_g=255; cfg.target_b=255;
                cfg.color_tolerance=30; cfg.min_cluster=4; break;
        default: break; // red
    }
    printf("[+] Target: RGB(%d,%d,%d) tolerance=%d\n", 
           cfg.target_r, cfg.target_g, cfg.target_b, cfg.color_tolerance);
    
    ScreenCapture sc;
    if (!sc.init()) {
        printf("[!] Screen capture init failed\n");
        system("pause"); return 1;
    }
    printf("[+] Screen: %dx%d\n", sc.width, sc.height);
    printf("[+] Running... hold Right Click to aim\n\n");
    
    int frame = 0;
    bool was_f1 = false, was_f2 = false, was_f3 = false, was_f4 = false;
    bool was_f5 = false, was_f6 = false;
    
    while (true) {
        // Quit
        if (GetAsyncKeyState(cfg.quit_key) & 0x8000) break;
        
        // Toggle
        bool f1 = GetAsyncKeyState(VK_F1) & 0x8000;
        if (f1 && !was_f1) { cfg.enabled = !cfg.enabled; printf("[*] %s\n", cfg.enabled ? "ON" : "OFF"); }
        was_f1 = f1;
        
        // FOV adjust
        bool f3 = GetAsyncKeyState(VK_F3) & 0x8000;
        if (f3 && !was_f3) { cfg.fov_radius = std::max(50, cfg.fov_radius - 50); printf("[*] FOV: %d\n", cfg.fov_radius); }
        was_f3 = f3;
        
        bool f4 = GetAsyncKeyState(VK_F4) & 0x8000;
        if (f4 && !was_f4) { cfg.fov_radius = std::min(800, cfg.fov_radius + 50); printf("[*] FOV: %d\n", cfg.fov_radius); }
        was_f4 = f4;
        
        // Smoothing adjust
        bool f5 = GetAsyncKeyState(VK_F5) & 0x8000;
        if (f5 && !was_f5) { cfg.smoothing = std::max(1.0f, cfg.smoothing - 0.5f); printf("[*] Smooth: %.1f\n", cfg.smoothing); }
        was_f5 = f5;
        
        bool f6 = GetAsyncKeyState(VK_F6) & 0x8000;
        if (f6 && !was_f6) { cfg.smoothing = std::min(10.0f, cfg.smoothing + 0.5f); printf("[*] Smooth: %.1f\n", cfg.smoothing); }
        was_f6 = f6;
        
        if (!cfg.enabled) { Sleep(50); continue; }
        
        // Capture screen
        sc.capture();
        
        // Color picker
        bool f2 = GetAsyncKeyState(VK_F2) & 0x8000;
        if (f2 && !was_f2) pick_color(sc);
        was_f2 = f2;
        
        // Aim when holding right click
        if (GetAsyncKeyState(cfg.aim_key) & 0x8000) {
            auto targets = find_targets(sc);
            
            if (!targets.empty()) {
                // Aim at closest target
                smooth_aim(targets[0].cx, targets[0].cy, sc.width / 2, sc.height / 2);
                
                if (frame % 30 == 0) {
                    printf("\r[*] targets: %zu  closest: %.0fpx  ", 
                           targets.size(), targets[0].distance);
                }
            }
        }
        
        frame++;
        Sleep(5); // ~200 FPS scan rate
    }
    
    sc.cleanup();
    printf("\n[*] done\n");
    return 0;
}
} // namespace aimbot_ns

int aimbot_main() { return aimbot_ns::aimbot_main_impl(); }
