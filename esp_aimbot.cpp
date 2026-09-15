// VANTA External ESP + Aimbot — screen-based, no injection, no offsets
// Overlay window draws ESP boxes around detected players
// Color detection: finds nametags/highlights, draws boxes, aims at nearest

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdint>
#include <cstdio>
#include <cmath>
#include <vector>
#include <algorithm>
#include <string>
#include <dwmapi.h>

#pragma comment(lib, "dwmapi.lib")

namespace esp_ns {

// ================================================================
// CONFIG
// ================================================================
struct Config {
    int target_r = 255, target_g = 255, target_b = 255; // white nametags
    int tolerance = 35;
    float smoothing = 3.0f;
    int fov = 300;
    int scan_step = 3;
    int min_cluster = 6;
    int aim_key = VK_RBUTTON;  // right click
    bool esp_enabled = true;
    bool aim_enabled = true;
    bool active = true;
    int esp_box_size = 60;     // box size around target
    // ESP colors
    int esp_r = 255, esp_g = 0, esp_b = 0; // red boxes
} cfg;

// ================================================================
// SCREEN CAPTURE
// ================================================================
struct Screen {
    HDC sdc, mdc;
    HBITMAP bmp, old;
    uint8_t* px;
    int w, h;
    BITMAPINFO bi;
    
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
        if (!bmp) return false;
        old = (HBITMAP)SelectObject(mdc, bmp);
        return true;
    }
    void capture() { BitBlt(mdc, 0, 0, w, h, sdc, 0, 0, SRCCOPY); }
    void get(int x, int y, uint8_t& r, uint8_t& g, uint8_t& b) {
        if (x<0||x>=w||y<0||y>=h){r=g=b=0;return;}
        int i=(y*w+x)*4; b=px[i]; g=px[i+1]; r=px[i+2];
    }
    void cleanup() { SelectObject(mdc,old); DeleteObject(bmp); DeleteDC(mdc); ReleaseDC(nullptr,sdc); }
};

// ================================================================
// TARGET DETECTION
// ================================================================
struct Target { int cx, cy, w, h, pixels; float dist; };

bool match(uint8_t r, uint8_t g, uint8_t b) {
    int dr=r-cfg.target_r, dg=g-cfg.target_g, db=b-cfg.target_b;
    return (int)sqrt((double)(dr*dr+dg*dg+db*db)) <= cfg.tolerance;
}

std::vector<Target> detect(Screen& sc) {
    int mx=sc.w/2, my=sc.h/2;
    int l=__max(0,mx-cfg.fov), r=__min(sc.w-1,mx+cfg.fov);
    int t=__max(0,my-cfg.fov), b=__min(sc.h-1,my+cfg.fov);
    
    const int CELL=16;
    int gw=(r-l)/CELL+1, gh=(b-t)/CELL+1;
    struct C{int sx,sy,c;}; 
    std::vector<C> grid(gw*gh,{0,0,0});
    
    for(int y=t;y<=b;y+=cfg.scan_step)
        for(int x=l;x<=r;x+=cfg.scan_step){
            int dx=x-mx,dy=y-my;
            if(dx*dx+dy*dy>cfg.fov*cfg.fov) continue;
            uint8_t cr,cg,cb; sc.get(x,y,cr,cg,cb);
            if(match(cr,cg,cb)){
                int gx=(x-l)/CELL, gy=(y-t)/CELL;
                if(gx>=0&&gx<gw&&gy>=0&&gy<gh){
                    auto& c=grid[gy*gw+gx]; c.sx+=x; c.sy+=y; c.c++;
                }
            }
        }
    
    std::vector<Target> targets;
    std::vector<bool> vis(gw*gh,false);
    
    for(int gy=0;gy<gh;gy++) for(int gx=0;gx<gw;gx++){
        int idx=gy*gw+gx;
        if(vis[idx]||grid[idx].c<2) continue;
        int tx=0,ty=0,tc=0,xmin=99999,xmax=0,ymin=99999,ymax=0;
        std::vector<int> stk={idx}; vis[idx]=true;
        while(!stk.empty()){
            int ci=stk.back(); stk.pop_back();
            tx+=grid[ci].sx; ty+=grid[ci].sy; tc+=grid[ci].c;
            int cgx=ci%gw, cgy=ci/gw;
            int px=l+cgx*CELL+CELL/2, py=t+cgy*CELL+CELL/2;
            if(px<xmin)xmin=px; if(px>xmax)xmax=px;
            if(py<ymin)ymin=py; if(py>ymax)ymax=py;
            for(int dy=-1;dy<=1;dy++) for(int dx=-1;dx<=1;dx++){
                int nx=cgx+dx, ny=cgy+dy;
                if(nx<0||nx>=gw||ny<0||ny>=gh) continue;
                int ni=ny*gw+nx;
                if(!vis[ni]&&grid[ni].c>=1){vis[ni]=true;stk.push_back(ni);}
            }
        }
        if(tc>=cfg.min_cluster){
            Target tg;
            tg.cx=tx/tc; tg.cy=ty/tc; tg.pixels=tc;
            tg.w=__max(cfg.esp_box_size,(xmax-xmin)+CELL*2);
            tg.h=__max(cfg.esp_box_size,(ymax-ymin)+CELL*2);
            int ddx=tg.cx-mx, ddy=tg.cy-my;
            tg.dist=sqrtf((float)(ddx*ddx+ddy*ddy));
            targets.push_back(tg);
        }
    }
    std::sort(targets.begin(),targets.end(),[](const Target&a,const Target&b){return a.dist<b.dist;});
    return targets;
}

// ================================================================
// OVERLAY WINDOW
// ================================================================
LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    if(msg==WM_DESTROY){PostQuitMessage(0);return 0;}
    return DefWindowProcA(hwnd,msg,wp,lp);
}

HWND create_overlay(int w, int h) {
    WNDCLASSEXA wc={sizeof(wc),CS_HREDRAW|CS_VREDRAW,WndProc,0,0,GetModuleHandle(nullptr),
        nullptr,nullptr,nullptr,nullptr,"VANTA_OVL",nullptr};
    RegisterClassExA(&wc);
    HWND hwnd=CreateWindowExA(
        WS_EX_TOPMOST|WS_EX_TRANSPARENT|WS_EX_LAYERED|WS_EX_TOOLWINDOW,
        "VANTA_OVL","",WS_POPUP,0,0,w,h,nullptr,nullptr,wc.hInstance,nullptr);
    SetLayeredWindowAttributes(hwnd,RGB(0,0,0),0,LWA_COLORKEY);
    // Make click-through
    MARGINS m={-1};
    DwmExtendFrameIntoClientArea(hwnd,&m);
    ShowWindow(hwnd,SW_SHOW);
    UpdateWindow(hwnd);
    return hwnd;
}

void draw_esp(HWND ovl, const std::vector<Target>& targets, int sw, int sh) {
    HDC hdc = GetDC(ovl);
    
    // Clear
    RECT rc={0,0,sw,sh};
    FillRect(hdc, &rc, (HBRUSH)GetStockObject(BLACK_BRUSH));
    
    if(!cfg.esp_enabled && !cfg.aim_enabled) { ReleaseDC(ovl,hdc); return; }
    
    // FOV circle
    HPEN fovPen = CreatePen(PS_SOLID, 1, cfg.active ? RGB(0,255,0) : RGB(100,100,100));
    SelectObject(hdc, fovPen);
    SelectObject(hdc, GetStockObject(NULL_BRUSH));
    int cx=sw/2, cy=sh/2;
    Ellipse(hdc, cx-cfg.fov, cy-cfg.fov, cx+cfg.fov, cy+cfg.fov);
    
    // Crosshair
    HPEN crossPen = CreatePen(PS_SOLID, 2, RGB(0,255,0));
    SelectObject(hdc, crossPen);
    MoveToEx(hdc,cx-12,cy,nullptr); LineTo(hdc,cx+12,cy);
    MoveToEx(hdc,cx,cy-12,nullptr); LineTo(hdc,cx,cy+12);
    
    if(cfg.esp_enabled) {
        HPEN boxPen = CreatePen(PS_SOLID, 2, RGB(cfg.esp_r, cfg.esp_g, cfg.esp_b));
        SelectObject(hdc, boxPen);
        
        for(size_t i=0; i<targets.size(); i++) {
            auto& tg = targets[i];
            int bx = tg.cx - tg.w/2;
            int by = tg.cy - tg.h/2;
            
            // Box
            Rectangle(hdc, bx, by, bx+tg.w, by+tg.h);
            
            // Distance text
            char buf[32];
            sprintf(buf, "%.0f", tg.dist);
            SetTextColor(hdc, RGB(cfg.esp_r, cfg.esp_g, cfg.esp_b));
            SetBkMode(hdc, TRANSPARENT);
            TextOutA(hdc, bx, by - 16, buf, (int)strlen(buf));
            
            // Line from crosshair to target (first target = aim target)
            if(i == 0 && cfg.aim_enabled) {
                HPEN linePen = CreatePen(PS_SOLID, 1, RGB(255,255,0));
                SelectObject(hdc, linePen);
                MoveToEx(hdc, cx, cy, nullptr);
                LineTo(hdc, tg.cx, tg.cy);
                SelectObject(hdc, boxPen);
                DeleteObject(linePen);
            }
        }
        DeleteObject(boxPen);
    }
    
    // Status text
    SetTextColor(hdc, RGB(0,255,0));
    SetBkMode(hdc, TRANSPARENT);
    char status[128];
    sprintf(status, "VANTA | ESP:%s AIM:%s | Targets:%d | FOV:%d | F1:toggle F2:pick F3/4:fov END:quit",
        cfg.esp_enabled?"ON":"OFF", cfg.aim_enabled?"ON":"OFF",
        (int)targets.size(), cfg.fov);
    TextOutA(hdc, 10, 10, status, (int)strlen(status));
    
    DeleteObject(fovPen);
    DeleteObject(crossPen);
    ReleaseDC(ovl, hdc);
}

// ================================================================
// SMOOTH AIM
// ================================================================
void aim(int tx, int ty, int cx, int cy) {
    float dx=(float)(tx-cx)/cfg.smoothing;
    float dy=(float)(ty-cy)/cfg.smoothing;
    if(fabsf(dx)<0.5f && fabsf(dy)<0.5f) return;
    INPUT inp={}; inp.type=INPUT_MOUSE;
    inp.mi.dx=(LONG)dx; inp.mi.dy=(LONG)dy;
    inp.mi.dwFlags=MOUSEEVENTF_MOVE;
    SendInput(1,&inp,sizeof(INPUT));
}

// ================================================================
// COLOR PICKER
// ================================================================
void pick(Screen& sc) {
    uint8_t r,g,b; sc.get(sc.w/2,sc.h/2,r,g,b);
    cfg.target_r=r; cfg.target_g=g; cfg.target_b=b;
    printf("[+] Color: RGB(%d,%d,%d)\n",r,g,b);
}

// ================================================================
// MAIN
// ================================================================
int esp_aimbot_main_impl() {
    printf("\n  VANTA ESP + Aimbot\n  ==================\n\n");
    printf("  Controls:\n");
    printf("    Right Click  = aim at closest\n");
    printf("    F1           = toggle ESP/AIM\n");
    printf("    F2           = pick color under crosshair\n");
    printf("    F3/F4        = FOV -/+\n");
    printf("    F5/F6        = smoothing -/+\n");
    printf("    F7           = toggle ESP boxes\n");
    printf("    F8           = toggle aimbot\n");
    printf("    END          = quit\n\n");
    
    printf("  Target color:\n");
    printf("    1 = white (nametags)\n");
    printf("    2 = red (ESP highlights)\n");
    printf("    3 = green\n");
    printf("    4 = purple\n");
    printf("    5 = yellow\n");
    printf("  Choice [1]: ");
    char ch[8]; fgets(ch,sizeof(ch),stdin);
    switch(atoi(ch)){
        case 2: cfg.target_r=255;cfg.target_g=0;cfg.target_b=0;cfg.tolerance=40;break;
        case 3: cfg.target_r=0;cfg.target_g=255;cfg.target_b=0;cfg.tolerance=40;break;
        case 4: cfg.target_r=170;cfg.target_g=0;cfg.target_b=255;cfg.tolerance=45;break;
        case 5: cfg.target_r=255;cfg.target_g=255;cfg.target_b=0;cfg.tolerance=40;break;
        default: cfg.tolerance=30; cfg.min_cluster=4; break;
    }
    printf("[+] Target: RGB(%d,%d,%d)\n",cfg.target_r,cfg.target_g,cfg.target_b);
    
    Screen sc;
    if(!sc.init()){printf("[!] Screen init failed\n");return 1;}
    
    HWND ovl = create_overlay(sc.w, sc.h);
    printf("[+] Overlay: %dx%d\n",sc.w,sc.h);
    printf("[+] Running...\n\n");
    
    int frame=0;
    bool kf1=0,kf2=0,kf3=0,kf4=0,kf5=0,kf6=0,kf7=0,kf8=0;
    
    while(true) {
        MSG msg;
        while(PeekMessage(&msg,nullptr,0,0,PM_REMOVE)){
            if(msg.message==WM_QUIT) goto done;
            TranslateMessage(&msg); DispatchMessage(&msg);
        }
        
        if(GetAsyncKeyState(VK_END)&0x8000) break;
        
        // Toggles
        bool f1=GetAsyncKeyState(VK_F1)&0x8000;
        if(f1&&!kf1){cfg.active=!cfg.active; printf("[*] %s\n",cfg.active?"ON":"OFF");} kf1=f1;
        
        bool f3=GetAsyncKeyState(VK_F3)&0x8000;
        if(f3&&!kf3){cfg.fov=__max(50,cfg.fov-50);printf("[*] FOV:%d\n",cfg.fov);} kf3=f3;
        bool f4=GetAsyncKeyState(VK_F4)&0x8000;
        if(f4&&!kf4){cfg.fov=__min(800,cfg.fov+50);printf("[*] FOV:%d\n",cfg.fov);} kf4=f4;
        
        bool f5=GetAsyncKeyState(VK_F5)&0x8000;
        if(f5&&!kf5){cfg.smoothing=__max(1.0f,cfg.smoothing-0.5f);printf("[*] Smooth:%.1f\n",cfg.smoothing);} kf5=f5;
        bool f6=GetAsyncKeyState(VK_F6)&0x8000;
        if(f6&&!kf6){cfg.smoothing=__min(10.0f,cfg.smoothing+0.5f);printf("[*] Smooth:%.1f\n",cfg.smoothing);} kf6=f6;
        
        bool f7=GetAsyncKeyState(VK_F7)&0x8000;
        if(f7&&!kf7){cfg.esp_enabled=!cfg.esp_enabled;printf("[*] ESP:%s\n",cfg.esp_enabled?"ON":"OFF");} kf7=f7;
        bool f8=GetAsyncKeyState(VK_F8)&0x8000;
        if(f8&&!kf8){cfg.aim_enabled=!cfg.aim_enabled;printf("[*] AIM:%s\n",cfg.aim_enabled?"ON":"OFF");} kf8=f8;
        
        if(!cfg.active){
            draw_esp(ovl,{},sc.w,sc.h);
            Sleep(50); continue;
        }
        
        sc.capture();
        
        bool f2=GetAsyncKeyState(VK_F2)&0x8000;
        if(f2&&!kf2) pick(sc); kf2=f2;
        
        auto targets = detect(sc);
        
        // Aim
        if(cfg.aim_enabled && (GetAsyncKeyState(cfg.aim_key)&0x8000) && !targets.empty()) {
            aim(targets[0].cx, targets[0].cy, sc.w/2, sc.h/2);
        }
        
        // Draw ESP
        draw_esp(ovl, targets, sc.w, sc.h);
        
        frame++;
        Sleep(5);
    }
done:
    sc.cleanup();
    DestroyWindow(ovl);
    return 0;
}
} // namespace esp_ns

int esp_aimbot_main() { return esp_ns::esp_aimbot_main_impl(); }
