// language: C++17, file: xeno_suite.cpp, target: Windows 11, MSVC
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdio>

int executor_main();
int esp_aimbot_main();
int aimbot_main();
int money_hack_main();
int dumper_main();

int main() {
    SetConsoleTitleA("VANTA Xeno Suite");

    while (true) {
        printf("\n");
        printf("  ==============================\n");
        printf("       VANTA — Xeno Suite\n");
        printf("  ==============================\n\n");
        printf("  [1] Lua Executor   (xeno)\n");
        printf("  [2] ESP + Aimbot   (overlay)\n");
        printf("  [3] Aimbot         (color aim)\n");
        printf("  [4] Value Editor   (money hack)\n");
        printf("  [5] Offset Dumper\n");
        printf("  [0] Exit\n\n");
        printf("  > ");

        char ch[16];
        if (!fgets(ch, sizeof(ch), stdin)) break;

        switch (ch[0]) {
            case '1': executor_main();    break;
            case '2': esp_aimbot_main();  break;
            case '3': aimbot_main();      break;
            case '4': money_hack_main();  break;
            case '5': dumper_main();      break;
            case '0': return 0;
            default:  printf("  [!] invalid\n"); break;
        }
    }
    return 0;
}
