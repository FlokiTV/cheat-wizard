#include <windows.h>

#if defined(CW_CRT_ENTRY_GUI)
extern "C" void guiCRTStartup();
int WINAPI WinMain(HINSTANCE, HINSTANCE, LPSTR, int) {
    guiCRTStartup();
    return 0;
}
#elif defined(CW_CRT_ENTRY_TRAINER)
extern "C" void trainerCRTStartup();
int WINAPI WinMain(HINSTANCE, HINSTANCE, LPSTR, int) {
    trainerCRTStartup();
    return 0;
}
#elif defined(CW_CRT_ENTRY_BUILDER)
extern "C" void builderCRTStartup();
int main() {
    builderCRTStartup();
    return 0;
}
#else
#error Define one CW_CRT_ENTRY_* target selector.
#endif
