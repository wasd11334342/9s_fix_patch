#include <windows.h>
#include <cstdio>
#include <cstdint>
#include <cstring>

namespace
{
HHOOK g_msgBoxHook = nullptr;
constexpr uintptr_t kPatchOffset = 0x4AA10;
constexpr DWORD kMessageBoxAutoCloseMs = 5000;

const BYTE kPatchBytes[] = {
    0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x14, 0xC7, 0x45,
    0xEC, 0x00, 0x00, 0x00, 0x2D, 0x66, 0xC7, 0x45,
    0xF0, 0x00, 0x02, 0xC7, 0x45, 0xF2, 0x00, 0x00,
    0x00, 0x0B, 0xC7, 0x45, 0xF6, 0x00, 0x00, 0x00,
    0x00, 0x8D, 0x45, 0xEC, 0x6A, 0x0E, 0x50, 0x68,
    0x04, 0x02, 0x00, 0x00, 0xE8, 0x1F, 0xF9, 0xFF,
    0xFF, 0x8B, 0xE5, 0x5D, 0xC2, 0x04, 0x00, 0x90,
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    0x90, 0x90, 0x90, 0x90
};

bool PatchBytes(void* address, const void* patch, size_t size)
{
    DWORD oldProtect = 0;
    if (!VirtualProtect(address, size, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        return false;
    }

    std::memcpy(address, patch, size);
    FlushInstructionCache(GetCurrentProcess(), address, size);

    DWORD unusedProtect = 0;
    return VirtualProtect(address, size, oldProtect, &unusedProtect) != FALSE;
}

DWORD WINAPI CloseMessageBoxThread(LPVOID hwndParam)
{
    Sleep(kMessageBoxAutoCloseMs);

    HWND hwnd = reinterpret_cast<HWND>(hwndParam);
    if (IsWindow(hwnd)) {
        PostMessageA(hwnd, WM_COMMAND, IDOK, 0);
    }

    return 0;
}

LRESULT CALLBACK MessageBoxHook(int code, WPARAM wParam, LPARAM lParam)
{
    HHOOK currentHook = g_msgBoxHook;

    if (code == HCBT_ACTIVATE) {
        HWND hwnd = reinterpret_cast<HWND>(wParam);
        RECT windowRect{};
        MONITORINFO monitorInfo{ sizeof(monitorInfo) };

        if (GetWindowRect(hwnd, &windowRect) &&
            GetMonitorInfoA(MonitorFromWindow(hwnd, MONITOR_DEFAULTTONEAREST), &monitorInfo)) {
            const int width = windowRect.right - windowRect.left;
            const int height = windowRect.bottom - windowRect.top;
            const int margin = 20;
            const int x = monitorInfo.rcWork.right - width - margin;
            const int y = monitorInfo.rcWork.bottom - height - margin;

            SetWindowPos(hwnd, nullptr, x, y, 0, 0, SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE);
        }

        HANDLE closeThread = CreateThread(nullptr, 0, CloseMessageBoxThread, hwnd, 0, nullptr);
        if (closeThread) {
            CloseHandle(closeThread);
        }

        if (g_msgBoxHook) {
            UnhookWindowsHookEx(g_msgBoxHook);
            g_msgBoxHook = nullptr;
        }
    }

    return CallNextHookEx(currentHook, code, wParam, lParam);
}
}

DWORD WINAPI MainThread(LPVOID)
{
    HMODULE mainModule = GetModuleHandleA(nullptr);
    uintptr_t base = reinterpret_cast<uintptr_t>(mainModule);
    void* patchAddress = reinterpret_cast<void*>(base + kPatchOffset);
    const bool patched = PatchBytes(patchAddress, kPatchBytes, sizeof(kPatchBytes));

    const DWORD pid = GetCurrentProcessId();
    char message[128]{};
    std::snprintf(
        message,
        sizeof(message),
        "PID: %lu\nPID hex: 0x%lX\nBase: 0x%p\nPatch %s\nAddress: 0x%p",
        pid,
        pid,
        reinterpret_cast<void*>(base),
        patched ? "OK" : "FAILED",
        patchAddress);

    g_msgBoxHook = SetWindowsHookExA(WH_CBT, MessageBoxHook, nullptr, GetCurrentThreadId());
    MessageBoxA(nullptr, message, "MyPatch", MB_OK);
    if (g_msgBoxHook) {
        UnhookWindowsHookEx(g_msgBoxHook);
        g_msgBoxHook = nullptr;
    }
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
        CreateThread(nullptr, 0, MainThread, nullptr, 0, nullptr);
    }
    return TRUE;
}

extern "C" __declspec(dllexport)
void InitPatch()
{
}
