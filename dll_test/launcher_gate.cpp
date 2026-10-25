#include "launcher_gate.h"

#include <windows.h>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <cwchar>

namespace
{
constexpr uint32_t kGateMagic = 0x39534C47u; // "GLS9"
constexpr uint32_t kGateVersion = 1;
constexpr uint32_t kMaxPids = 256;
constexpr DWORD kStartupWaitMs = 5000;
constexpr DWORD kHeartbeatTimeoutMs = 5000;
constexpr DWORD kWatchdogIntervalMs = 1000;
constexpr int kMaxConsecutiveFailures = 2;
constexpr wchar_t kMappingName[] = L"Local\\9sLauncherGate_v1";
constexpr wchar_t kMutexName[] = L"Local\\9sLauncherGateMutex_v1";
constexpr wchar_t kLauncherTitle[] = L"9s啟動器";

#pragma pack(push, 8)
struct GateState
{
    uint32_t magic;
    uint32_t version;
    uint32_t launcherPid;
    uint32_t allowedCount;
    uint64_t token;
    uint64_t heartbeat;
    uint32_t pids[kMaxPids];
};
#pragma pack(pop)

static_assert(sizeof(GateState) == 1056, "GateState layout must match 9s launcher");

HANDLE g_mapping = nullptr;
void* g_view = nullptr;
HANDLE g_mutex = nullptr;
uint64_t g_token = 0;
DWORD g_launcherPid = 0;
HWND g_launcherHwnd = nullptr;
volatile LONG g_watchdogStop = 0;

bool ReadState(GateState& state)
{
    if (!g_view)
        return false;

    if (g_mutex)
    {
        const DWORD wait = WaitForSingleObject(g_mutex, INFINITE);
        if (wait != WAIT_OBJECT_0 && wait != WAIT_ABANDONED)
            return false;
    }

    std::memcpy(&state, g_view, sizeof(state));
    if (g_mutex)
        ReleaseMutex(g_mutex);
    return true;
}

bool HasPid(const GateState& state, DWORD pid)
{
    const uint32_t count = state.allowedCount < kMaxPids ? state.allowedCount : kMaxPids;
    for (uint32_t i = 0; i < count; ++i)
    {
        if (state.pids[i] == pid)
            return true;
    }
    return false;
}

bool HeartbeatFresh(uint64_t heartbeat)
{
    if (heartbeat == 0)
        return false;

    const uint64_t now = GetTickCount64();
    return now >= heartbeat && now - heartbeat <= kHeartbeatTimeoutMs;
}

bool ProcessAlive(DWORD pid)
{
    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, pid);
    if (!process)
        return false;

    DWORD exitCode = 0;
    const bool alive = GetExitCodeProcess(process, &exitCode) && exitCode == STILL_ACTIVE;
    CloseHandle(process);
    return alive;
}

bool WindowBelongsToLauncher(HWND hwnd, DWORD pid)
{
    if (!hwnd || !IsWindow(hwnd))
        return false;

    DWORD ownerPid = 0;
    GetWindowThreadProcessId(hwnd, &ownerPid);
    if (ownerPid != pid)
        return false;

    wchar_t title[128]{};
    GetWindowTextW(hwnd, title, static_cast<int>(sizeof(title) / sizeof(title[0])));
    return _wcsicmp(title, kLauncherTitle) == 0;
}

HWND LauncherHwndFromCommandLine()
{
    const wchar_t* commandLine = GetCommandLineW();
    if (!commandLine)
        return nullptr;

    // 路徑可能含空白且未加引號；從第一個 .EXE 後面找 argv[1]（啟動器 HWND）。
    const wchar_t* cursor = nullptr;
    for (const wchar_t* p = commandLine; *p; ++p)
    {
        if (p[0] == L'.' &&
            (p[1] == L'e' || p[1] == L'E') &&
            (p[2] == L'x' || p[2] == L'X') &&
            (p[3] == L'e' || p[3] == L'E'))
        {
            cursor = p + 4;
            break;
        }
    }
    if (!cursor)
        return nullptr;

    while (*cursor == L' ' || *cursor == L'\t' || *cursor == L'"')
        ++cursor;

    uintptr_t value = 0;
    bool hasDigit = false;
    while (*cursor >= L'0' && *cursor <= L'9')
    {
        value = value * 10 + static_cast<uintptr_t>(*cursor - L'0');
        hasDigit = true;
        ++cursor;
    }
    if (!hasDigit || value == 0)
        return nullptr;

    return reinterpret_cast<HWND>(value);
}

bool ValidateState(const GateState& state, DWORD selfPid)
{
    if (state.magic != kGateMagic || state.version != kGateVersion)
        return false;
    if (state.launcherPid == 0 || state.token == 0)
        return false;
    if (!HeartbeatFresh(state.heartbeat))
        return false;
    if (!HasPid(state, selfPid))
        return false;
    if (!ProcessAlive(state.launcherPid))
        return false;
    if (!WindowBelongsToLauncher(g_launcherHwnd, state.launcherPid))
        return false;
    return true;
}

void CloseGateHandles()
{
    if (g_view)
    {
        UnmapViewOfFile(g_view);
        g_view = nullptr;
    }
    if (g_mutex)
    {
        CloseHandle(g_mutex);
        g_mutex = nullptr;
    }
    if (g_mapping)
    {
        CloseHandle(g_mapping);
        g_mapping = nullptr;
    }
}

DWORD WINAPI WatchdogThread(LPVOID)
{
    const DWORD selfPid = GetCurrentProcessId();
    int failures = 0;

    while (InterlockedCompareExchange(&g_watchdogStop, 0, 0) == 0)
    {
        Sleep(kWatchdogIntervalMs);

        GateState state{};
        const bool ok =
            ReadState(state) &&
            state.token == g_token &&
            state.launcherPid == g_launcherPid &&
            ValidateState(state, selfPid);

        if (ok)
        {
            failures = 0;
            continue;
        }

        if (++failures >= kMaxConsecutiveFailures)
        {
            LauncherGate::TerminateSelf();
            return 0;
        }
    }
    return 0;
}
}

namespace LauncherGate
{
bool ValidateAndStart()
{
    g_mapping = OpenFileMappingW(FILE_MAP_READ, FALSE, kMappingName);
    if (!g_mapping)
        return false;

    g_view = MapViewOfFile(g_mapping, FILE_MAP_READ, 0, 0, sizeof(GateState));
    if (!g_view)
    {
        CloseGateHandles();
        return false;
    }

    g_mutex = OpenMutexW(MUTEX_MODIFY_STATE | SYNCHRONIZE, FALSE, kMutexName);
    g_launcherHwnd = LauncherHwndFromCommandLine();
    if (!g_launcherHwnd)
    {
        CloseGateHandles();
        return false;
    }

    const DWORD selfPid = GetCurrentProcessId();
    const ULONGLONG deadline = GetTickCount64() + kStartupWaitMs;
    GateState state{};
    bool accepted = false;

    for (;;)
    {
        if (ReadState(state) && ValidateState(state, selfPid))
        {
            accepted = true;
            break;
        }
        if (GetTickCount64() >= deadline)
            break;
        Sleep(50);
    }

    if (!accepted)
    {
        CloseGateHandles();
        return false;
    }

    g_token = state.token;
    g_launcherPid = state.launcherPid;

    HANDLE watchdog = CreateThread(nullptr, 0, WatchdogThread, nullptr, 0, nullptr);
    if (!watchdog)
    {
        CloseGateHandles();
        return false;
    }
    CloseHandle(watchdog);
    return true;
}

void TerminateSelf()
{
    TerminateProcess(GetCurrentProcess(), 0x39A00001u);
    ExitProcess(0x39A00001u);
}
}
