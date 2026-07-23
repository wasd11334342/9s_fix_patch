#include "native_optimization.h"

#include <psapi.h>
#include <cstring>

namespace
{
constexpr uintptr_t kDeleteDcIatOffset = 0x1C41B0;
constexpr DWORD kSampleIntervalMs = 5000;

using DeleteDcFn = BOOL(WINAPI*)(HDC);

SRWLOCK g_snapshotLock = SRWLOCK_INIT;
NativeOptimizationSnapshot g_snapshot{};
DeleteDcFn g_originalDeleteDc = nullptr;
void** g_deleteDcSlot = nullptr;
volatile LONG g_installed = 0;
volatile LONG g_lastSampleTick = 0;
volatile LONG g_nativeLogItems = -1;
volatile LONG g_nativeLogTrimmed = 0;
volatile LONG g_windowDcReleaseCount = 0;

bool IsReadableAddress(const void* address, size_t bytes)
{
    MEMORY_BASIC_INFORMATION info{};
    if (!address || VirtualQuery(address, &info, sizeof(info)) != sizeof(info)) {
        return false;
    }
    if (info.State != MEM_COMMIT || (info.Protect & (PAGE_NOACCESS | PAGE_GUARD)) != 0) {
        return false;
    }
    const uintptr_t start = reinterpret_cast<uintptr_t>(address);
    const uintptr_t end = reinterpret_cast<uintptr_t>(info.BaseAddress) + info.RegionSize;
    return bytes <= end - start;
}

BOOL WINAPI DeleteDcCompatibilityHook(HDC hdc)
{
    HWND owner = hdc ? WindowFromDC(hdc) : nullptr;
    if (owner) {
        const int released = ReleaseDC(owner, hdc);
        if (released != 0) {
            InterlockedIncrement(&g_windowDcReleaseCount);
            return TRUE;
        }
        return FALSE;
    }

    DeleteDcFn original = g_originalDeleteDc;
    return original ? original(hdc) : FALSE;
}

bool InstallDeleteDcCompatibility(uintptr_t mainBase)
{
    if (InterlockedCompareExchange(&g_installed, 0, 0) != 0) {
        return true;
    }

    HMODULE gdi32 = GetModuleHandleW(L"gdi32.dll");
    if (!mainBase || !gdi32) {
        return false;
    }

    auto expected = reinterpret_cast<DeleteDcFn>(GetProcAddress(gdi32, "DeleteDC"));
    auto slot = reinterpret_cast<void**>(mainBase + kDeleteDcIatOffset);
    if (!expected || !IsReadableAddress(slot, sizeof(*slot)) || *slot != reinterpret_cast<void*>(expected)) {
        return false;
    }

    DWORD oldProtect = 0;
    if (!VirtualProtect(slot, sizeof(*slot), PAGE_READWRITE, &oldProtect)) {
        return false;
    }

    g_originalDeleteDc = expected;
    g_deleteDcSlot = slot;
    InterlockedExchangePointer(slot, reinterpret_cast<void*>(&DeleteDcCompatibilityHook));

    DWORD unusedProtect = 0;
    VirtualProtect(slot, sizeof(*slot), oldProtect, &unusedProtect);
    FlushInstructionCache(GetCurrentProcess(), slot, sizeof(*slot));
    InterlockedExchange(&g_installed, 1);
    return true;
}

void UpdateSnapshot(uintptr_t mainBase, DWORD now)
{
    PROCESS_MEMORY_COUNTERS_EX memory{};
    memory.cb = sizeof(memory);
    DWORD handleCount = 0;
    GetProcessHandleCount(GetCurrentProcess(), &handleCount);
    GetProcessMemoryInfo(
        GetCurrentProcess(),
        reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&memory),
        sizeof(memory));

    LONG syncRequestCount = -1;
    __try {
        syncRequestCount = *reinterpret_cast<volatile LONG*>(mainBase + 0x230C2C);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        syncRequestCount = -1;
    }

    NativeOptimizationSnapshot next{};
    next.structSize = sizeof(next);
    next.version = 1;
    next.privateBytes = static_cast<uint64_t>(memory.PrivateUsage);
    next.workingSetBytes = static_cast<uint64_t>(memory.WorkingSetSize);
    next.handleCount = handleCount;
    next.gdiObjects = GetGuiResources(GetCurrentProcess(), GR_GDIOBJECTS);
    next.userObjects = GetGuiResources(GetCurrentProcess(), GR_USEROBJECTS);
    next.syncRequestCount = syncRequestCount;
    next.nativeLogItems = InterlockedCompareExchange(&g_nativeLogItems, 0, 0);
    next.nativeLogTrimmed = static_cast<uint32_t>(
        InterlockedCompareExchange(&g_nativeLogTrimmed, 0, 0));
    next.windowDcReleaseCount = static_cast<uint32_t>(
        InterlockedCompareExchange(&g_windowDcReleaseCount, 0, 0));
    next.sampleTick = now;

    AcquireSRWLockExclusive(&g_snapshotLock);
    g_snapshot = next;
    ReleaseSRWLockExclusive(&g_snapshotLock);
}
}

namespace NativeOptimization
{
bool Install(uintptr_t mainBase)
{
    const bool deleteDcOk = InstallDeleteDcCompatibility(mainBase);
    Tick(mainBase);
    return deleteDcOk;
}

void Tick(uintptr_t mainBase)
{
    if (!mainBase) {
        return;
    }

    const DWORD now = GetTickCount();
    const DWORD last = static_cast<DWORD>(
        InterlockedCompareExchange(&g_lastSampleTick, 0, 0));
    if (last != 0 && now - last < kSampleIntervalMs) {
        return;
    }
    if (InterlockedCompareExchange(
            &g_lastSampleTick,
            static_cast<LONG>(now),
            static_cast<LONG>(last)) != static_cast<LONG>(last)) {
        return;
    }
    UpdateSnapshot(mainBase, now);
}

void __stdcall BeforeNativeLog(void* owner)
{
    HWND listBox = nullptr;
    __try {
        if (owner) {
            listBox = *(reinterpret_cast<HWND*>(owner) + 62);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        listBox = nullptr;
    }

    if (!listBox || !IsWindow(listBox)) {
        InterlockedExchange(&g_nativeLogItems, -1);
        return;
    }

    LRESULT count = SendMessageW(listBox, LB_GETCOUNT, 0, 0);
    if (count == LB_ERR) {
        InterlockedExchange(&g_nativeLogItems, -1);
        return;
    }

    if (count >= kNativeLogLimit) {
        int removeCount = static_cast<int>(count) - kNativeLogRetainAfterTrim;
        while (removeCount-- > 0) {
            if (SendMessageW(listBox, LB_DELETESTRING, 0, 0) == LB_ERR) {
                break;
            }
            InterlockedIncrement(&g_nativeLogTrimmed);
            --count;
        }
    }

    // The original function appends one item immediately after this hook.
    InterlockedExchange(&g_nativeLogItems, static_cast<LONG>(count + 1));
}

bool GetSnapshot(NativeOptimizationSnapshot& snapshot)
{
    AcquireSRWLockShared(&g_snapshotLock);
    snapshot = g_snapshot;
    ReleaseSRWLockShared(&g_snapshotLock);
    return snapshot.structSize == sizeof(snapshot) && snapshot.version == 1;
}
}

extern "C" __declspec(dllexport)
BOOL WINAPI MyPatchGetOptimizationSnapshot(
    NativeOptimizationSnapshot* snapshot,
    DWORD snapshotSize)
{
    if (!snapshot || snapshotSize < sizeof(*snapshot)) {
        return FALSE;
    }

    NativeOptimizationSnapshot current{};
    if (!NativeOptimization::GetSnapshot(current)) {
        return FALSE;
    }
    std::memcpy(snapshot, &current, sizeof(current));
    return TRUE;
}
