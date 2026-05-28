#include <windows.h>
#include <climits>
#include <cstdio>
#include <cstdint>
#include <cstring>

namespace
{
HHOOK g_msgBoxHook = nullptr;
constexpr DWORD kMessageBoxAutoCloseMs = 3000;

struct MemoryPatch
{
    const char* name;
    uintptr_t offset;
    const BYTE* bytes;
    size_t size;
};

struct PatchResult
{
    const MemoryPatch* patch;
    void* address;
    bool applied;
};

struct CodeBuffer
{
    BYTE* data;
    size_t capacity;
    size_t size;
    uintptr_t address;
};

using CodeBuilder = bool (*)(uintptr_t base, CodeBuffer& code);

struct JumpPatch
{
    const char* name;
    uintptr_t hookOffset;
    size_t overwriteSize;
    CodeBuilder buildCode;
};

struct JumpPatchResult
{
    const JumpPatch* patch;
    void* hookAddress;
    void* codeAddress;
    size_t codeSize;
    bool applied;
};

// Dragon vein fix
const BYTE kDragonVeinPatchBytes[] = {
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

// Break egg fix
const BYTE kBreakEggPatchBytes[] = {
    0x6A, 0x01, 0x8D, 0x04, 0x24, 0x6A, 0x01, 0x50,
    0x68, 0xE9, 0x25, 0x00, 0x00, 0xE8, 0xEE, 0x37,
    0x01, 0x00, 0x83, 0xC4, 0x04
};

const MemoryPatch kPatches[] = {
    { "Dragon vein fix", 0x4AA10, kDragonVeinPatchBytes, sizeof(kDragonVeinPatchBytes) },
    { "Break egg fix", 0x36B60, kBreakEggPatchBytes, sizeof(kBreakEggPatchBytes) },
};
constexpr size_t kPatchCount = sizeof(kPatches) / sizeof(kPatches[0]);

bool BuildSend37A4Code(uintptr_t base, CodeBuffer& code);

const JumpPatch kJumpPatches[] = {
    { "Fast Daily Battle", 0x4A785, 11, BuildSend37A4Code },
};
constexpr size_t kJumpPatchCount = sizeof(kJumpPatches) / sizeof(kJumpPatches[0]);

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

bool CanWrite(CodeBuffer& code, size_t bytes)
{
    return code.size <= code.capacity && bytes <= code.capacity - code.size;
}

bool AppendByte(CodeBuffer& code, BYTE value)
{
    if (!CanWrite(code, 1)) {
        return false;
    }

    code.data[code.size++] = value;
    return true;
}

bool AppendU32(CodeBuffer& code, uint32_t value)
{
    if (!CanWrite(code, sizeof(value))) {
        return false;
    }

    std::memcpy(code.data + code.size, &value, sizeof(value));
    code.size += sizeof(value);
    return true;
}

bool GetRel32(uintptr_t sourceNext, uintptr_t destination, int32_t& displacement)
{
    const long long diff = static_cast<long long>(destination) - static_cast<long long>(sourceNext);
    if (diff < INT_MIN || diff > INT_MAX) {
        return false;
    }

    displacement = static_cast<int32_t>(diff);
    return true;
}

bool AppendPushImm32(CodeBuffer& code, uint32_t value)
{
    return AppendByte(code, 0x68) && AppendU32(code, value);
}

bool AppendCallPtr(CodeBuffer& code, uint32_t pointerAddress)
{
    return AppendByte(code, 0xFF) && AppendByte(code, 0x15) && AppendU32(code, pointerAddress);
}

bool AppendRel32Instruction(CodeBuffer& code, BYTE opcode, uintptr_t destination)
{
    if (!CanWrite(code, 5)) {
        return false;
    }

    const uintptr_t sourceNext = code.address + code.size + 5;
    int32_t displacement = 0;
    if (!GetRel32(sourceNext, destination, displacement)) {
        return false;
    }

    return AppendByte(code, opcode) && AppendU32(code, static_cast<uint32_t>(displacement));
}

bool WriteRel32Jump(void* source, void* destination, size_t overwriteSize)
{
    if (overwriteSize < 5) {
        return false;
    }

    int32_t displacement = 0;
    const uintptr_t sourceNext = reinterpret_cast<uintptr_t>(source) + 5;
    if (!GetRel32(sourceNext, reinterpret_cast<uintptr_t>(destination), displacement)) {
        return false;
    }

    BYTE jumpBytes[32]{};
    if (overwriteSize > sizeof(jumpBytes)) {
        return false;
    }

    jumpBytes[0] = 0xE9;
    std::memcpy(jumpBytes + 1, &displacement, sizeof(displacement));
    std::memset(jumpBytes + 5, 0x90, overwriteSize - 5);
    return PatchBytes(source, jumpBytes, overwriteSize);
}

PatchResult ApplyPatch(uintptr_t base, const MemoryPatch& patch)
{
    void* address = reinterpret_cast<void*>(base + patch.offset);
    return { &patch, address, PatchBytes(address, patch.bytes, patch.size) };
}

JumpPatchResult ApplyJumpPatch(uintptr_t base, const JumpPatch& patch)
{
    constexpr size_t kCodeCapacity = 128;
    void* codeMemory = VirtualAlloc(nullptr, kCodeCapacity, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    void* hookAddress = reinterpret_cast<void*>(base + patch.hookOffset);
    if (!codeMemory) {
        return { &patch, hookAddress, nullptr, 0, false };
    }

    CodeBuffer code{
        static_cast<BYTE*>(codeMemory),
        kCodeCapacity,
        0,
        reinterpret_cast<uintptr_t>(codeMemory),
    };

    if (!patch.buildCode(base, code)) {
        VirtualFree(codeMemory, 0, MEM_RELEASE);
        return { &patch, hookAddress, nullptr, 0, false };
    }

    FlushInstructionCache(GetCurrentProcess(), codeMemory, code.size);
    const bool patched = WriteRel32Jump(hookAddress, codeMemory, patch.overwriteSize);
    if (!patched) {
        VirtualFree(codeMemory, 0, MEM_RELEASE);
        return { &patch, hookAddress, nullptr, code.size, false };
    }

    return { &patch, hookAddress, codeMemory, code.size, true };
}

bool BuildSend37A4Code(uintptr_t base, CodeBuffer& code)
{
    return AppendPushImm32(code, static_cast<uint32_t>(base + 0x2304BC)) &&
        AppendCallPtr(code, static_cast<uint32_t>(base + 0x1C4418)) &&
        AppendByte(code, 0x6A) && AppendByte(code, 0x00) &&
        AppendByte(code, 0x6A) && AppendByte(code, 0x00) &&
        AppendPushImm32(code, 0x37A4) &&
        AppendRel32Instruction(code, 0xE8, base + 0x4A360) &&
        AppendRel32Instruction(code, 0xE9, base + 0x4A790);
}

size_t AppendMessage(char* buffer, size_t capacity, size_t used, const char* text)
{
    if (used >= capacity) {
        return used;
    }

    const int written = std::snprintf(buffer + used, capacity - used, "%s", text);
    if (written <= 0) {
        return used;
    }

    const size_t added = static_cast<size_t>(written);
    return used + (added < capacity - used ? added : capacity - used - 1);
}

DWORD WINAPI CloseMessageBoxThread(LPVOID hwndParam)
{
    Sleep(kMessageBoxAutoCloseMs);

    HWND hwnd = reinterpret_cast<HWND>(hwndParam);
    if (IsWindow(hwnd)) {
        PostMessageA(hwnd, WM_CLOSE, 0, 0);
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
    PatchResult results[kPatchCount]{};
    JumpPatchResult jumpResults[kJumpPatchCount]{};

    size_t appliedCount = 0;
    for (size_t i = 0; i < kPatchCount; ++i) {
        results[i] = ApplyPatch(base, kPatches[i]);
        if (results[i].applied) {
            ++appliedCount;
        }
    }

    size_t appliedJumpCount = 0;
    for (size_t i = 0; i < kJumpPatchCount; ++i) {
        jumpResults[i] = ApplyJumpPatch(base, kJumpPatches[i]);
        if (jumpResults[i].applied) {
            ++appliedJumpCount;
        }
    }

    const DWORD pid = GetCurrentProcessId();
    char message[1024]{};
    const int headerLength = std::snprintf(
        message,
        sizeof(message),
        "PID: %lu\nPID hex: 0x%lX\nBase: %p\nByte patches: %zu/%zu applied\nJump patches: %zu/%zu applied\n",
        pid,
        pid,
        reinterpret_cast<void*>(base),
        appliedCount,
        kPatchCount,
        appliedJumpCount,
        kJumpPatchCount);
    size_t used = headerLength > 0 ? static_cast<size_t>(headerLength) : 0;

    for (const PatchResult& result : results) {
        char line[192]{};
        std::snprintf(
            line,
            sizeof(line),
            "%s @ +0x%lX -> %p (%zu bytes): %s\n",
            result.patch->name,
            static_cast<unsigned long>(result.patch->offset),
            result.address,
            result.patch->size,
            result.applied ? "OK" : "FAILED");
        used = AppendMessage(message, sizeof(message), used, line);
    }

    for (const JumpPatchResult& result : jumpResults) {
        char line[224]{};
        std::snprintf(
            line,
            sizeof(line),
            "%s @ +0x%lX -> %p (%zu bytes): %s\n",
            result.patch->name,
            static_cast<unsigned long>(result.patch->hookOffset),
            result.codeAddress,
            result.codeSize,
            result.applied ? "OK" : "FAILED");
        used = AppendMessage(message, sizeof(message), used, line);
    }

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
