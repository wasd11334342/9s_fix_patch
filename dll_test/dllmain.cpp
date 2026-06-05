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
    size_t codeCapacity;
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

uintptr_t g_mainBase = 0;

namespace DailySign
{
volatile LONG g_dailySignNeedSign = 0;
volatile LONG g_dailySignBonusBits = 0;
volatile LONG g_dailySignLastQuery = 0;
uint32_t g_dailySignBonusPayload = 0;

const wchar_t kDailySignLogFormat[] = L"%s";
const wchar_t kDailySignLogDaily[] = L"\x6BCF\x65E5\x7C3D\x5230";
const wchar_t kDailySignLogBonus[] = L"\x7D2F\x7A4D\x7C3D\x5230";
}

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

namespace LgfGuard
{
volatile LONG g_enabled = 1;
volatile LONG g_level = 0;
volatile LONG g_allowedRoom = 0;
volatile LONG g_maxRoom = 0;
volatile LONG g_blockRoom = 0;
volatile LONG g_blockSlot = 0;
volatile LONG g_targetRoom = 0;
volatile LONG g_lastCurrent = -1;
volatile LONG g_lastMax = -1;
volatile LONG g_lastAllowed = -1;
volatile LONG g_shouldBlock = 0;
volatile LONG g_openState = 0;
volatile LONG g_lastOpenState = -1;

const wchar_t kLogFormat[] = {
    0x7DF4, 0x529F, 0x623F, 0x0020, 0x7B49, 0x7D1A, 0x0025, 0x0069,
    0x0020, 0x76EE, 0x524D, 0x0025, 0x0069, 0x0020, 0x6700, 0x9AD8,
    0x0025, 0x0069, 0x0020, 0x76EE, 0x6A19, 0x0025, 0x0069, 0x0020,
    0x0025, 0x0073, 0x0000
};
const wchar_t kLogFullFormat[] = {
    0x7DF4, 0x529F, 0x623F, 0x0020, 0x7B49, 0x7D1A, 0x0025, 0x0069,
    0x0020, 0x76EE, 0x524D, 0x0025, 0x0069, 0x0020, 0x6700, 0x9AD8,
    0x0025, 0x0069, 0x0020, 0x76EE, 0x6A19, 0x0025, 0x0069, 0x0020,
    0x623F, 0x9593, 0x0025, 0x0069, 0x5230, 0x0025, 0x0069, 0x5DF2,
    0x6EFF, 0x0020, 0x0025, 0x0073, 0x0000
};
const wchar_t kLogAtMax[] = { 0x5DF2, 0x5728, 0x76EE, 0x6A19, 0x623F, 0x9593, 0x0000 };
const wchar_t kLogAtBest[] = { 0x5DF2, 0x5728, 0x6700, 0x9AD8, 0x623F, 0x0000 };
const wchar_t kLogGoMax[] = { 0x524D, 0x5F80, 0x76EE, 0x6A19, 0x623F, 0x9593, 0x0000 };
const wchar_t kLogFullGo[] = {
    0x6700, 0x9AD8, 0x623F, 0x5DF2, 0x6EFF, 0x0020, 0x524D, 0x5F80,
    0x76EE, 0x6A19, 0x623F, 0x9593, 0x0000
};
const wchar_t kLogActionFormat[] = {
    0x7DF4, 0x529F, 0x623F, 0x0020, 0x0025, 0x0069, 0x0020, 0x0025,
    0x0069, 0x0000
};
const wchar_t kLogClosed[] = { 0x7DF4, 0x529F, 0x623F, 0x0020, 0x672A, 0x958B, 0x653E, 0x0000 };
}

const BYTE kLgfRefreshIntervalBytes[] = { 0x00, 0x4C, 0x1D, 0x00 };
const BYTE kLgfSuppressActionLogBytes[] = {
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90
};

const MemoryPatch kPatches[] = {
    { "Dragon vein fix", 0x4AA10, kDragonVeinPatchBytes, sizeof(kDragonVeinPatchBytes) },
    { "Break egg fix", 0x36B60, kBreakEggPatchBytes, sizeof(kBreakEggPatchBytes) },
    { "LGF refresh interval", 0x3719C, kLgfRefreshIntervalBytes, sizeof(kLgfRefreshIntervalBytes) },
    { "LGF suppress action log", 0x37385, kLgfSuppressActionLogBytes, sizeof(kLgfSuppressActionLogBytes) },
};
constexpr size_t kPatchCount = sizeof(kPatches) / sizeof(kPatches[0]);

namespace FastDailyBattle
{
bool BuildSend37A4Code(uintptr_t base, CodeBuffer& code);
}

namespace DailySign
{
bool BuildSendCode(uintptr_t base, CodeBuffer& code);
bool BuildDispatchCode(uintptr_t base, CodeBuffer& code);
}

namespace LgfGuard
{
bool BuildMainCode(uintptr_t base, CodeBuffer& code);
bool Build396DCode(uintptr_t base, CodeBuffer& code);
bool Build3970Code(uintptr_t base, CodeBuffer& code);
}

const JumpPatch kJumpPatches[] = {
    { "Fast Daily Battle", 0x4A785, 11, 128, FastDailyBattle::BuildSend37A4Code },
    { "Daily Sign send tick", 0x38F90, 5, 128, DailySign::BuildSendCode },
    { "Daily Sign recv dispatch", 0x42AD0, 5, 128, DailySign::BuildDispatchCode },
    { "LGF status log", 0x37150, 7, 128, LgfGuard::BuildMainCode },
    { "LGF 396D guard", 0x4AC30, 6, 128, LgfGuard::Build396DCode },
    { "LGF 3970 guard", 0x4AC90, 6, 128, LgfGuard::Build3970Code },
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

bool AppendPushEdx(CodeBuffer& code)
{
    return AppendByte(code, 0x52);
}

bool AppendPushEax(CodeBuffer& code)
{
    return AppendByte(code, 0x50);
}

bool AppendPushDwordPtrEspOffset(CodeBuffer& code, BYTE offset)
{
    return AppendByte(code, 0xFF) &&
        AppendByte(code, 0x74) &&
        AppendByte(code, 0x24) &&
        AppendByte(code, offset);
}

bool AppendPushad(CodeBuffer& code)
{
    return AppendByte(code, 0x60);
}

bool AppendPopad(CodeBuffer& code)
{
    return AppendByte(code, 0x61);
}

bool AppendMovzxEaxCx(CodeBuffer& code)
{
    return AppendByte(code, 0x0F) && AppendByte(code, 0xB7) && AppendByte(code, 0xC1);
}

bool AppendMovEaxDwordPtrAbs(CodeBuffer& code, uint32_t address)
{
    return AppendByte(code, 0xA1) && AppendU32(code, address);
}

bool AppendMovDwordPtrEspOffsetEax(CodeBuffer& code, BYTE offset)
{
    return AppendByte(code, 0x89) &&
        AppendByte(code, 0x44) &&
        AppendByte(code, 0x24) &&
        AppendByte(code, offset);
}

bool AppendOriginalFunctionPrologue(CodeBuffer& code)
{
    return AppendByte(code, 0x55) &&
        AppendByte(code, 0x8B) && AppendByte(code, 0xEC) &&
        AppendByte(code, 0x6A) && AppendByte(code, 0xFF);
}

bool AppendFunctionPrologueWithStack(CodeBuffer& code, BYTE stackSize)
{
    return AppendByte(code, 0x55) &&
        AppendByte(code, 0x8B) && AppendByte(code, 0xEC) &&
        AppendByte(code, 0x83) && AppendByte(code, 0xEC) && AppendByte(code, stackSize);
}

bool AppendCmpDwordAbsImm8(CodeBuffer& code, uint32_t address, BYTE value)
{
    return AppendByte(code, 0x83) &&
        AppendByte(code, 0x3D) &&
        AppendU32(code, address) &&
        AppendByte(code, value);
}

bool AppendJneShort(CodeBuffer& code, BYTE displacement)
{
    return AppendByte(code, 0x75) && AppendByte(code, displacement);
}

bool AppendRetImm16(CodeBuffer& code, uint16_t bytes)
{
    return AppendByte(code, 0xC2) &&
        AppendByte(code, static_cast<BYTE>(bytes & 0xFF)) &&
        AppendByte(code, static_cast<BYTE>((bytes >> 8) & 0xFF));
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
    void* hookAddress = reinterpret_cast<void*>(base + patch.hookOffset);
    void* codeMemory = VirtualAlloc(nullptr, patch.codeCapacity, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!codeMemory) {
        return { &patch, hookAddress, nullptr, 0, false };
    }

    CodeBuffer code{
        static_cast<BYTE*>(codeMemory),
        patch.codeCapacity,
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

uint32_t ReadU32Unaligned(const BYTE* address)
{
    uint32_t value = 0;
    std::memcpy(&value, address, sizeof(value));
    return value;
}

uint32_t ReadGameU32(uintptr_t address)
{
    return *reinterpret_cast<volatile uint32_t*>(address);
}

DWORD GetGameTick()
{
    using GetTickFn = DWORD(__stdcall*)();
    GetTickFn tick = *reinterpret_cast<GetTickFn*>(g_mainBase + 0x1C43DC);
    return tick ? tick() : 0;
}

namespace LgfGuard
{

uintptr_t FindRoomPtr(uint32_t room)
{
    uintptr_t list = ReadGameU32(g_mainBase + 0x23097C);
    int32_t count = static_cast<int32_t>(ReadGameU32(g_mainBase + 0x230980));
    if (list == 0 || count <= 0) {
        return 0;
    }

    for (int32_t i = 0; i < count; ++i) {
        uintptr_t entry = ReadGameU32(list + static_cast<uintptr_t>(i) * sizeof(uint32_t));
        if (entry != 0 && ReadGameU32(entry + 0x04) == room) {
            return entry;
        }
    }

    return 0;
}

void CalcAvailableRoom()
{
    LONG room = g_allowedRoom;
    g_maxRoom = room;
    if (room <= 0) {
        return;
    }

    while (room > 0) {
        uintptr_t roomPtr = FindRoomPtr(static_cast<uint32_t>(room));
        if (roomPtr != 0) {
            const uint32_t capacity = ReadGameU32(roomPtr + 0x0C);
            if (capacity == 0 || ReadGameU32(roomPtr + 0x08) < capacity) {
                g_maxRoom = room;
                return;
            }
        }
        --room;
    }

    g_maxRoom = 0;
}

void CalcLevelMax()
{
    g_level = 0;
    g_allowedRoom = 0;
    g_maxRoom = 0;

    uintptr_t list = ReadGameU32(g_mainBase + 0x230520);
    int32_t count = static_cast<int32_t>(ReadGameU32(g_mainBase + 0x230524));
    if (list != 0 && count > 0) {
        for (int32_t i = 0; i < count; ++i) {
            uintptr_t prop = ReadGameU32(list + static_cast<uintptr_t>(i) * sizeof(uint32_t));
            if (prop != 0 && ReadGameU32(prop) == 0x194) {
                g_level = static_cast<LONG>(ReadGameU32(prop + 0x04));
                break;
            }
        }
    }

    const LONG level = g_level;
    if (level >= 160) {
        g_allowedRoom = 6;
    } else if (level >= 150) {
        g_allowedRoom = 5;
    } else if (level >= 140) {
        g_allowedRoom = 4;
    } else if (level >= 130) {
        g_allowedRoom = 3;
    } else if (level >= 110) {
        g_allowedRoom = 2;
    } else if (level >= 90) {
        g_allowedRoom = 1;
    }

    CalcAvailableRoom();
}

void RefreshLog()
{
    using RefreshLogFn = void(__stdcall*)(uint32_t, uint32_t, uint32_t, uint32_t);
    RefreshLogFn refreshLog = *reinterpret_cast<RefreshLogFn*>(g_mainBase + 0x1C46B0);
    if (refreshLog) {
        refreshLog(ReadGameU32(g_mainBase + 0x2300A4), ReadGameU32(g_mainBase + 0x2304D8), 0, 0);
    }
}

void WriteStatusLog()
{
    using PrintLogFn = void(__cdecl*)(uintptr_t, const wchar_t*, ...);
    PrintLogFn printLog = reinterpret_cast<PrintLogFn>(g_mainBase + 0x2EF0);

    const LONG current = static_cast<LONG>(ReadGameU32(g_mainBase + 0x230970));
    const LONG allowed = g_allowedRoom;
    const LONG maxRoom = g_maxRoom;
    if (allowed != maxRoom) {
        const LONG nextRoom = maxRoom + 1;
        const wchar_t* message = kLogFullGo;
        if (current >= maxRoom) {
            message = kLogAtBest;
        }
        printLog(g_mainBase + 0x230504, kLogFullFormat, g_level, current, allowed, maxRoom, nextRoom, allowed, message);
    } else {
        const wchar_t* message = current < maxRoom ? kLogGoMax : kLogAtMax;
        printLog(g_mainBase + 0x230504, kLogFormat, g_level, current, allowed, maxRoom, message);
    }

    RefreshLog();
}

void WriteActionLog()
{
    using PrintLogFn = void(__cdecl*)(uintptr_t, const wchar_t*, ...);
    PrintLogFn printLog = reinterpret_cast<PrintLogFn>(g_mainBase + 0x2EF0);
    printLog(g_mainBase + 0x230504, kLogActionFormat, g_blockRoom, g_blockSlot);
    RefreshLog();
}

void UpdateOpenState()
{
    SYSTEMTIME time{};
    GetLocalTime(&time);
    g_openState = time.wHour >= 10 ? 1 : 0;
}

void WriteClosedLog()
{
    using PrintLogFn = void(__cdecl*)(uintptr_t, const wchar_t*, ...);
    PrintLogFn printLog = reinterpret_cast<PrintLogFn>(g_mainBase + 0x2EF0);
    printLog(g_mainBase + 0x230504, kLogClosed);
    RefreshLog();
}

__declspec(noinline) void __stdcall MainHook()
{
    if (g_enabled == 0 || ReadGameU32(g_mainBase + 0x23033C) == 0) {
        return;
    }

    UpdateOpenState();
    if (g_openState == 0) {
        if (g_lastOpenState == 0) {
            return;
        }

        g_lastOpenState = 0;
        WriteClosedLog();
        return;
    }

    if (g_lastOpenState != 1) {
        g_lastOpenState = 1;
        g_lastCurrent = -1;
    }

    CalcLevelMax();
    const LONG current = static_cast<LONG>(ReadGameU32(g_mainBase + 0x230970));
    const LONG maxRoom = g_maxRoom;
    const LONG allowed = g_allowedRoom;
    if (current == g_lastCurrent && maxRoom == g_lastMax && allowed == g_lastAllowed) {
        return;
    }

    g_lastCurrent = current;
    g_lastMax = maxRoom;
    g_lastAllowed = allowed;
    WriteStatusLog();
}

__declspec(noinline) void __stdcall Guard396DHook(uint32_t room)
{
    g_blockRoom = static_cast<LONG>(room);
    g_targetRoom = static_cast<LONG>(room);
    g_shouldBlock = 0;
    if (g_enabled == 0) {
        return;
    }

    UpdateOpenState();
    if (g_openState == 0) {
        g_shouldBlock = 1;
        return;
    }

    CalcLevelMax();
    if (g_maxRoom <= 0) {
        g_shouldBlock = 1;
        return;
    }

    g_targetRoom = g_maxRoom;
    g_blockRoom = g_targetRoom;
}

__declspec(noinline) void __stdcall Guard3970Hook(uint32_t room, uint32_t slot)
{
    g_blockRoom = static_cast<LONG>(room);
    g_blockSlot = static_cast<LONG>(slot);
    g_targetRoom = static_cast<LONG>(room);
    g_shouldBlock = 0;
    if (g_enabled == 0) {
        return;
    }

    UpdateOpenState();
    if (g_openState == 0) {
        g_shouldBlock = 1;
        return;
    }

    CalcLevelMax();
    if (g_maxRoom <= 0) {
        g_shouldBlock = 1;
        return;
    }

    g_targetRoom = g_maxRoom;
    g_blockRoom = g_targetRoom;
    WriteActionLog();
}

bool BuildMainCode(uintptr_t base, CodeBuffer& code)
{
    return AppendPushad(code) &&
        AppendRel32Instruction(code, 0xE8, reinterpret_cast<uintptr_t>(&MainHook)) &&
        AppendPopad(code) &&
        AppendCmpDwordAbsImm8(code, static_cast<uint32_t>(base + 0x23033C), 0) &&
        AppendRel32Instruction(code, 0xE9, base + 0x37157);
}

bool Build396DCode(uintptr_t base, CodeBuffer& code)
{
    return AppendPushad(code) &&
        AppendPushDwordPtrEspOffset(code, 0x24) &&
        AppendRel32Instruction(code, 0xE8, reinterpret_cast<uintptr_t>(&Guard396DHook)) &&
        AppendPopad(code) &&
        AppendCmpDwordAbsImm8(code, static_cast<uint32_t>(reinterpret_cast<uintptr_t>(&g_shouldBlock)), 0) &&
        AppendJneShort(code, 0x14) &&
        AppendMovEaxDwordPtrAbs(code, static_cast<uint32_t>(reinterpret_cast<uintptr_t>(&g_targetRoom))) &&
        AppendMovDwordPtrEspOffsetEax(code, 0x04) &&
        AppendFunctionPrologueWithStack(code, 0x0C) &&
        AppendRel32Instruction(code, 0xE9, base + 0x4AC36) &&
        AppendRetImm16(code, 0x08);
}

bool Build3970Code(uintptr_t base, CodeBuffer& code)
{
    return AppendPushad(code) &&
        AppendPushDwordPtrEspOffset(code, 0x28) &&
        AppendPushDwordPtrEspOffset(code, 0x28) &&
        AppendRel32Instruction(code, 0xE8, reinterpret_cast<uintptr_t>(&Guard3970Hook)) &&
        AppendPopad(code) &&
        AppendCmpDwordAbsImm8(code, static_cast<uint32_t>(reinterpret_cast<uintptr_t>(&g_shouldBlock)), 0) &&
        AppendJneShort(code, 0x14) &&
        AppendMovEaxDwordPtrAbs(code, static_cast<uint32_t>(reinterpret_cast<uintptr_t>(&g_targetRoom))) &&
        AppendMovDwordPtrEspOffsetEax(code, 0x04) &&
        AppendFunctionPrologueWithStack(code, 0x10) &&
        AppendRel32Instruction(code, 0xE9, base + 0x4AC96) &&
        AppendRetImm16(code, 0x08);
}

}

namespace DailySign
{

void SendDailySignPacket(uint32_t opcode, const void* payload, uint32_t payloadLength)
{
    using SendPacketFn = void(__stdcall*)(uint32_t, const void*, uint32_t);
    SendPacketFn sendPacket = reinterpret_cast<SendPacketFn>(g_mainBase + 0x4A360);
    sendPacket(opcode, payload, payloadLength);
}

void WriteDailySignLog(const wchar_t* text)
{
    using PrintLogFn = void(__cdecl*)(uintptr_t, const wchar_t*, const wchar_t*);
    using RefreshLogFn = void(__stdcall*)(uint32_t, uint32_t, uint32_t, uint32_t);

    PrintLogFn printLog = reinterpret_cast<PrintLogFn>(g_mainBase + 0x2EF0);
    RefreshLogFn refreshLog = *reinterpret_cast<RefreshLogFn*>(g_mainBase + 0x1C46B0);

    printLog(g_mainBase + 0x230504, kDailySignLogFormat, text);
    if (refreshLog) {
        refreshLog(ReadGameU32(g_mainBase + 0x2300A4), ReadGameU32(g_mainBase + 0x2304D8), 0, 0);
    }
}

uint32_t BuildDailySignBonusPayload(uint32_t index)
{
    using BonusPayloadFn = uint32_t(__stdcall*)(uint32_t);
    BonusPayloadFn buildPayload = *reinterpret_cast<BonusPayloadFn*>(g_mainBase + 0x1C4930);
    return buildPayload ? buildPayload(index) : 0;
}

void SendDailySignQuery(bool updateTick)
{
    if (updateTick) {
        InterlockedExchange(&g_dailySignLastQuery, static_cast<LONG>(GetGameTick()));
    }
    SendDailySignPacket(0x4EFF, nullptr, 0);
}

void SendDailySignNow()
{
    SendDailySignPacket(0x4F03, nullptr, 0);
    WriteDailySignLog(kDailySignLogDaily);
}

void SendDailySignBonus(uint32_t index)
{
    g_dailySignBonusPayload = BuildDailySignBonusPayload(index);
    SendDailySignPacket(0x4F02, &g_dailySignBonusPayload, sizeof(g_dailySignBonusPayload));
    WriteDailySignLog(kDailySignLogBonus);
}

void ParseDailySignPayload(const BYTE* payload)
{
    if (!payload) {
        return;
    }

    if (payload[0x12] == 1) {
        InterlockedExchange(&g_dailySignNeedSign, 1);
    }

    LONG bonusBits = 0;
    const uint32_t thresholds[] = {
        0x02000000,
        0x05000000,
        0x08000000,
        0x0C000000,
        0x10000000,
        0x14000000,
        0x1A000000,
    };

    for (uint32_t day = 1; day <= 7; ++day) {
        const uint32_t dayValue = day << 24;
        for (size_t offset = 0; offset < 0x900; ++offset) {
            const BYTE* cursor = payload + offset;
            if (ReadU32Unaligned(cursor) == dayValue &&
                ReadU32Unaligned(cursor + 4) == thresholds[day - 1] &&
                ReadU32Unaligned(cursor + 8) == 0x02000000) {
                bonusBits |= 1 << (day - 1);
                break;
            }
        }
    }

    InterlockedExchange(&g_dailySignBonusBits, bonusBits);
}

__declspec(noinline) void __stdcall DailySignDispatchHook(uint32_t opcode, const BYTE* payload)
{
    if ((opcode & 0xFFFF) != 0x4F05) {
        return;
    }

    ParseDailySignPayload(payload);
    InterlockedExchange(&g_dailySignLastQuery, static_cast<LONG>(GetGameTick()));
}

__declspec(noinline) void __stdcall DailySignSendHook()
{
    if (ReadGameU32(g_mainBase + 0x230314) == 0) {
        return;
    }

    const DWORD now = GetGameTick();
    const DWORD lastQuery = static_cast<DWORD>(g_dailySignLastQuery);
    if (lastQuery == 0 || now - lastQuery > 0x00200B20) {
        InterlockedExchange(&g_dailySignLastQuery, static_cast<LONG>(now));
        SendDailySignQuery(false);
    }

    if (g_dailySignNeedSign == 1) {
        SendDailySignNow();
        InterlockedExchange(&g_dailySignNeedSign, 0);
    }

    LONG bits = g_dailySignBonusBits;
    for (uint32_t day = 1; day <= 7; ++day) {
        const LONG mask = 1 << (day - 1);
        if ((bits & mask) == 0) {
            continue;
        }

        SendDailySignBonus(day);
        LONG current = 0;
        do {
            current = g_dailySignBonusBits;
        } while (InterlockedCompareExchange(&g_dailySignBonusBits, current & ~mask, current) != current);
        bits &= ~mask;
    }
}

}

namespace FastDailyBattle
{

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

}

namespace DailySign
{

bool BuildSendCode(uintptr_t, CodeBuffer& code)
{
    return AppendPushad(code) &&
        AppendRel32Instruction(code, 0xE8, reinterpret_cast<uintptr_t>(&DailySignSendHook)) &&
        AppendPopad(code) &&
        AppendByte(code, 0xC3);
}

bool BuildDispatchCode(uintptr_t base, CodeBuffer& code)
{
    return AppendPushad(code) &&
        AppendPushEdx(code) &&
        AppendMovzxEaxCx(code) &&
        AppendPushEax(code) &&
        AppendRel32Instruction(code, 0xE8, reinterpret_cast<uintptr_t>(&DailySignDispatchHook)) &&
        AppendPopad(code) &&
        AppendOriginalFunctionPrologue(code) &&
        AppendRel32Instruction(code, 0xE9, base + 0x42AD5);
}

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
    g_mainBase = base;
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
    char message[2048]{};
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
