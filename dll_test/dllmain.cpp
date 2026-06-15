#include <windows.h>
#include <climits>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cwchar>

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

namespace PrizePool
{
volatile LONG g_id = 0;
volatile LONG g_count = 0;
volatile LONG g_state = 0;
volatile LONG g_lastQuery = 0;
uint32_t g_now = 0;
uint32_t g_payload[2]{};

const BYTE kQueryPayload[] = { 0x00, 0x00, 0x4E, 0x49, 0x14, 0x1B, 0x9E, 0x38 };
const wchar_t kLogFormat[] = L"%s";
const wchar_t kLogCase[] = { 0x734E, 0x6C60, 0x653E, 0x9001, 0x0000 };
}

namespace WeeklyReward
{
constexpr DWORD kQueryInterval = 0x00133AE0;
volatile LONG g_activity = 0;
volatile LONG g_nextData = -1;
volatile LONG g_pendingNext = 0;
volatile LONG g_cmdSendNext = 0;
volatile LONG g_lastSentData = -1;
volatile LONG g_recvLen = 0;
volatile LONG g_lastQueryTick = 0;
volatile LONG g_rewardCmdSend = 0;
volatile LONG g_rewardNextId = 0;
volatile LONG g_rewardNextIndex = 0;
volatile LONG g_rewardLastSentId = -1;
volatile LONG g_rewardCount = 0;
volatile LONG g_rewardCandidateCount = 0;
volatile LONG g_rewardStates[7]{};
BYTE g_packetDump[2048]{};
uint32_t g_nextPayload = 0;
uint32_t g_rewardPayload = 0;

const wchar_t kLogFormat[] = L"%s";
const wchar_t kRecvLogFormat[] = {
    0x5468, 0x5E38, 0x4EFB, 0x52D9, 0x0020, 0x7A4D, 0x5206, 0x0020,
    0x0025, 0x0069, 0x0000
};
const wchar_t kRewardLogFormat[] = {
    0x5468, 0x5E38, 0x734E, 0x52F5, 0x0020, 0x7B2C, 0x0025, 0x0069,
    0x500B, 0x7D2F, 0x7A4D, 0x734E, 0x52F5, 0x0000
};
}

namespace AutoLureDash
{
constexpr DWORD kPhaseGapMs = 100;
constexpr size_t kMaxGroups = 8;
constexpr size_t kMaxPayloadsPerGroup = 8;
constexpr size_t kGroupStride = 0x40;

volatile LONG g_phase = 0;
volatile LONG g_nextTick = 0;
volatile LONG g_groupCount = 0;
volatile LONG g_groupIndex = 0;
volatile LONG g_action = 1;
uint32_t g_targetTmp = 0;
BYTE g_groups[512]{};
BYTE g_dashBuffer[256]{};

bool BuildMainCode(uintptr_t base, CodeBuffer& code);
bool BuildGuardCode(uintptr_t base, CodeBuffer& code);
bool BuildTimerCode(uintptr_t base, CodeBuffer& code);
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
void HandleRecvPacket(uint32_t opcode, const BYTE* payload);
}

namespace PrizePool
{
bool BuildSendCode(uintptr_t base, CodeBuffer& code);
void HandleRecvPacket(uint32_t opcode, const BYTE* payload);
}

namespace WeeklyReward
{
bool BuildSendCode(uintptr_t base, CodeBuffer& code);
void HandleRecvPacket(uint32_t opcode, const BYTE* payload, uint32_t payloadLength);
}

namespace SharedRecvRouter
{
volatile LONG g_clearStackArg = 0;
bool BuildCode(uintptr_t base, CodeBuffer& code);
}

namespace LgfGuard
{
bool BuildMainCode(uintptr_t base, CodeBuffer& code);
bool Build396DCode(uintptr_t base, CodeBuffer& code);
bool Build3970Code(uintptr_t base, CodeBuffer& code);
}

const JumpPatch kJumpPatches[] = {
    { "Fast Daily Battle", 0x4A785, 11, 128, FastDailyBattle::BuildSend37A4Code },
    { "Shared recv router", 0x42AD0, 5, 128, SharedRecvRouter::BuildCode },
    { "Daily Sign send tick", 0x38F90, 5, 128, DailySign::BuildSendCode },
    { "Prize Pool sender", 0x364C0, 5, 128, PrizePool::BuildSendCode },
    { "Weekly Reward sender", 0x35CE0, 5, 128, WeeklyReward::BuildSendCode },
    { "LGF status log", 0x37150, 7, 128, LgfGuard::BuildMainCode },
    { "LGF 396D guard", 0x4AC30, 6, 128, LgfGuard::Build396DCode },
    { "LGF 3970 guard", 0x4AC90, 6, 128, LgfGuard::Build3970Code },
    { "AutoLure dash main", 0x351F0, 6, 128, AutoLureDash::BuildMainCode },
    { "AutoLure dash guard", 0x3B7A0, 6, 128, AutoLureDash::BuildGuardCode },
    { "AutoLure dash timer", 0x403A3, 12, 128, AutoLureDash::BuildTimerCode },
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

bool AppendMovDwordAbsImm32(CodeBuffer& code, uint32_t address, uint32_t value)
{
    return AppendByte(code, 0xC7) &&
        AppendByte(code, 0x05) &&
        AppendU32(code, address) &&
        AppendU32(code, value);
}

bool AppendMovDwordPtrEspOffsetImm32(CodeBuffer& code, BYTE offset, uint32_t value)
{
    return AppendByte(code, 0xC7) &&
        AppendByte(code, 0x44) &&
        AppendByte(code, 0x24) &&
        AppendByte(code, offset) &&
        AppendU32(code, value);
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

bool AppendJeShort(CodeBuffer& code, BYTE displacement)
{
    return AppendByte(code, 0x74) && AppendByte(code, displacement);
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

uint16_t ReadGameU16(uintptr_t address)
{
    return *reinterpret_cast<volatile uint16_t*>(address);
}

DWORD GetGameTick()
{
    using GetTickFn = DWORD(__stdcall*)();
    GetTickFn tick = *reinterpret_cast<GetTickFn*>(g_mainBase + 0x1C43DC);
    return tick ? tick() : 0;
}

namespace AutoLureDash
{

BYTE* GroupPtr(size_t index)
{
    return g_groups + index * kGroupStride;
}

uint32_t ReadGroupU32(BYTE* group, size_t offset)
{
    return ReadU32Unaligned(group + offset);
}

void WriteGroupU32(BYTE* group, size_t offset, uint32_t value)
{
    std::memcpy(group + offset, &value, sizeof(value));
}

void SendPacketWithEcx(uint32_t ecxValue, uint32_t opcode, const void* payload, uint32_t payloadLength)
{
    const uintptr_t sendAddress = g_mainBase + 0x4A360;
    __asm {
        mov ecx, ecxValue
        push payloadLength
        push payload
        push opcode
        call sendAddress
    }
}

bool GetTarget(uintptr_t entry, uint32_t& current, uint32_t& target)
{
    current = ReadGameU16(entry + 0x30);

    const uint32_t activeIndex = ReadGameU32(g_mainBase + 0x2303EC);
    const uint32_t activeCount = ReadGameU32(g_mainBase + 0x2306C4);
    if (activeIndex >= activeCount) {
        return false;
    }

    uintptr_t containerList = ReadGameU32(g_mainBase + 0x2306C0);
    if (containerList == 0) {
        return false;
    }

    uintptr_t container = ReadGameU32(containerList + static_cast<uintptr_t>(activeIndex) * sizeof(uint32_t));
    if (container == 0) {
        return false;
    }

    const int32_t count = static_cast<int32_t>(ReadGameU32(container + 0x0C));
    if (count <= 0) {
        return false;
    }

    uintptr_t entries = ReadGameU32(container + 0x08);
    if (entries == 0) {
        return false;
    }

    for (int32_t i = 0; i < count; ++i) {
        uintptr_t node = ReadGameU32(entries + static_cast<uintptr_t>(i) * sizeof(uint32_t));
        if (node == 0 || ReadGameU16(node) != static_cast<uint16_t>(current)) {
            continue;
        }

        ++i;
        if (i >= count) {
            return false;
        }

        node = ReadGameU32(entries + static_cast<uintptr_t>(i) * sizeof(uint32_t));
        if (node == 0) {
            return false;
        }

        target = ReadGameU16(node);
        g_targetTmp = target;
        return true;
    }

    return false;
}

BYTE* FindGroup(uint32_t current)
{
    const LONG count = g_groupCount;
    for (LONG i = 0; i < count; ++i) {
        BYTE* group = GroupPtr(static_cast<size_t>(i));
        if (ReadGroupU32(group, 0x00) == current) {
            return group;
        }
    }

    return nullptr;
}

BYTE* CreateGroup(uintptr_t entry, uint32_t current, uint32_t target)
{
    LONG count = g_groupCount;
    if (count >= static_cast<LONG>(kMaxGroups)) {
        return nullptr;
    }

    BYTE* group = GroupPtr(static_cast<size_t>(count));
    WriteGroupU32(group, 0x00, current);
    WriteGroupU32(group, 0x04, target);
    WriteGroupU32(group, 0x08, 0);
    WriteGroupU32(group, 0x0C, static_cast<uint32_t>(entry));
    InterlockedExchange(&g_groupCount, count + 1);
    return group;
}

void AddPayload(BYTE* group, uintptr_t entry)
{
    uint32_t count = ReadGroupU32(group, 0x08);
    if (count >= kMaxPayloadsPerGroup) {
        return;
    }

    BYTE* payload = group + 0x10 + count * 8;
    const uint32_t first = ReadGameU32(entry);
    const uint32_t second = ReadGameU32(entry + 0x04);
    std::memcpy(payload, &first, sizeof(first));
    std::memcpy(payload + 4, &second, sizeof(second));
    ++count;
    WriteGroupU32(group, 0x08, count);
}

void BuildGroups()
{
    InterlockedExchange(&g_groupCount, 0);
    InterlockedExchange(&g_groupIndex, 0);
    std::memset(g_groups, 0, sizeof(g_groups));

    uintptr_t list = ReadGameU32(g_mainBase + 0x230644);
    if (list == 0) {
        return;
    }

    int32_t count = static_cast<int32_t>(ReadGameU32(g_mainBase + 0x230648));
    if (count <= 0) {
        return;
    }
    if (count > 20) {
        count = 20;
    }

    for (int32_t i = 0; i < count; ++i) {
        uintptr_t entry = ReadGameU32(list + static_cast<uintptr_t>(i) * sizeof(uint32_t));
        if (entry == 0 ||
            ReadGameU32(entry + 0x1C) != 2 ||
            ReadGameU32(entry + 0x20) != 3) {
            continue;
        }

        uint32_t current = 0;
        uint32_t target = 0;
        if (!GetTarget(entry, current, target)) {
            continue;
        }

        BYTE* group = FindGroup(current);
        if (!group) {
            group = CreateGroup(entry, current, target);
        }
        if (group) {
            AddPayload(group, entry);
        }
    }

    if (g_groupCount != 0) {
        InterlockedExchange(&g_phase, 1);
        InterlockedExchange(&g_nextTick, 0);
    }
}

void SetNextPhase(LONG phase)
{
    InterlockedExchange(&g_nextTick, static_cast<LONG>(GetTickCount() + kPhaseGapMs));
    InterlockedExchange(&g_phase, phase);
}

void FinishAll()
{
    InterlockedExchange(&g_phase, 0);
    InterlockedExchange(&g_groupCount, 0);
    InterlockedExchange(&g_groupIndex, 0);
    InterlockedExchange(&g_action, 1);
}

void Send1483(BYTE* group)
{
    std::memset(g_dashBuffer, 0, sizeof(g_dashBuffer));
    g_dashBuffer[3] = static_cast<BYTE>(ReadGroupU32(group, 0x00));
    g_dashBuffer[4] = 0;

    uint32_t count = ReadGroupU32(group, 0x08);
    if (count > kMaxPayloadsPerGroup) {
        count = static_cast<uint32_t>(kMaxPayloadsPerGroup);
    }
    g_dashBuffer[5] = static_cast<BYTE>(count);

    const BYTE* source = group + 0x10;
    BYTE* destination = g_dashBuffer + 0x06;
    for (uint32_t i = 0; i < count; ++i) {
        std::memcpy(destination, source, 8);
        source += 8;
        destination += 8;
    }

    uint32_t targetBlock = 0;
    std::memcpy(destination, &targetBlock, sizeof(targetBlock));
    destination[3] = static_cast<BYTE>(ReadGroupU32(group, 0x04));

    const uint32_t payloadLength = count * 8 + 10;
    SendPacketWithEcx(ReadGroupU32(group, 0x0C), 0x1483, g_dashBuffer, payloadLength);

    LONG nextIndex = g_groupIndex + 1;
    InterlockedExchange(&g_groupIndex, nextIndex);
    if (nextIndex >= g_groupCount) {
        FinishAll();
        return;
    }

    SetNextPhase(5);
}

void SendCurrentPhase()
{
    const DWORD now = GetTickCount();
    if (now < static_cast<DWORD>(g_nextTick)) {
        return;
    }

    const LONG groupIndex = g_groupIndex;
    if (groupIndex >= g_groupCount) {
        FinishAll();
        return;
    }

    BYTE* group = GroupPtr(static_cast<size_t>(groupIndex));
    const uint32_t ecxValue = ReadGroupU32(group, 0x0C);
    switch (g_phase) {
    case 1:
        SendPacketWithEcx(ecxValue, 0x1467, nullptr, 0);
        SetNextPhase(2);
        break;
    case 2:
        SendPacketWithEcx(ecxValue, 0x373F, nullptr, 0);
        SetNextPhase(3);
        break;
    case 3:
        SendPacketWithEcx(ecxValue, 0x31E6, nullptr, 0);
        SetNextPhase(4);
        break;
    case 4:
        Send1483(group);
        break;
    case 5:
        InterlockedExchange(&g_phase, 1);
        break;
    default:
        InterlockedExchange(&g_phase, 0);
        InterlockedExchange(&g_action, 1);
        break;
    }
}

__declspec(noinline) void __stdcall DashTick()
{
    InterlockedExchange(&g_action, 0);
    if (g_phase == 0) {
        BuildGroups();
        if (g_groupCount == 0) {
            InterlockedExchange(&g_action, 1);
            return;
        }
    }

    SendCurrentPhase();
}

bool BuildMainCode(uintptr_t base, CodeBuffer& code)
{
    const uint32_t action = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(&g_action));
    return AppendByte(code, 0x9C) &&
        AppendPushad(code) &&
        AppendRel32Instruction(code, 0xE8, reinterpret_cast<uintptr_t>(&DashTick)) &&
        AppendPopad(code) &&
        AppendByte(code, 0x9D) &&
        AppendCmpDwordAbsImm8(code, action, 1) &&
        AppendJeShort(code, 0x01) &&
        AppendByte(code, 0xC3) &&
        AppendByte(code, 0x56) &&
        AppendRel32Instruction(code, 0xE8, base + 0x38B90) &&
        AppendRel32Instruction(code, 0xE9, base + 0x351F6);
}

bool BuildGuardCode(uintptr_t base, CodeBuffer& code)
{
    const uint32_t action = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(&g_action));
    return AppendCmpDwordAbsImm8(code, action, 1) &&
        AppendJeShort(code, 0x01) &&
        AppendByte(code, 0xC3) &&
        AppendFunctionPrologueWithStack(code, 0x0C) &&
        AppendRel32Instruction(code, 0xE9, base + 0x3B7A6);
}

bool BuildTimerCode(uintptr_t base, CodeBuffer& code)
{
    const uint32_t phase = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(&g_phase));
    const uint32_t action = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(&g_action));
    return AppendRel32Instruction(code, 0xE8, base + 0x351F0) &&
        AppendByte(code, 0x6A) && AppendByte(code, 0x00) &&
        AppendCmpDwordAbsImm8(code, phase, 0) &&
        AppendJneShort(code, 0x13) &&
        AppendCmpDwordAbsImm8(code, action, 0) &&
        AppendJeShort(code, 0x0A) &&
        AppendPushImm32(code, 0x4E20) &&
        AppendRel32Instruction(code, 0xE9, base + 0x403AF) &&
        AppendPushImm32(code, kPhaseGapMs) &&
        AppendRel32Instruction(code, 0xE9, base + 0x403AF);
}

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

void HandleRecvPacket(uint32_t opcode, const BYTE* payload)
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

namespace PrizePool
{

uint32_t BuildPayload(uint32_t value)
{
    using BuildPayloadFn = uint32_t(__stdcall*)(uint32_t);
    BuildPayloadFn buildPayload = *reinterpret_cast<BuildPayloadFn*>(g_mainBase + 0x1C4930);
    return buildPayload ? buildPayload(value) : 0;
}

void SendPacket(uint32_t opcode, const void* payload, uint32_t payloadLength)
{
    using SendPacketFn = void(__stdcall*)(uint32_t, const void*, uint32_t);
    SendPacketFn sendPacket = reinterpret_cast<SendPacketFn>(g_mainBase + 0x4A360);
    sendPacket(opcode, payload, payloadLength);
}

void WriteLog(const wchar_t* text)
{
    using PrintLogFn = void(__cdecl*)(uintptr_t, const wchar_t*, const wchar_t*);
    using RefreshLogFn = void(__stdcall*)(uint32_t, uint32_t, uint32_t, uint32_t);

    PrintLogFn printLog = reinterpret_cast<PrintLogFn>(g_mainBase + 0x2EF0);
    RefreshLogFn refreshLog = *reinterpret_cast<RefreshLogFn*>(g_mainBase + 0x1C46B0);

    printLog(g_mainBase + 0x230504, kLogFormat, text);
    if (refreshLog) {
        refreshLog(ReadGameU32(g_mainBase + 0x2300A4), ReadGameU32(g_mainBase + 0x2304D8), 0, 0);
    }
}

void SendAction(BYTE action)
{
    g_payload[0] = BuildPayload(static_cast<uint32_t>(g_id));
    g_payload[1] = 0;
    reinterpret_cast<BYTE*>(g_payload)[4] = action;
    SendPacket(0x3EA5, g_payload, 5);
}

void SendQuery()
{
    SendPacket(0x25EE, kQueryPayload, sizeof(kQueryPayload));
}

void HandleRecvPacket(uint32_t opcode, const BYTE* payload)
{
    if ((opcode & 0xFFFF) != 0x3EA4 || !payload) {
        return;
    }

    InterlockedExchange(&g_id, static_cast<LONG>(BuildPayload(ReadU32Unaligned(payload))));
    InterlockedExchange(&g_count, static_cast<LONG>(payload[0x215]));
    InterlockedExchange(&g_state, static_cast<LONG>(payload[0x21A]));
    InterlockedExchange(&SharedRecvRouter::g_clearStackArg, 1);
}

__declspec(noinline) void __stdcall SendHook()
{
    if (ReadGameU32(g_mainBase + 0x230388) == 0) {
        return;
    }

    const DWORD now = GetGameTick();
    g_now = now;

    const DWORD lastQuery = static_cast<DWORD>(g_lastQuery);
    if (lastQuery == 0 || now - lastQuery > 0x00200B20) {
        InterlockedExchange(&g_lastQuery, static_cast<LONG>(now));
        SendQuery();
        return;
    }

    if (g_id == 0) {
        return;
    }

    if ((static_cast<BYTE>(g_state) == 0xFF)) {
        if (g_count == 0) {
            return;
        }

        SendAction(1);
        SendAction(2);
        InterlockedExchange(&g_count, 0);
        WriteLog(kLogCase);
        return;
    }

    SendAction(2);
    WriteLog(kLogCase);
}

bool BuildSendCode(uintptr_t, CodeBuffer& code)
{
    return AppendPushad(code) &&
        AppendRel32Instruction(code, 0xE8, reinterpret_cast<uintptr_t>(&SendHook)) &&
        AppendPopad(code) &&
        AppendByte(code, 0xC3);
}

}

namespace WeeklyReward
{

void SendPacket(uint32_t opcode, const void* payload, uint32_t payloadLength)
{
    using SendPacketFn = void(__stdcall*)(uint32_t, const void*, uint32_t);
    SendPacketFn sendPacket = reinterpret_cast<SendPacketFn>(g_mainBase + 0x4A360);
    sendPacket(opcode, payload, payloadLength);
}

void RefreshLog()
{
    using RefreshLogFn = void(__stdcall*)(uint32_t, uint32_t, uint32_t, uint32_t);
    RefreshLogFn refreshLog = *reinterpret_cast<RefreshLogFn*>(g_mainBase + 0x1C46B0);
    if (refreshLog) {
        refreshLog(ReadGameU32(g_mainBase + 0x2300A4), ReadGameU32(g_mainBase + 0x2304D8), 0, 0);
    }
}

void WriteRecvLog()
{
    using PrintLogFn = void(__cdecl*)(uintptr_t, const wchar_t*, uint32_t);
    PrintLogFn printLog = reinterpret_cast<PrintLogFn>(g_mainBase + 0x2EF0);
    printLog(g_mainBase + 0x230504, kRecvLogFormat, static_cast<uint32_t>(g_activity));
    RefreshLog();
}

void WriteRewardLog()
{
    using PrintLogFn = void(__cdecl*)(uintptr_t, const wchar_t*, uint32_t);
    PrintLogFn printLog = reinterpret_cast<PrintLogFn>(g_mainBase + 0x2EF0);
    printLog(g_mainBase + 0x230504, kRewardLogFormat, static_cast<uint32_t>(g_rewardNextIndex));
    RefreshLog();
}

void FindNextPattern(const BYTE* payload, uint32_t payloadLength)
{
    InterlockedExchange(&g_nextData, -1);
    if (!payload || payloadLength < 8) {
        return;
    }

    for (uint32_t offset = 0; offset <= payloadLength - 8; ++offset) {
        if (ReadU32Unaligned(payload + offset) == 0x09007D7B) {
            InterlockedExchange(&g_nextData, static_cast<LONG>(ReadU32Unaligned(payload + offset + 4)));
            return;
        }
    }
}

void HandleRecvPacket(uint32_t opcode, const BYTE* payload, uint32_t payloadLength)
{
    if ((opcode & 0xFFFF) != 0x4BB0 || !payload) {
        return;
    }

    InterlockedExchange(&g_recvLen, static_cast<LONG>(payloadLength));
    std::memset(g_packetDump, 0, sizeof(g_packetDump));

    const uint32_t packetLength = payloadLength + 4;
    g_packetDump[0] = static_cast<BYTE>((packetLength >> 8) & 0xFF);
    g_packetDump[1] = static_cast<BYTE>(packetLength & 0xFF);
    g_packetDump[2] = 0x4B;
    g_packetDump[3] = 0xB0;

    const uint32_t copyLength = payloadLength < 0x7FC ? payloadLength : 0x7FC;
    if (copyLength != 0) {
        std::memcpy(g_packetDump + 4, payload, copyLength);
    }

    if (payloadLength >= 4) {
        const uint32_t activity = (static_cast<uint32_t>(payload[2]) << 8) + payload[3];
        InterlockedExchange(&g_activity, static_cast<LONG>(activity));
        WriteRecvLog();
    }

    FindNextPattern(payload, payloadLength);
    if (g_nextData == -1 || g_nextData == g_lastSentData) {
        return;
    }

    InterlockedExchange(&g_pendingNext, 1);
    InterlockedExchange(&g_cmdSendNext, 1);
}

void ResetRewardScanState()
{
    InterlockedExchange(&g_rewardCmdSend, 0);
    InterlockedExchange(&g_rewardCount, 0);
    InterlockedExchange(&g_rewardCandidateCount, 0);
    for (size_t i = 0; i < sizeof(g_rewardStates) / sizeof(g_rewardStates[0]); ++i) {
        InterlockedExchange(&g_rewardStates[i], 0);
    }
}

void ScanRewards()
{
    ResetRewardScanState();
    if (g_packetDump[2] != 0x4B || g_packetDump[3] != 0xB0) {
        return;
    }

    const uint32_t recvLen = static_cast<uint32_t>(g_recvLen);
    if (recvLen < 5) {
        return;
    }

    uint32_t scanLength = recvLen - 4;
    if (scanLength > 0x7FC) {
        scanLength = 0x7FC;
    }
    BYTE* cursor = g_packetDump + 4;
    for (uint32_t remaining = scanLength; remaining != 0; --remaining, ++cursor) {
        if (ReadU32Unaligned(cursor) != 0x0000007D) {
            continue;
        }

        const uint32_t state = cursor[4];
        if (state < 1 || state > 3 || g_rewardCount >= 7) {
            continue;
        }

        const LONG rewardIndex = g_rewardCount;
        InterlockedExchange(&g_rewardStates[rewardIndex], static_cast<LONG>(state));
        if (state == 2 && g_rewardCmdSend != 1) {
            const LONG oneBasedIndex = rewardIndex + 1;
            // CE [weekly_packet_dump+12] uses hex notation: +0x12.
            const LONG rewardId = static_cast<LONG>(g_packetDump[0x12]) + rewardIndex;
            InterlockedExchange(&g_rewardNextIndex, oneBasedIndex);
            if (rewardId != g_rewardLastSentId) {
                InterlockedExchange(&g_rewardNextId, rewardId);
                InterlockedExchange(&g_rewardCmdSend, 1);
            }
        }

        InterlockedIncrement(&g_rewardCount);
        InterlockedIncrement(&g_rewardCandidateCount);
    }
}

void SendQuery()
{
    InterlockedExchange(&g_lastQueryTick, static_cast<LONG>(GetGameTick()));
    InterlockedExchange(&g_cmdSendNext, 0);
    InterlockedExchange(&g_pendingNext, 0);
    InterlockedExchange(&g_lastSentData, -1);
    InterlockedExchange(&g_rewardLastSentId, -1);
    SendPacket(0x4BAF, nullptr, 0);
}

void SendNext()
{
    InterlockedExchange(&g_cmdSendNext, 0);
    InterlockedExchange(&g_pendingNext, 0);
    g_nextPayload = static_cast<uint32_t>(g_nextData);
    SendPacket(0x4BB1, &g_nextPayload, sizeof(g_nextPayload));
    InterlockedExchange(&g_lastSentData, static_cast<LONG>(g_nextPayload));
}

void SendReward()
{
    InterlockedExchange(&g_rewardCmdSend, 0);
    g_rewardPayload = 0;
    reinterpret_cast<BYTE*>(&g_rewardPayload)[3] = static_cast<BYTE>(g_rewardNextId);
    SendPacket(0x4BB2, &g_rewardPayload, sizeof(g_rewardPayload));
    g_packetDump[2] = 0;
    g_packetDump[3] = 0;
    InterlockedExchange(&g_rewardLastSentId, g_rewardNextId);
    WriteRewardLog();
}

__declspec(noinline) void __stdcall SendHook()
{
    if (ReadGameU32(g_mainBase + 0x2303B0) == 0) {
        InterlockedExchange(&g_lastQueryTick, 0);
        InterlockedExchange(&g_cmdSendNext, 0);
        InterlockedExchange(&g_pendingNext, 0);
        InterlockedExchange(&g_rewardCmdSend, 0);
        return;
    }

    ScanRewards();
    if (g_rewardCmdSend == 1) {
        SendReward();
        return;
    }

    if (g_cmdSendNext == 1) {
        SendNext();
        return;
    }

    const DWORD now = GetGameTick();
    const DWORD lastQuery = static_cast<DWORD>(g_lastQueryTick);
    if (lastQuery == 0 || now - lastQuery >= kQueryInterval) {
        SendQuery();
    }
}

bool BuildSendCode(uintptr_t, CodeBuffer& code)
{
    return AppendPushad(code) &&
        AppendRel32Instruction(code, 0xE8, reinterpret_cast<uintptr_t>(&SendHook)) &&
        AppendPopad(code) &&
        AppendByte(code, 0xC3);
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

}

namespace SharedRecvRouter
{

__declspec(noinline) void __stdcall DispatchHook(uint32_t opcode, const BYTE* payload, uint32_t payloadLength)
{
    InterlockedExchange(&g_clearStackArg, 0);
    DailySign::HandleRecvPacket(opcode, payload);
    PrizePool::HandleRecvPacket(opcode, payload);
    WeeklyReward::HandleRecvPacket(opcode, payload, payloadLength);
}

bool BuildCode(uintptr_t base, CodeBuffer& code)
{
    const uint32_t clearStackArg = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(&g_clearStackArg));

    return AppendPushad(code) &&
        AppendMovDwordAbsImm32(code, clearStackArg, 0) &&
        AppendPushDwordPtrEspOffset(code, 0x24) &&
        AppendPushEdx(code) &&
        AppendMovzxEaxCx(code) &&
        AppendPushEax(code) &&
        AppendRel32Instruction(code, 0xE8, reinterpret_cast<uintptr_t>(&DispatchHook)) &&
        AppendCmpDwordAbsImm8(code, clearStackArg, 0) &&
        AppendJeShort(code, 0x08) &&
        AppendMovDwordPtrEspOffsetImm32(code, 0x24, 0) &&
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

size_t AppendWideMessage(wchar_t* buffer, size_t capacity, size_t used, const wchar_t* text)
{
    if (used >= capacity) {
        return used;
    }

    const int written = std::swprintf(buffer + used, capacity - used, L"%s", text);
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

bool IsPatchApplied(const PatchResult* results, size_t count, const char* name)
{
    for (size_t i = 0; i < count; ++i) {
        if (results[i].patch && std::strcmp(results[i].patch->name, name) == 0) {
            return results[i].applied;
        }
    }

    return false;
}

bool IsJumpPatchApplied(const JumpPatchResult* results, size_t count, const char* name)
{
    for (size_t i = 0; i < count; ++i) {
        if (results[i].patch && std::strcmp(results[i].patch->name, name) == 0) {
            return results[i].applied;
        }
    }

    return false;
}

void AppendFeatureStatus(wchar_t* message, size_t capacity, size_t& used, const wchar_t* name, bool ok)
{
    wchar_t line[128]{};
    std::swprintf(line, sizeof(line) / sizeof(line[0]), L"%s %s\n", name, ok ? L"OK" : L"FAILED");
    used = AppendWideMessage(message, capacity, used, line);
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
    wchar_t message[2048]{};
    const int headerLength = std::swprintf(
        message,
        sizeof(message) / sizeof(message[0]),
        L"PID: %lu\nPID hex: 0x%lX\nBase: %p\nByte patches: %zu/%zu applied\nJump patches: %zu/%zu applied\n\n",
        pid,
        pid,
        reinterpret_cast<void*>(base),
        appliedCount,
        kPatchCount,
        appliedJumpCount,
        kJumpPatchCount);
    size_t used = headerLength > 0 ? static_cast<size_t>(headerLength) : 0;

    const bool sharedRouterOk = IsJumpPatchApplied(jumpResults, kJumpPatchCount, "Shared recv router");
    const bool dragonVeinOk = IsPatchApplied(results, kPatchCount, "Dragon vein fix");
    const bool breakEggOk = IsPatchApplied(results, kPatchCount, "Break egg fix");
    const bool dailySignOk = sharedRouterOk &&
        IsJumpPatchApplied(jumpResults, kJumpPatchCount, "Daily Sign send tick");
    const bool prizePoolOk = sharedRouterOk &&
        IsJumpPatchApplied(jumpResults, kJumpPatchCount, "Prize Pool sender");
    const bool weeklyRewardOk = sharedRouterOk &&
        IsJumpPatchApplied(jumpResults, kJumpPatchCount, "Weekly Reward sender");
    const bool lgfOk = IsPatchApplied(results, kPatchCount, "LGF refresh interval") &&
        IsPatchApplied(results, kPatchCount, "LGF suppress action log") &&
        IsJumpPatchApplied(jumpResults, kJumpPatchCount, "LGF status log") &&
        IsJumpPatchApplied(jumpResults, kJumpPatchCount, "LGF 396D guard") &&
        IsJumpPatchApplied(jumpResults, kJumpPatchCount, "LGF 3970 guard");
    const bool fastDailyBattleOk = IsJumpPatchApplied(jumpResults, kJumpPatchCount, "Fast Daily Battle");
    const bool autoLureDashOk = IsJumpPatchApplied(jumpResults, kJumpPatchCount, "AutoLure dash main") &&
        IsJumpPatchApplied(jumpResults, kJumpPatchCount, "AutoLure dash guard") &&
        IsJumpPatchApplied(jumpResults, kJumpPatchCount, "AutoLure dash timer");

    AppendFeatureStatus(message, sizeof(message) / sizeof(message[0]), used, L"\x5171\x7528\x6536\x5305Router", sharedRouterOk);
    AppendFeatureStatus(message, sizeof(message) / sizeof(message[0]), used, L"\x9F8D\x8108", dragonVeinOk);
    AppendFeatureStatus(message, sizeof(message) / sizeof(message[0]), used, L"\x7838\x86CB", breakEggOk);
    AppendFeatureStatus(message, sizeof(message) / sizeof(message[0]), used, L"\x6BCF\x65E5\x7C3D\x5230", dailySignOk);
    AppendFeatureStatus(message, sizeof(message) / sizeof(message[0]), used, L"\x734E\x6C60\x653E\x9001", prizePoolOk);
    AppendFeatureStatus(message, sizeof(message) / sizeof(message[0]), used, L"\x5468\x5E38\x4EFB\x52D9", weeklyRewardOk);
    AppendFeatureStatus(message, sizeof(message) / sizeof(message[0]), used, L"\x7DF4\x529F\x623F", lgfOk);
    AppendFeatureStatus(message, sizeof(message) / sizeof(message[0]), used, L"\x5FEB\x901F\x6BCF\x65E5\x6230\x9B25", fastDailyBattleOk);
    AppendFeatureStatus(message, sizeof(message) / sizeof(message[0]), used, L"\x81EA\x52D5\x7A81\x9032", autoLureDashOk);

    g_msgBoxHook = SetWindowsHookExA(WH_CBT, MessageBoxHook, nullptr, GetCurrentThreadId());
    MessageBoxW(nullptr, message, L"MyPatch", MB_OK);
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
