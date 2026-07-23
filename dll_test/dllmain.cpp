#include <windows.h>
#include <algorithm>
#include <climits>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cwchar>
#include <string>
#include <vector>

#include "license_tls_client.h"
#include "native_optimization.h"

namespace
{
HHOOK g_msgBoxHook = nullptr;
HMODULE g_selfModule = nullptr;
wchar_t g_patchStatusMessage[2048]{};
constexpr DWORD kMessageBoxAutoCloseMs = 3000;
constexpr wchar_t kMyPatchVersion[] = L"0.15b";

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

bool IsNativeEntryReady()
{
    if (g_mainBase == 0) {
        return false;
    }
    HWND mainHwnd = *reinterpret_cast<HWND volatile*>(g_mainBase + 0x2300A4);
    if (!mainHwnd || !IsWindow(mainHwnd)) {
        return false;
    }
    HWND startHwnd = GetDlgItem(mainHwnd, 1010);
    return startHwnd && IsWindowEnabled(startHwnd) != FALSE;
}

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
volatile LONG g_pending = 0;
volatile LONG g_router3Ea4Hits = 0;
volatile LONG g_routerSwitchSeen = 0;
volatile LONG g_routerPendingSets = 0;
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

namespace Jrnt
{
volatile LONG g_this = 0;
volatile LONG g_didWork = 0;
volatile LONG g_pendingOpen = 0;
volatile LONG g_bribeTaskActive = 0;
volatile LONG g_bribeTaskTarget = 0;
volatile LONG g_bribeTaskSchedule = 0;
volatile LONG g_bribeSnapshotGeneration = 0;
volatile LONG g_bribeConsumedGeneration = 0;
uint32_t g_ids[4] = { 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0 };
BYTE g_claimPending[4]{};
BYTE g_payloadZero = 0;
BYTE g_payload4F37 = 0;
uint32_t g_payload4F36 = 0;

const BYTE kBribeTaskName[] = {
    0xE8, 0xA0, 0xBB, 0xE6, 0x97, 0x8F, 0xE5, 0xA4, 0x96, 0xE4, 0xBA, 0xA4
};
const BYTE kBribeTaskDescription[] = {
    0xE6, 0x94, 0xB6, 0xE8, 0xB2, 0xB7, 0xE8, 0xA0, 0xBB, 0xE6, 0x97, 0x8F
};

const wchar_t kLogOpen[] = {
    0x570B, 0x5BB6, 0x52D5, 0x54E1, 0x0020, 0x958B, 0x555F, 0x5BF6, 0x7BB1, 0x0000
};
const wchar_t kLogClaim[] = {
    0x570B, 0x5BB6, 0x52D5, 0x54E1, 0x0020, 0x9818, 0x53D6, 0x5BF6, 0x7BB1, 0x0000
};
}

namespace Xyfp
{
constexpr size_t kMaxPatterns = 5;

uint32_t g_payload4C83 = 0;
BYTE g_payload4C86[8]{};
BYTE g_payload145A[0x2F] = {
    0x00, 0x00, 0x00, 0x00, 0x24, 0x00, 0x05
};
BYTE g_payload4C87[0x0C] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x01
};
volatile LONG g_day = 0;
volatile LONG g_stamina = 0;
volatile LONG g_patternCount = 0;
volatile LONG g_payload8Count = 0;
volatile LONG g_candidateStage = 0;
volatile LONG g_clearCount = 0;
BYTE g_payload8s[kMaxPatterns * 8]{};

const wchar_t kLogBattleFormat[] = {
    0x79D8, 0x5883, 0x6230, 0x9B42, 0x0020, 0x0025, 0x0064, 0x0000
};
const wchar_t kLogSweepFormat[] = {
    0x6230, 0x9B42, 0x79D8, 0x5883, 0x0020, 0x6383, 0x8569, 0x0020, 0x0025, 0x0064, 0x0000
};
}

namespace PersonalTask
{
volatile LONG g_level = 0;
volatile LONG g_pendingPromo = 0;
uint16_t g_rewardIds[4]{};
BYTE g_rewardValid[4]{};
BYTE g_claimPending[4]{};
volatile LONG g_didWork = 0;
BYTE g_payloadZero = 0;
uint32_t g_payload4E62 = 0;

const wchar_t kLogPromoMid[] = {
    0x500B, 0x4EBA, 0x4EFB, 0x52D9, 0x0020, 0x9818, 0x53D6, 0x4E2D,
    0x7D1A, 0x6649, 0x5347, 0x734E, 0x52F5, 0x0000
};
const wchar_t kLogPromoHigh[] = {
    0x500B, 0x4EBA, 0x4EFB, 0x52D9, 0x0020, 0x9818, 0x53D6, 0x9AD8,
    0x7D1A, 0x6649, 0x5347, 0x734E, 0x52F5, 0x0000
};
const wchar_t kLogPromoFinal[] = {
    0x500B, 0x4EBA, 0x4EFB, 0x52D9, 0x0020, 0x9818, 0x53D6, 0x7D42,
    0x6975, 0x6649, 0x5347, 0x734E, 0x52F5, 0x0000
};
const wchar_t kLogSmallMid[3][20] = {
    { 0x500B, 0x4EBA, 0x4EFB, 0x52D9, 0x0020, 0x9818, 0x53D6, 0x7B2C, 0x0020, 0x0031, 0x0020, 0x500B, 0x0020, 0x4E2D, 0x7D1A, 0x0020, 0x734E, 0x52F5, 0x0000 },
    { 0x500B, 0x4EBA, 0x4EFB, 0x52D9, 0x0020, 0x9818, 0x53D6, 0x7B2C, 0x0020, 0x0032, 0x0020, 0x500B, 0x0020, 0x4E2D, 0x7D1A, 0x0020, 0x734E, 0x52F5, 0x0000 },
    { 0x500B, 0x4EBA, 0x4EFB, 0x52D9, 0x0020, 0x9818, 0x53D6, 0x7B2C, 0x0020, 0x0033, 0x0020, 0x500B, 0x0020, 0x4E2D, 0x7D1A, 0x0020, 0x734E, 0x52F5, 0x0000 },
};
const wchar_t kLogSmallHigh[3][20] = {
    { 0x500B, 0x4EBA, 0x4EFB, 0x52D9, 0x0020, 0x9818, 0x53D6, 0x7B2C, 0x0020, 0x0031, 0x0020, 0x500B, 0x0020, 0x9AD8, 0x7D1A, 0x0020, 0x734E, 0x52F5, 0x0000 },
    { 0x500B, 0x4EBA, 0x4EFB, 0x52D9, 0x0020, 0x9818, 0x53D6, 0x7B2C, 0x0020, 0x0032, 0x0020, 0x500B, 0x0020, 0x9AD8, 0x7D1A, 0x0020, 0x734E, 0x52F5, 0x0000 },
    { 0x500B, 0x4EBA, 0x4EFB, 0x52D9, 0x0020, 0x9818, 0x53D6, 0x7B2C, 0x0020, 0x0033, 0x0020, 0x500B, 0x0020, 0x9AD8, 0x7D1A, 0x0020, 0x734E, 0x52F5, 0x0000 },
};
const wchar_t kLogSmallFinal[3][20] = {
    { 0x500B, 0x4EBA, 0x4EFB, 0x52D9, 0x0020, 0x9818, 0x53D6, 0x7B2C, 0x0020, 0x0031, 0x0020, 0x500B, 0x0020, 0x7D42, 0x6975, 0x0020, 0x734E, 0x52F5, 0x0000 },
    { 0x500B, 0x4EBA, 0x4EFB, 0x52D9, 0x0020, 0x9818, 0x53D6, 0x7B2C, 0x0020, 0x0032, 0x0020, 0x500B, 0x0020, 0x7D42, 0x6975, 0x0020, 0x734E, 0x52F5, 0x0000 },
    { 0x500B, 0x4EBA, 0x4EFB, 0x52D9, 0x0020, 0x9818, 0x53D6, 0x7B2C, 0x0020, 0x0033, 0x0020, 0x500B, 0x0020, 0x7D42, 0x6975, 0x0020, 0x734E, 0x52F5, 0x0000 },
};
}

namespace TaskDispatch
{
constexpr size_t kMaxTaskCount = 16;
constexpr DWORD kConfigWaitMs = 0x2710;

struct TaskId
{
    BYTE bytes[8]{};
};

struct TaskInfo
{
    TaskId id{};
    uint32_t quality = 0;
    uint32_t status = 0;
    uint32_t rank = 0x63;
};

volatile LONG g_parseError = 0;
volatile LONG g_currentDispatch = 0;
volatile LONG g_maxDispatch = 0;
volatile LONG g_freeSlots = 0;
volatile LONG g_unassignedCount = 0;
volatile LONG g_dispatchedCount = 0;
volatile LONG g_unassignedSeen = 0;
volatile LONG g_dispatchedSeen = 0;
TaskInfo g_unassigned[kMaxTaskCount]{};
TaskInfo g_dispatched[kMaxTaskCount]{};
volatile LONG g_claimPending = 0;
TaskId g_claimTaskId{};
volatile LONG g_bestPending = 0;
TaskId g_bestTaskId{};
volatile LONG g_bestRank = 0x63;
volatile LONG g_bestQuality = 0;
volatile LONG g_configReady = 0;
TaskId g_configTaskId{};
uint32_t g_4B45PayloadLen = 0;
BYTE g_4B45Payload[1024]{};
volatile LONG g_skipCount = 0;
TaskId g_skipIds[kMaxTaskCount]{};
volatile LONG g_senderTickCount = 0;
volatile LONG g_senderSendCount = 0;
volatile LONG g_senderLastOpcode = 0;
TaskId g_senderLastTaskId{};
volatile LONG g_waitConfig = 0;
volatile LONG g_waitTick = 0;
TaskId g_waitTaskId{};
BYTE g_payloadZero = 0;
TaskId g_payload4B47{};
TaskId g_payload4B4A{};

const wchar_t kLogClaim[] = {
    0x4EFB, 0x52D9, 0x6D3E, 0x9063, 0x0020, 0x9818, 0x734E, 0x0000
};
const wchar_t kLogDispatch[] = {
    0x4EFB, 0x52D9, 0x6D3E, 0x9063, 0x0020, 0x57F7, 0x884C, 0x0000
};

void SendTick();
void HandleRecvPacket(uint32_t opcode, const BYTE* payload, uint32_t payloadLength);
}

uint16_t ReadBe16Unaligned(const BYTE* address);
uint32_t ReadBe32Unaligned(const BYTE* address);
DWORD GetGameTick();

namespace GameLog
{
template <typename... Args>
void Write(const wchar_t* format, Args... args);
}

namespace TaskDispatchUi
{
extern volatile LONG g_dianFengZhuLuSwitch;
extern volatile LONG g_huanJingSwitch;
}

namespace AlBattle
{
size_t CopyReadyHeroUuids(BYTE* output, size_t capacity);
}

namespace DianFengZhuLu
{
constexpr DWORD kResponseTimeoutMs = 15000;
constexpr DWORD kBattlePollMs = 15000;
constexpr DWORD kIdlePollMs = 5000;
constexpr DWORD kMaxResetSeconds = 7 * 24 * 60 * 60;
constexpr size_t kMaxHeroes = 16;

enum State : LONG
{
    kIdle = 0,
    kWaitingPanel = 1,
    kSendSelection = 2,
    kWaitingFormation = 3,
    kSendFormation = 4,
    kWaitingFormationSave = 5,
    kRepeatChallenge = 6,
    kStartBattle = 7,
    kWaitingBattle = 8,
    kSendBuffReplace = 9,
    kWaitingBuffReplace = 10,
    kWaitingBuffList = 11,
    kWaitingRecovery = 12,
    kSendRecoverySkip = 13,
    kSendFastBattleRetry = 14
};

struct PacketReader
{
    const BYTE* cursor = nullptr;
    const BYTE* end = nullptr;

    bool ReadByte(BYTE& value)
    {
        if (!cursor || cursor >= end) return false;
        value = *cursor++;
        return true;
    }

    bool ReadU16(uint16_t& value)
    {
        if (!cursor || cursor + 2 > end) return false;
        value = ReadBe16Unaligned(cursor);
        cursor += 2;
        return true;
    }

    bool ReadU32(uint32_t& value)
    {
        if (!cursor || cursor + 4 > end) return false;
        value = ReadBe32Unaligned(cursor);
        cursor += 4;
        return true;
    }

    bool Skip(size_t length)
    {
        if (!cursor || length > static_cast<size_t>(end - cursor)) return false;
        cursor += length;
        return true;
    }

    bool ReadUtf(const BYTE*& text, uint16_t& length)
    {
        if (!ReadU16(length) || length > static_cast<size_t>(end - cursor)) return false;
        text = cursor;
        cursor += length;
        return true;
    }

    bool SkipUtf()
    {
        const BYTE* text = nullptr;
        uint16_t length = 0;
        return ReadUtf(text, length);
    }
};

struct Hero
{
    uint32_t heroId = 0;
    uint32_t uuidHigh = 0;
    uint32_t uuidLow = 0;
    uint32_t currentHp = 0;
    bool disabled = false;
};

struct PanelOption
{
    uint32_t optionLv = 0;
    int32_t score = 0;
    wchar_t buffName[128]{};
};

volatile LONG g_tickRunning = 0;
volatile LONG g_wasEnabled = 0;
volatile LONG g_state = kIdle;
volatile LONG g_deadlineTick = 0;
volatile LONG g_nextTick = 0;
volatile LONG g_resetDeadlineTick = 0;
volatile LONG g_dailyPauseDate = 0;
volatile LONG g_weeklyPaused = 0;
volatile LONG g_selectedOption = 0;
volatile LONG g_selectionMode = 0;
volatile LONG g_battleId = 0;
volatile LONG g_replaceTemplateId = 0;
volatile LONG g_pendingLog = 0;
volatile LONG g_parseError = 0;
volatile LONG g_battleActive = 0;
volatile LONG g_fastBattleRetrySent = 0;
volatile LONG g_battleStartTick = 0;
Hero g_heroes[kMaxHeroes]{};
size_t g_heroCount = 0;
wchar_t g_stageText[32] = L"?";
wchar_t g_battleStageText[32] = L"?";
wchar_t g_buffText[128] = L"?";
wchar_t g_lastBuffLogStage[32]{};
wchar_t g_lastBuffLogText[128]{};

bool IsEnabled()
{
    return TaskDispatchUi::g_dianFengZhuLuSwitch != 0;
}

LONG DateKey(const SYSTEMTIME& time)
{
    return static_cast<LONG>(time.wYear * 10000 + time.wMonth * 100 + time.wDay);
}

bool TickReached(DWORD now, LONG target)
{
    return target == 0 || static_cast<LONG>(now - static_cast<DWORD>(target)) >= 0;
}

void WriteU16(BYTE*& cursor, uint16_t value)
{
    *cursor++ = static_cast<BYTE>((value >> 8) & 0xFF);
    *cursor++ = static_cast<BYTE>(value & 0xFF);
}

void WriteU32(BYTE*& cursor, uint32_t value)
{
    *cursor++ = static_cast<BYTE>((value >> 24) & 0xFF);
    *cursor++ = static_cast<BYTE>((value >> 16) & 0xFF);
    *cursor++ = static_cast<BYTE>((value >> 8) & 0xFF);
    *cursor++ = static_cast<BYTE>(value & 0xFF);
}

void SendPacket(uint32_t opcode, const void* payload, uint32_t payloadLength)
{
    using SendPacketFn = void(__stdcall*)(uint32_t, const void*, uint32_t);
    reinterpret_cast<SendPacketFn>(g_mainBase + 0x4A360)(opcode, payload, payloadLength);
}

void CopyUtfToWide(const BYTE* text, uint16_t length, wchar_t* output, size_t capacity)
{
    if (!output || capacity == 0) return;
    output[0] = L'\0';
    if (!text || length == 0) return;
    int count = MultiByteToWideChar(CP_UTF8, 0, reinterpret_cast<const char*>(text), length,
        output, static_cast<int>(capacity - 1));
    if (count < 0) count = 0;
    output[count] = L'\0';
}

void ExtractStage(const BYTE* text, uint16_t length)
{
    wchar_t title[128]{};
    CopyUtfToWide(text, length, title, _countof(title));
    for (size_t index = 0; title[index] != L'\0'; ++index) {
        if (title[index] < L'0' || title[index] > L'9') continue;
        size_t out = 0;
        while (title[index] != L'\0' && out + 1 < _countof(g_stageText)) {
            const wchar_t ch = title[index];
            if ((ch >= L'0' && ch <= L'9') || ch == L'-') {
                g_stageText[out++] = ch;
                ++index;
                continue;
            }
            break;
        }
        g_stageText[out] = L'\0';
        if (out != 0) return;
    }
    wcscpy_s(g_stageText, L"?");
}

bool ParseUnsignedField(const char* json, const char* key, uint32_t& value)
{
    const char* found = strstr(json, key);
    if (!found) return false;
    found += strlen(key);
    while (*found == ' ' || *found == '\"' || *found == ':') ++found;
    uint64_t result = 0;
    bool any = false;
    while (*found >= '0' && *found <= '9') {
        any = true;
        result = result * 10 + static_cast<unsigned>(*found - '0');
        ++found;
    }
    value = static_cast<uint32_t>(result);
    return any;
}

bool ParseHeroExtra(const BYTE* text, uint16_t length, Hero& hero)
{
    char json[768]{};
    const size_t copyLength = length < sizeof(json) - 1 ? length : sizeof(json) - 1;
    memcpy(json, text, copyLength);
    json[copyLength] = '\0';
    ParseUnsignedField(json, "heroId", hero.heroId);
    const char* uuid = strstr(json, "heroUUID");
    if (uuid) {
        uuid = strchr(uuid, ':');
        if (uuid) {
            ++uuid;
            while (*uuid == ' ' || *uuid == '\"') ++uuid;
            uint64_t high = 0;
            while (*uuid >= '0' && *uuid <= '9') high = high * 10 + static_cast<unsigned>(*uuid++ - '0');
            if (*uuid == ',') ++uuid;
            uint64_t low = 0;
            while (*uuid >= '0' && *uuid <= '9') low = low * 10 + static_cast<unsigned>(*uuid++ - '0');
            hero.uuidHigh = static_cast<uint32_t>(high);
            hero.uuidLow = static_cast<uint32_t>(low);
        }
    }
    hero.disabled = strstr(json, "\"disabled\":true") != nullptr ||
        strstr(json, "\"disabled\":1") != nullptr;
    return hero.heroId != 0 && (hero.uuidHigh != 0 || hero.uuidLow != 0);
}

bool SkipBuff(PacketReader& reader, wchar_t* name, size_t nameCapacity, uint32_t* templateId)
{
    const BYTE* text = nullptr;
    uint16_t length = 0;
    uint32_t id = 0;
    uint32_t ignored = 0;
    uint16_t descCount = 0;
    if (!reader.ReadUtf(text, length) || !reader.ReadU32(id) || !reader.ReadU32(ignored) ||
        !reader.ReadU16(descCount)) return false;
    if (name) CopyUtfToWide(text, length, name, nameCapacity);
    if (templateId) *templateId = id;
    for (uint16_t index = 0; index < descCount; ++index) {
        if (!reader.SkipUtf()) return false;
    }
    return reader.ReadU32(ignored) && reader.SkipUtf();
}

bool ParsePanel(const BYTE* payload, uint32_t payloadLength, uint32_t& raidType,
    uint32_t& currentPower, uint32_t& firstOption, wchar_t* buffName, size_t buffCapacity,
    uint32_t& resetSeconds, uint16_t& optionCount)
{
    PacketReader reader{ payload, payload + payloadLength };
    const BYTE* title = nullptr;
    uint16_t titleLength = 0;
    uint32_t ignored = 0;
    if (!reader.ReadUtf(title, titleLength) || !reader.ReadU32(resetSeconds) ||
        !reader.ReadU32(raidType) || !reader.ReadU32(ignored) || !reader.ReadU32(currentPower) ||
        !reader.ReadU16(optionCount)) return false;
    ExtractStage(title, titleLength);
    firstOption = 0;
    PanelOption options[16]{};
    size_t savedOptionCount = 0;
    for (uint16_t optionIndex = 0; optionIndex < optionCount; ++optionIndex) {
        uint32_t optionLv = 0;
        uint32_t npcIcon = 0;
        uint32_t rawScore = 0;
        uint32_t soldierId = 0;
        uint16_t descCount = 0;
        if (!reader.ReadU32(optionLv) || !reader.ReadU32(npcIcon) || !reader.ReadU32(rawScore) ||
            !reader.ReadU32(soldierId) || !reader.ReadU16(descCount)) return false;
        for (uint16_t descIndex = 0; descIndex < descCount; ++descIndex) {
            if (!reader.SkipUtf()) return false;
        }
        if (!reader.SkipUtf() || !reader.SkipUtf()) return false;
        const BYTE* optionBuffName = nullptr;
        uint16_t optionBuffLength = 0;
        if (!reader.ReadUtf(optionBuffName, optionBuffLength)) return false;
        if (savedOptionCount < _countof(options)) {
            PanelOption& option = options[savedOptionCount++];
            option.optionLv = optionLv;
            option.score = static_cast<int32_t>(rawScore);
            CopyUtfToWide(optionBuffName, optionBuffLength, option.buffName, _countof(option.buffName));
        }
        if (!reader.Skip(12) || !reader.SkipUtf()) return false;
    }
    uint32_t currentScore = 0;
    uint32_t totalScore = 0;
    if (!reader.SkipUtf() || !reader.ReadU32(currentScore) || !reader.ReadU32(totalScore)) return false;
    for (size_t optionIndex = 0; optionIndex < savedOptionCount; ++optionIndex) {
        const PanelOption& option = options[optionIndex];
        const int64_t signedScore = static_cast<int64_t>(option.score);
        const uint64_t requiredScore = static_cast<uint64_t>(
            signedScore < 0 ? -signedScore : signedScore);
        if (raidType == 2 && static_cast<uint64_t>(currentScore) < requiredScore) continue;
        firstOption = option.optionLv;
        if (buffName) wcscpy_s(buffName, buffCapacity, option.buffName);
        break;
    }
    return true;
}

bool ParseRole(PacketReader& reader, Hero* hero)
{
    uint32_t ignored = 0;
    uint16_t ignored16 = 0;
    uint16_t tacticCount = 0;
    if (!reader.SkipUtf() || !reader.ReadU32(ignored)) return false;
    uint32_t currentHp = 0;
    if (!reader.ReadU32(currentHp) || !reader.ReadU32(ignored) || !reader.ReadU32(ignored) ||
        !reader.ReadU16(ignored16) || !reader.SkipUtf() || !reader.ReadU16(tacticCount)) return false;
    for (uint16_t index = 0; index < tacticCount; ++index) {
        if (!reader.ReadU32(ignored) || !reader.SkipUtf()) return false;
    }
    if (!reader.ReadU32(ignored)) return false;
    const BYTE* extra = nullptr;
    uint16_t extraLength = 0;
    if (!reader.ReadUtf(extra, extraLength)) return false;
    if (hero) {
        hero->currentHp = currentHp;
        return ParseHeroExtra(extra, extraLength, *hero);
    }
    return true;
}

bool ParseFormation(const BYTE* payload, uint32_t payloadLength, BYTE& offon,
    uint32_t& battleId, Hero* heroes, size_t& heroCount)
{
    PacketReader reader{ payload, payload + payloadLength };
    uint16_t ownCount = 0;
    uint16_t enemyCount = 0;
    if (!reader.ReadByte(offon) || !reader.ReadU16(ownCount)) return false;
    heroCount = 0;
    for (uint16_t index = 0; index < ownCount; ++index) {
        Hero parsed{};
        if (!ParseRole(reader, &parsed)) return false;
        if (heroCount < kMaxHeroes) heroes[heroCount++] = parsed;
    }
    if (!reader.ReadU16(enemyCount)) return false;
    for (uint16_t index = 0; index < enemyCount; ++index) {
        if (!ParseRole(reader, nullptr)) return false;
    }
    return reader.ReadU32(battleId) && reader.SkipUtf();
}

bool ParseRecoveryFormation(const BYTE* payload, uint32_t payloadLength, bool& allDead)
{
    PacketReader reader{ payload, payload + payloadLength };
    uint32_t ignored = 0;
    uint16_t heroCount = 0;
    if (!reader.ReadU32(ignored) || !reader.ReadU16(heroCount)) return false;
    size_t usableCount = 0;
    for (uint16_t index = 0; index < heroCount; ++index) {
        Hero hero{};
        if (!ParseRole(reader, &hero)) return false;
        if (hero.currentHp != 0 && !hero.disabled) ++usableCount;
    }
    if (!reader.ReadU32(ignored) || !reader.SkipUtf()) return false;
    allDead = heroCount != 0 && usableCount == 0;
    return true;
}

bool ParseBuffSelection(const BYTE* payload, uint32_t payloadLength, wchar_t* selectedName,
    size_t nameCapacity, uint32_t& replaceTemplateId)
{
    PacketReader reader{ payload, payload + payloadLength };
    uint16_t selectedCount = 0;
    uint16_t currentCount = 0;
    if (!reader.ReadU16(selectedCount)) return false;
    for (uint16_t index = 0; index < selectedCount; ++index) {
        if (!SkipBuff(reader, index == 0 ? selectedName : nullptr, nameCapacity, nullptr)) return false;
    }
    if (!reader.ReadU16(currentCount)) return false;
    replaceTemplateId = 0;
    for (uint16_t index = 0; index < currentCount; ++index) {
        if (!SkipBuff(reader, nullptr, 0, index == 0 ? &replaceTemplateId : nullptr)) return false;
    }
    return reader.SkipUtf();
}

void PauseForReset()
{
    InterlockedExchange(&g_battleActive, 0);
    InterlockedExchange(&g_fastBattleRetrySent, 0);
    InterlockedExchange(&g_battleStartTick, 0);
    InterlockedExchange(&g_weeklyPaused, 1);
    InterlockedExchange(&g_state, kIdle);
}

void ResetTransient()
{
    InterlockedExchange(&g_state, kIdle);
    InterlockedExchange(&g_deadlineTick, 0);
    InterlockedExchange(&g_nextTick, 0);
    InterlockedExchange(&g_pendingLog, 0);
    InterlockedExchange(&g_battleActive, 0);
    InterlockedExchange(&g_fastBattleRetrySent, 0);
    InterlockedExchange(&g_battleStartTick, 0);
    g_heroCount = 0;
    g_lastBuffLogStage[0] = L'\0';
    g_lastBuffLogText[0] = L'\0';
}

void QueueBuffLogOnce()
{
    if (wcscmp(g_lastBuffLogStage, g_stageText) == 0 &&
        wcscmp(g_lastBuffLogText, g_buffText) == 0) {
        return;
    }
    wcscpy_s(g_lastBuffLogStage, g_stageText);
    wcscpy_s(g_lastBuffLogText, g_buffText);
    InterlockedExchange(&g_pendingLog, 2);
}

void OnEnabledChanged(LONG enabled)
{
    InterlockedExchange(&g_wasEnabled, enabled ? 1 : 0);
    InterlockedExchange(&g_weeklyPaused, 0);
    InterlockedExchange(&g_dailyPauseDate, 0);
    ResetTransient();
}

void HandleRecvPacket(uint32_t opcode, const BYTE* payload, uint32_t payloadLength)
{
    if (!IsEnabled()) return;
    const uint32_t packetOpcode = opcode & 0xFFFF;
    const DWORD now = GetGameTick();
    if (packetOpcode == 0x1464 && g_battleActive != 0) {
        InterlockedExchange(&g_battleActive, 0);
        InterlockedExchange(&g_fastBattleRetrySent, 0);
        InterlockedExchange(&g_battleStartTick, 0);
        InterlockedExchange(&g_nextTick, static_cast<LONG>(now + 1000));
        InterlockedExchange(&g_state, kWaitingBattle);
        return;
    }
    if (packetOpcode == 0x52BA) {
        const LONG priorState = g_state;
        uint32_t raidType = 0;
        uint32_t currentPower = 0;
        uint32_t firstOption = 0;
        uint32_t resetSeconds = 0;
        uint16_t optionCount = 0;
        wchar_t optionBuff[128]{};
        if (!ParsePanel(payload, payloadLength, raidType, currentPower, firstOption,
                optionBuff, _countof(optionBuff), resetSeconds, optionCount)) {
            InterlockedIncrement(&g_parseError);
            return;
        }
        const DWORD boundedSeconds = resetSeconds > kMaxResetSeconds ? kMaxResetSeconds : resetSeconds;
        InterlockedExchange(&g_resetDeadlineTick, static_cast<LONG>(now + boundedSeconds * 1000));
        if (raidType != 2) {
            g_lastBuffLogStage[0] = L'\0';
            g_lastBuffLogText[0] = L'\0';
        }
        if (priorState == kWaitingPanel && g_battleActive != 0) {
            const bool sameStage = wcscmp(g_stageText, g_battleStageText) == 0;
            const bool insideRetryWindow = g_battleStartTick != 0 &&
                now - static_cast<DWORD>(g_battleStartTick) <= 120000;
            if (sameStage && insideRetryWindow &&
                InterlockedCompareExchange(&g_fastBattleRetrySent, 1, 0) == 0) {
                InterlockedExchange(&g_state, kSendFastBattleRetry);
                return;
            }
            InterlockedExchange(&g_battleActive, 0);
            InterlockedExchange(&g_battleStartTick, 0);
        }
        if (currentPower == 0) {
            SYSTEMTIME localTime{};
            GetLocalTime(&localTime);
            InterlockedExchange(&g_dailyPauseDate, DateKey(localTime));
            InterlockedExchange(&g_state, kIdle);
            return;
        }
        if (raidType == 2 && optionCount != 0 && firstOption == 0) {
            InterlockedExchange(&g_pendingLog, 3);
            InterlockedExchange(&g_state, kSendRecoverySkip);
            return;
        }
        if (optionCount == 0 || firstOption == 0) {
            PauseForReset();
            return;
        }
        InterlockedExchange(&g_selectedOption, static_cast<LONG>(firstOption));
        InterlockedExchange(&g_selectionMode, static_cast<LONG>(raidType));
        if (raidType == 2) {
            wcscpy_s(g_buffText, optionBuff[0] ? optionBuff : L"?");
        }
        InterlockedExchange(&g_state, kSendSelection);
        return;
    }
    if (packetOpcode == 0x52BC) {
        BYTE offon = 0;
        uint32_t battleId = 0;
        Hero heroes[kMaxHeroes]{};
        size_t heroCount = 0;
        if (!ParseFormation(payload, payloadLength, offon, battleId, heroes, heroCount)) {
            InterlockedIncrement(&g_parseError);
            return;
        }
        size_t usableCount = 0;
        for (size_t index = 0; index < heroCount; ++index) {
            if (heroes[index].currentHp != 0 && !heroes[index].disabled) ++usableCount;
        }
        if (usableCount == 0) {
            PauseForReset();
            return;
        }
        memcpy(g_heroes, heroes, sizeof(heroes));
        g_heroCount = heroCount;
        InterlockedExchange(&g_battleId, static_cast<LONG>(battleId));
        if (g_state == kWaitingFormationSave) {
            InterlockedExchange(&g_state, kRepeatChallenge);
        } else if (offon == 0) {
            InterlockedExchange(&g_state, kSendFormation);
        } else {
            InterlockedExchange(&g_state, kStartBattle);
        }
        return;
    }
    if (packetOpcode == 0x52BE) {
        uint32_t replaceTemplateId = 0;
        wchar_t selectedName[128]{};
        if (!ParseBuffSelection(payload, payloadLength, selectedName, _countof(selectedName), replaceTemplateId)) {
            InterlockedIncrement(&g_parseError);
            return;
        }
        if (selectedName[0]) wcscpy_s(g_buffText, selectedName);
        if (g_state == kWaitingBuffReplace) {
            InterlockedExchange(&g_nextTick, static_cast<LONG>(now + kIdlePollMs));
            InterlockedExchange(&g_state, kWaitingBattle);
        } else if (replaceTemplateId != 0) {
            InterlockedExchange(&g_replaceTemplateId, static_cast<LONG>(replaceTemplateId));
            InterlockedExchange(&g_state, kSendBuffReplace);
        } else {
            InterlockedExchange(&g_nextTick, static_cast<LONG>(now + kIdlePollMs));
            InterlockedExchange(&g_state, kWaitingBattle);
        }
        return;
    }
    if (packetOpcode == 0x52C2 && g_state == kWaitingRecovery) {
        bool allDead = false;
        if (!ParseRecoveryFormation(payload, payloadLength, allDead)) {
            InterlockedIncrement(&g_parseError);
            return;
        }
        if (allDead) {
            PauseForReset();
        } else {
            InterlockedExchange(&g_state, kSendRecoverySkip);
        }
    }
}

void DrainPendingLog()
{
    const LONG pending = InterlockedExchange(&g_pendingLog, 0);
    if (pending == 1) {
        GameLog::Write(L"\x5DD4\x5CF0\x9010\x9E7F \x6311\x6230 %s", g_stageText);
    } else if (pending == 2) {
        GameLog::Write(L"\x5DD4\x5CF0\x9010\x9E7F \x9078\x64C7 %s", g_buffText);
    } else if (pending == 3) {
        GameLog::Write(L"\x9010\x9E7F\x5DD4\x5CF0 \x7A4D\x5206\x4E0D\x8DB3");
    }
}

void QueryPanel(DWORD now)
{
    InterlockedExchange(&g_deadlineTick, static_cast<LONG>(now + kResponseTimeoutMs));
    InterlockedExchange(&g_state, kWaitingPanel);
    SendPacket(0x52B9, nullptr, 0);
}

void TickImpl()
{
    DrainPendingLog();
    if (!IsEnabled()) {
        if (InterlockedExchange(&g_wasEnabled, 0) != 0) ResetTransient();
        return;
    }
    if (InterlockedExchange(&g_wasEnabled, 1) == 0) ResetTransient();
    const DWORD now = GetGameTick();

    if (g_weeklyPaused) {
        if (!TickReached(now, g_resetDeadlineTick)) return;
        InterlockedExchange(&g_weeklyPaused, 0);
        InterlockedExchange(&g_resetDeadlineTick, 0);
    }
    SYSTEMTIME localTime{};
    GetLocalTime(&localTime);
    const LONG today = DateKey(localTime);
    if (g_dailyPauseDate == today) return;
    if (g_dailyPauseDate != 0 && g_dailyPauseDate != today) InterlockedExchange(&g_dailyPauseDate, 0);

    LONG state = g_state;
    if ((state == kWaitingPanel || state == kWaitingFormation || state == kWaitingFormationSave ||
            state == kWaitingBuffList || state == kWaitingBuffReplace ||
            state == kWaitingRecovery) && TickReached(now, g_deadlineTick)) {
        InterlockedExchange(&g_state, kIdle);
        InterlockedExchange(&g_nextTick, static_cast<LONG>(now + kIdlePollMs));
        state = kIdle;
    }
    if (state == kSendSelection) {
        const LONG mode = g_selectionMode;
        BYTE payload[4]{};
        BYTE* cursor = payload;
        WriteU32(cursor, static_cast<uint32_t>(g_selectedOption));
        if (mode == 2) {
            QueueBuffLogOnce();
        }
        InterlockedExchange(&g_deadlineTick, static_cast<LONG>(now + kResponseTimeoutMs));
        InterlockedExchange(&g_state,
            mode == 2 ? kWaitingBuffList : (mode == 3 ? kWaitingRecovery : kWaitingFormation));
        SendPacket(0x52BB, payload, sizeof(payload));
        return;
    }
    if (state == kSendRecoverySkip) {
        InterlockedExchange(&g_nextTick, static_cast<LONG>(now + kIdlePollMs));
        InterlockedExchange(&g_state, kWaitingBattle);
        SendPacket(0x52C4, nullptr, 0);
        return;
    }
    if (state == kSendFastBattleRetry) {
        InterlockedExchange(&g_nextTick, static_cast<LONG>(now + kBattlePollMs));
        InterlockedExchange(&g_state, kWaitingBattle);
        SendPacket(0x37A4, nullptr, 0);
        return;
    }
    if (state == kSendFormation) {
        BYTE payload[2 + kMaxHeroes * 4 + 4]{};
        BYTE* cursor = payload;
        WriteU16(cursor, static_cast<uint16_t>(g_heroCount));
        for (size_t index = 0; index < g_heroCount; ++index) WriteU32(cursor, g_heroes[index].heroId);
        WriteU32(cursor, static_cast<uint32_t>(g_selectedOption));
        InterlockedExchange(&g_deadlineTick, static_cast<LONG>(now + kResponseTimeoutMs));
        InterlockedExchange(&g_state, kWaitingFormationSave);
        SendPacket(0x52BD, payload, static_cast<uint32_t>(cursor - payload));
        return;
    }
    if (state == kRepeatChallenge) {
        BYTE payload[4]{};
        BYTE* cursor = payload;
        WriteU32(cursor, static_cast<uint32_t>(g_selectedOption));
        InterlockedExchange(&g_deadlineTick, static_cast<LONG>(now + kResponseTimeoutMs));
        InterlockedExchange(&g_state, kWaitingFormation);
        SendPacket(0x52BB, payload, sizeof(payload));
        return;
    }
    if (state == kStartBattle) {
        BYTE payload[4 + 1 + 2 + kMaxHeroes * 8]{};
        BYTE* cursor = payload;
        WriteU32(cursor, static_cast<uint32_t>(g_battleId));
        *cursor++ = 37;
        BYTE* countCursor = cursor;
        cursor += 2;
        uint16_t usableCount = 0;
        for (size_t index = 0; index < g_heroCount; ++index) {
            const Hero& hero = g_heroes[index];
            if (hero.currentHp == 0 || hero.disabled) continue;
            WriteU32(cursor, hero.uuidHigh);
            WriteU32(cursor, hero.uuidLow);
            ++usableCount;
        }
        WriteU16(countCursor, usableCount);
        if (usableCount == 0) {
            PauseForReset();
            return;
        }
        wcscpy_s(g_battleStageText, g_stageText);
        InterlockedExchange(&g_battleActive, 1);
        InterlockedExchange(&g_fastBattleRetrySent, 0);
        InterlockedExchange(&g_battleStartTick, static_cast<LONG>(now));
        InterlockedExchange(&g_pendingLog, 1);
        InterlockedExchange(&g_nextTick, static_cast<LONG>(now + kBattlePollMs));
        InterlockedExchange(&g_state, kWaitingBattle);
        SendPacket(0x145A, payload, static_cast<uint32_t>(cursor - payload));
        SendPacket(0x37A4, nullptr, 0);
        return;
    }
    if (state == kSendBuffReplace) {
        BYTE payload[4]{};
        BYTE* cursor = payload;
        WriteU32(cursor, static_cast<uint32_t>(g_replaceTemplateId));
        InterlockedExchange(&g_deadlineTick, static_cast<LONG>(now + kResponseTimeoutMs));
        InterlockedExchange(&g_state, kWaitingBuffReplace);
        SendPacket(0x52BF, payload, sizeof(payload));
        return;
    }
    if (state == kWaitingBattle) {
        if (TickReached(now, g_nextTick)) QueryPanel(now);
        return;
    }
    if (state == kIdle && TickReached(now, g_nextTick)) QueryPanel(now);
}

void Tick()
{
    if (InterlockedCompareExchange(&g_tickRunning, 1, 0) != 0) return;
    __try {
        TickImpl();
    } __finally {
        InterlockedExchange(&g_tickRunning, 0);
    }
}

}

namespace HuanJing
{
constexpr DWORD kIdlePollMs = 3000;
constexpr DWORD kResponseTimeoutMs = 15000;
constexpr DWORD kMoveStepDelayMs = 1200;
constexpr DWORD kFastBattleDelayMs = 2000;
constexpr DWORD kAfterBattleDelayMs = 1800;
constexpr DWORD kNoCandidateDelayMs = 30000;
constexpr size_t kMaxCityId = 252;
constexpr size_t kMaxHeroes = 16;

enum State : LONG
{
    kIdle = 0,
    kWaitingMap = 1,
    kWaitingProgressReward = 2,
    kWaitingPreview = 3,
    kWaitingCityInfo = 4,
    kWaitingMoveAck = 5,
    kMoveStepDelay = 6,
    kWaitingBattleInfo = 7,
    kFastBattleDelay = 8,
    kWaitingTreasure = 9,
    kRefreshAfterBattle = 10
};

struct PacketReader
{
    const BYTE* cursor = nullptr;
    const BYTE* end = nullptr;

    bool ReadByte(BYTE& value)
    {
        if (!cursor || cursor >= end) return false;
        value = *cursor++;
        return true;
    }

    bool ReadU16(uint16_t& value)
    {
        if (!cursor || cursor + 2 > end) return false;
        value = ReadBe16Unaligned(cursor);
        cursor += 2;
        return true;
    }

    bool ReadU32(uint32_t& value)
    {
        if (!cursor || cursor + 4 > end) return false;
        value = ReadBe32Unaligned(cursor);
        cursor += 4;
        return true;
    }

    bool Skip(size_t size)
    {
        if (!cursor || size > static_cast<size_t>(end - cursor)) return false;
        cursor += size;
        return true;
    }

    bool SkipUtf()
    {
        uint16_t length = 0;
        return ReadU16(length) && Skip(length);
    }
};

struct Candidate
{
    uint32_t cityId = 0;
    std::vector<uint16_t> path;
};

struct HeroUuid
{
    BYTE bytes[8]{};
};

volatile LONG g_tickRunning = 0;
volatile LONG g_wasEnabled = 0;
volatile LONG g_state = kIdle;
volatile LONG g_nextTick = 0;
volatile LONG g_deadlineTick = 0;
volatile LONG g_grade = 0;
volatile LONG g_currentCity = 0;
volatile LONG g_currentTimes = -1;
volatile LONG g_haveMap = 0;
volatile LONG g_haveCurrentCity = 0;
volatile LONG g_progressReward = 0;
volatile LONG g_checkingCity = 0;
volatile LONG g_moveTarget = 0;
volatile LONG g_battleId = 0;
volatile LONG g_dailyPauseDate = 0;
volatile LONG g_parseErrors = 0;
volatile LONG g_routerHits = 0;
volatile LONG g_roadLoaded = 0;
volatile LONG g_roadLoadFailed = 0;
volatile LONG g_testBypassReady = 0;
volatile LONG g_testMoveSends = 0;
volatile LONG g_testStepSends = 0;
volatile LONG g_testBattleInfoSends = 0;
volatile LONG g_testStartBattleSends = 0;
volatile LONG g_testBattleEnds = 0;
std::vector<uint16_t> g_adjacency[kMaxCityId + 1];
BYTE g_cityUnlocked[kMaxCityId + 1]{};
std::vector<Candidate> g_candidates;
std::vector<uint16_t> g_movePath;
size_t g_moveIndex = 0;
HeroUuid g_heroes[kMaxHeroes]{};
size_t g_heroCount = 0;
SRWLOCK g_lock = SRWLOCK_INIT;

bool IsEnabled()
{
    return TaskDispatchUi::g_huanJingSwitch != 0;
}

bool TickReached(DWORD now, LONG target)
{
    return target == 0 || static_cast<LONG>(now - static_cast<DWORD>(target)) >= 0;
}

LONG DateKey(const SYSTEMTIME& time)
{
    return static_cast<LONG>(time.wYear * 10000 + time.wMonth * 100 + time.wDay);
}

void WriteU16(BYTE*& cursor, uint16_t value)
{
    *cursor++ = static_cast<BYTE>((value >> 8) & 0xFF);
    *cursor++ = static_cast<BYTE>(value & 0xFF);
}

void WriteU32(BYTE*& cursor, uint32_t value)
{
    *cursor++ = static_cast<BYTE>((value >> 24) & 0xFF);
    *cursor++ = static_cast<BYTE>((value >> 16) & 0xFF);
    *cursor++ = static_cast<BYTE>((value >> 8) & 0xFF);
    *cursor++ = static_cast<BYTE>(value & 0xFF);
}

void SendPacket(uint32_t opcode, const void* payload, uint32_t payloadLength)
{
    using SendPacketFn = void(__stdcall*)(uint32_t, const void*, uint32_t);
    SendPacketFn sendPacket = reinterpret_cast<SendPacketFn>(g_mainBase + 0x4A360);
    sendPacket(opcode, payload, payloadLength);
}

void SendOneU32(uint32_t opcode, uint32_t value)
{
    BYTE payload[4]{};
    BYTE* cursor = payload;
    WriteU32(cursor, value);
    SendPacket(opcode, payload, sizeof(payload));
}

void SendTwoU32(uint32_t opcode, uint32_t first, uint32_t second)
{
    BYTE payload[8]{};
    BYTE* cursor = payload;
    WriteU32(cursor, first);
    WriteU32(cursor, second);
    SendPacket(opcode, payload, sizeof(payload));
}

void SetWaiting(State state, DWORD now, DWORD timeout = kResponseTimeoutMs)
{
    InterlockedExchange(&g_state, state);
    InterlockedExchange(&g_deadlineTick, static_cast<LONG>(now + timeout));
}

void ResetTransient()
{
    AcquireSRWLockExclusive(&g_lock);
    g_candidates.clear();
    g_movePath.clear();
    g_moveIndex = 0;
    ReleaseSRWLockExclusive(&g_lock);
    InterlockedExchange(&g_state, kIdle);
    InterlockedExchange(&g_nextTick, 0);
    InterlockedExchange(&g_deadlineTick, 0);
    InterlockedExchange(&g_grade, 0);
    InterlockedExchange(&g_currentCity, 0);
    InterlockedExchange(&g_currentTimes, -1);
    InterlockedExchange(&g_haveMap, 0);
    InterlockedExchange(&g_haveCurrentCity, 0);
    InterlockedExchange(&g_progressReward, 0);
    InterlockedExchange(&g_checkingCity, 0);
    InterlockedExchange(&g_moveTarget, 0);
    InterlockedExchange(&g_battleId, 0);
}

bool AppendRoadEdge(uint16_t first, uint16_t second)
{
    if (first == 0 || second == 0 || first > kMaxCityId || second > kMaxCityId) return false;
    g_adjacency[first].push_back(second);
    g_adjacency[second].push_back(first);
    return true;
}

bool ParseRoadBytes(const char* data, size_t size)
{
    if (!data || size == 0) return false;
    size_t edgeCount = 0;
    const char* cursor = data;
    const char* end = data + size;
    static constexpr char marker[] = "city=\"";
    while (cursor + sizeof(marker) < end) {
        const char* found = std::strstr(cursor, marker);
        if (!found || found >= end) break;
        const char* number = found + sizeof(marker) - 1;
        uint32_t first = 0;
        uint32_t second = 0;
        bool firstDigit = false;
        while (number < end && *number >= '0' && *number <= '9') {
            firstDigit = true;
            first = first * 10 + static_cast<uint32_t>(*number++ - '0');
        }
        if (!firstDigit || number >= end || *number++ != '-') {
            cursor = found + 1;
            continue;
        }
        bool secondDigit = false;
        while (number < end && *number >= '0' && *number <= '9') {
            secondDigit = true;
            second = second * 10 + static_cast<uint32_t>(*number++ - '0');
        }
        if (secondDigit && AppendRoadEdge(static_cast<uint16_t>(first), static_cast<uint16_t>(second))) {
            ++edgeCount;
        }
        cursor = number;
    }
    return edgeCount > 0;
}

bool LoadRoadGraph()
{
    if (g_roadLoaded != 0) return true;
    if (g_roadLoadFailed != 0) return false;

    wchar_t programFiles[MAX_PATH]{};
    DWORD length = GetEnvironmentVariableW(L"ProgramFiles(x86)", programFiles, _countof(programFiles));
    if (length == 0 || length >= _countof(programFiles)) {
        wcscpy_s(programFiles, L"C:\\Program Files (x86)");
    }
    std::wstring path(programFiles);
    path += L"\\\x4E00\x7D71\x5929\x4E0B\\media\\zh_TW\\config\\dreamland\\road.xml";

    HANDLE file = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        InterlockedExchange(&g_roadLoadFailed, 1);
        GameLog::Write(L"\x5E7B\x5883\xFF1A\x7121\x6CD5\x8B80\x53D6 road.xml");
        return false;
    }

    LARGE_INTEGER fileSize{};
    bool success = GetFileSizeEx(file, &fileSize) != FALSE &&
        fileSize.QuadPart > 0 && fileSize.QuadPart <= 4 * 1024 * 1024;
    std::vector<char> bytes;
    if (success) {
        bytes.resize(static_cast<size_t>(fileSize.QuadPart) + 1);
        DWORD read = 0;
        success = ReadFile(file, bytes.data(), static_cast<DWORD>(fileSize.QuadPart), &read, nullptr) != FALSE &&
            read == static_cast<DWORD>(fileSize.QuadPart);
        bytes[read] = '\0';
    }
    CloseHandle(file);

    if (success) {
        success = ParseRoadBytes(bytes.data(), static_cast<size_t>(fileSize.QuadPart));
    }
    if (!success) {
        InterlockedExchange(&g_roadLoadFailed, 1);
        GameLog::Write(L"\x5E7B\x5883\xFF1A\x9053\x8DEF\x8A2D\x5B9A\x89E3\x6790\x5931\x6557");
        return false;
    }

    InterlockedExchange(&g_roadLoaded, 1);
    return true;
}

std::vector<uint16_t> FindShortestPath(uint16_t start, uint16_t target)
{
    std::vector<uint16_t> empty;
    if (start == 0 || target == 0 || start > kMaxCityId || target > kMaxCityId) return empty;
    if (start == target) return std::vector<uint16_t>{ start };

    uint16_t previous[kMaxCityId + 1]{};
    BYTE visited[kMaxCityId + 1]{};
    uint16_t queue[kMaxCityId + 1]{};
    size_t head = 0;
    size_t tail = 0;
    queue[tail++] = start;
    visited[start] = 1;

    while (head < tail) {
        const uint16_t current = queue[head++];
        for (uint16_t next : g_adjacency[current]) {
            if (next == 0 || next > kMaxCityId || visited[next]) continue;
            if (next != target && next != start && g_cityUnlocked[next] == 0) continue;
            visited[next] = 1;
            previous[next] = current;
            if (next == target) {
                head = tail;
                break;
            }
            if (tail < _countof(queue)) queue[tail++] = next;
        }
    }
    if (!visited[target]) return empty;

    std::vector<uint16_t> path;
    for (uint16_t city = target; city != 0; city = previous[city]) {
        path.push_back(city);
        if (city == start) break;
    }
    if (path.empty() || path.back() != start) return empty;
    std::reverse(path.begin(), path.end());
    return path;
}

bool SkipBuff(PacketReader& reader)
{
    uint32_t ignored = 0;
    BYTE byte = 0;
    return reader.ReadU32(ignored) && reader.SkipUtf() && reader.ReadU32(ignored) &&
        reader.SkipUtf() && reader.ReadU32(ignored) && reader.ReadByte(byte) && reader.SkipUtf();
}

bool ParseMap(const BYTE* payload, uint32_t payloadLength, LONG& grade, LONG& currentTimes, LONG& progressReward)
{
    PacketReader reader{ payload, payload + payloadLength };
    BYTE parsedUnlocked[kMaxCityId + 1]{};
    uint16_t cityCount = 0;
    if (!reader.ReadU16(cityCount) || cityCount > 512) return false;
    for (uint16_t index = 0; index < cityCount; ++index) {
        uint16_t cityId = 0;
        BYTE initCountry = 0;
        BYTE country = 0;
        BYTE unlocked = 0;
        BYTE fighting = 0;
        uint16_t buffCount = 0;
        if (!reader.ReadU16(cityId) || !reader.ReadByte(initCountry) || !reader.ReadByte(country) ||
            !reader.ReadByte(unlocked) || !reader.ReadByte(fighting) || !reader.ReadU16(buffCount) ||
            buffCount > 256) return false;
        if (cityId > 0 && cityId <= kMaxCityId) {
            parsedUnlocked[cityId] = unlocked != 0 ? 1 : 0;
        }
        for (uint16_t buff = 0; buff < buffCount; ++buff) {
            if (!SkipBuff(reader)) return false;
        }
        if (!reader.SkipUtf()) return false;
    }

    uint16_t dreamCityCount = 0;
    if (!reader.ReadU16(dreamCityCount) || dreamCityCount > 512) return false;
    for (uint16_t index = 0; index < dreamCityCount; ++index) {
        uint16_t cityId = 0;
        uint32_t heroHead = 0;
        if (!reader.ReadU16(cityId) || !reader.ReadU32(heroHead) || !reader.SkipUtf()) return false;
    }

    uint32_t initCity = 0;
    uint32_t country = 0;
    uint32_t parsedGrade = 0;
    uint32_t parsedTimes = 0;
    uint32_t maxTimes = 0;
    uint32_t killed = 0;
    BYTE parsedProgress = 0;
    if (!reader.ReadU32(initCity) || !reader.ReadU32(country) || !reader.ReadU32(parsedGrade) ||
        !reader.SkipUtf() || !reader.ReadU32(parsedTimes) || !reader.ReadU32(maxTimes) ||
        !reader.ReadU32(killed) || !reader.ReadByte(parsedProgress) || !reader.SkipUtf()) return false;

    grade = static_cast<LONG>(parsedGrade);
    currentTimes = static_cast<LONG>(parsedTimes);
    progressReward = parsedProgress != 0 ? 1 : 0;
    AcquireSRWLockExclusive(&g_lock);
    std::memcpy(g_cityUnlocked, parsedUnlocked, sizeof(g_cityUnlocked));
    ReleaseSRWLockExclusive(&g_lock);
    return grade > 0;
}

bool ParseSyncCharacter(const BYTE* payload, uint32_t payloadLength, LONG& grade, LONG& currentCity)
{
    PacketReader reader{ payload, payload + payloadLength };
    uint32_t parsedGrade = 0;
    uint32_t ignored = 0;
    uint32_t parsedCity = 0;
    if (!reader.ReadU32(parsedGrade) || !reader.Skip(8) || !reader.ReadU32(ignored) ||
        !reader.ReadU32(parsedCity) || !reader.SkipUtf()) return false;
    grade = static_cast<LONG>(parsedGrade);
    currentCity = static_cast<LONG>(parsedCity);
    return grade > 0 && currentCity > 0;
}

bool ParseProgressReward(const BYTE* payload, uint32_t payloadLength, uint32_t& grade, uint32_t& claimCity)
{
    PacketReader reader{ payload, payload + payloadLength };
    uint16_t rewardCount = 0;
    claimCity = 0;
    if (!reader.ReadU32(grade) || !reader.ReadU16(rewardCount) || rewardCount > 256) return false;
    for (uint16_t index = 0; index < rewardCount; ++index) {
        uint32_t cityNum = 0;
        uint32_t rewardState = 0;
        uint16_t bonusCount = 0;
        if (!reader.ReadU32(cityNum) || !reader.ReadU32(rewardState) ||
            !reader.ReadU16(bonusCount) || bonusCount > 256) return false;
        for (uint16_t bonus = 0; bonus < bonusCount; ++bonus) {
            uint16_t type = 0;
            uint32_t value = 0;
            if (!reader.ReadU16(type) || !reader.ReadU32(value) || !reader.SkipUtf()) return false;
        }
        if (!reader.SkipUtf()) return false;
        if (claimCity == 0 && rewardState == 1) claimCity = cityNum;
    }
    return reader.SkipUtf();
}

bool ParsePreview(const BYTE* payload, uint32_t payloadLength, uint32_t& grade, std::vector<uint32_t>& cityIds)
{
    PacketReader reader{ payload, payload + payloadLength };
    uint16_t count = 0;
    if (!reader.ReadU32(grade) || !reader.ReadU16(count) || count > 512) return false;
    cityIds.clear();
    for (uint16_t index = 0; index < count; ++index) {
        uint32_t cityId = 0;
        uint32_t cityState = 0;
        uint32_t treasureState = 0;
        if (!reader.ReadU32(cityId) || !reader.SkipUtf() || !reader.SkipUtf() ||
            !reader.ReadU32(cityState) || !reader.ReadU32(treasureState) || !reader.SkipUtf()) return false;
        if (cityState == 0) cityIds.push_back(cityId);
    }
    return reader.SkipUtf();
}

bool ParseCityInfo(const BYTE* payload, uint32_t payloadLength, bool& unlocked, BYTE& state)
{
    PacketReader reader{ payload, payload + payloadLength };
    uint32_t ignored = 0;
    uint16_t count = 0;
    unlocked = true;
    state = 0xFF;
    if (!reader.ReadU32(ignored) || !reader.SkipUtf() || !reader.ReadU32(ignored) ||
        !reader.SkipUtf() || !reader.ReadU16(count) || count > 256) return false;
    for (uint16_t index = 0; index < count; ++index) {
        if (!reader.SkipUtf()) return false;
    }
    if (!reader.ReadU16(count) || count > 256) return false;
    for (uint16_t index = 0; index < count; ++index) {
        BYTE alreadyHave = 0;
        if (!reader.ReadU32(ignored) || !reader.SkipUtf() || !reader.ReadByte(alreadyHave) ||
            !reader.SkipUtf()) return false;
        if (alreadyHave == 0) unlocked = false;
    }
    if (!reader.ReadU16(count) || count > 256) return false;
    for (uint16_t index = 0; index < count; ++index) {
        uint16_t type = 0;
        if (!reader.ReadU16(type) || !reader.ReadU32(ignored) || !reader.SkipUtf()) return false;
    }
    return reader.ReadByte(state) && reader.ReadU32(ignored) && reader.SkipUtf() && reader.SkipUtf();
}

bool ParseBattleInfo(const BYTE* payload, uint32_t payloadLength, uint32_t& battleId,
    BYTE& battleType, uint16_t& currentTimes)
{
    PacketReader reader{ payload, payload + payloadLength };
    uint16_t roleCount = 0;
    if (!reader.ReadU16(roleCount) || roleCount > 256) return false;
    for (uint16_t role = 0; role < roleCount; ++role) {
        uint32_t ignored = 0;
        uint16_t ignored16 = 0;
        uint16_t tacticCount = 0;
        if (!reader.SkipUtf() || !reader.ReadU32(ignored) || !reader.ReadU32(ignored) ||
            !reader.ReadU32(ignored) || !reader.ReadU32(ignored) || !reader.ReadU16(ignored16) ||
            !reader.SkipUtf() || !reader.ReadU16(tacticCount) || tacticCount > 256) return false;
        for (uint16_t tactic = 0; tactic < tacticCount; ++tactic) {
            if (!reader.ReadU32(ignored) || !reader.SkipUtf()) return false;
        }
        if (!reader.ReadU32(ignored) || !reader.SkipUtf()) return false;
    }
    uint32_t mapId = 0;
    uint32_t ignored = 0;
    BYTE packetBattleType = 0;
    uint16_t terrain = 0;
    if (!reader.ReadU32(battleId) || !reader.ReadU32(mapId) ||
        !reader.ReadByte(packetBattleType) || !reader.SkipUtf() || !reader.ReadU16(terrain) ||
        !reader.ReadU32(ignored) || !reader.ReadU32(ignored) || !reader.SkipUtf() ||
        !reader.SkipUtf()) return false;
    battleType = packetBattleType;
    currentTimes = static_cast<uint16_t>(g_currentTimes > 0 ? g_currentTimes : 0);
    return true;
}

bool ParseHero(PacketReader& reader, size_t index, HeroUuid& output, bool& usable)
{
    const BYTE* uuid = reader.cursor;
    if (!reader.Skip(8) || !reader.SkipUtf() || !reader.SkipUtf() || !reader.Skip(0x1A)) return false;
    BYTE heroState = 0;
    uint16_t roleType = 0;
    BYTE bonusType = 0;
    uint32_t ignored = 0;
    uint16_t tacticCount = 0;
    if (!reader.ReadByte(heroState) || !reader.ReadU16(roleType) || !reader.ReadByte(bonusType) ||
        !reader.SkipUtf() || !reader.ReadU32(ignored) || !reader.ReadU16(tacticCount) ||
        tacticCount > 256) return false;
    for (uint16_t tactic = 0; tactic < tacticCount; ++tactic) {
        if (!reader.ReadU32(ignored) || !reader.SkipUtf()) return false;
    }
    if (!reader.SkipUtf()) return false;
    std::memcpy(output.bytes, uuid, sizeof(output.bytes));
    usable = index < 5 && heroState == 1 && roleType != 4;
    return true;
}

bool ParseHeroList(PacketReader& reader, bool store)
{
    uint16_t count = 0;
    if (!reader.ReadU16(count) || count > 256) return false;
    for (uint16_t index = 0; index < count; ++index) {
        HeroUuid uuid{};
        bool usable = false;
        if (!ParseHero(reader, index, uuid, usable)) return false;
        if (store && usable && g_heroCount < kMaxHeroes) {
            g_heroes[g_heroCount++] = uuid;
        }
    }
    return true;
}

void HandleHeroList(const BYTE* payload, uint32_t payloadLength)
{
    if (!payload || payloadLength < 0x12) return;
    PacketReader reader{ payload + 0x10, payload + payloadLength };
    HeroUuid parsed[kMaxHeroes]{};
    HeroUuid old[kMaxHeroes]{};
    std::memcpy(old, g_heroes, sizeof(old));
    const size_t oldCount = g_heroCount;
    g_heroCount = 0;
    if (!ParseHeroList(reader, true) || !ParseHeroList(reader, false)) {
        std::memcpy(g_heroes, old, sizeof(old));
        g_heroCount = oldCount;
        InterlockedIncrement(&g_parseErrors);
    }
}

void SendEnterMap(uint32_t grade, DWORD now)
{
    SendOneU32(0x49D5, grade);
    SetWaiting(kWaitingMap, now);
}

void SendProgressQuery(DWORD now)
{
    SendOneU32(0x49E0, static_cast<uint32_t>(g_grade));
    SetWaiting(kWaitingProgressReward, now);
}

void SendPreview(DWORD now)
{
    if (g_grade <= 0 || g_currentCity <= 0) {
        SendEnterMap(0, now);
        return;
    }
    SendOneU32(0x49E2, static_cast<uint32_t>(g_grade));
    SetWaiting(kWaitingPreview, now);
}

void SendNextCandidate(DWORD now)
{
    Candidate candidate{};
    bool hasCandidate = false;
    AcquireSRWLockExclusive(&g_lock);
    if (!g_candidates.empty()) {
        candidate = g_candidates.front();
        g_candidates.erase(g_candidates.begin());
        hasCandidate = true;
    }
    ReleaseSRWLockExclusive(&g_lock);
    if (!hasCandidate) {
        InterlockedExchange(&g_state, kIdle);
        InterlockedExchange(&g_nextTick, static_cast<LONG>(now + kNoCandidateDelayMs));
        GameLog::Write(L"\x5E7B\x5883\xFF1A\x6C92\x6709\x53EF\x79FB\x52D5\x7684\x672A\x4F54\x9818\x57CE\x6C60");
        return;
    }
    InterlockedExchange(&g_checkingCity, static_cast<LONG>(candidate.cityId));
    AcquireSRWLockExclusive(&g_lock);
    g_movePath = candidate.path;
    g_moveIndex = 0;
    ReleaseSRWLockExclusive(&g_lock);
    SendTwoU32(0x49DA, static_cast<uint32_t>(g_grade), candidate.cityId);
    SetWaiting(kWaitingCityInfo, now);
}

void SendMoveRequest(DWORD now)
{
    std::vector<uint16_t> path;
    AcquireSRWLockShared(&g_lock);
    path = g_movePath;
    ReleaseSRWLockShared(&g_lock);
    if (path.size() < 2 || path.size() > kMaxCityId) {
        SendNextCandidate(now);
        return;
    }

    std::vector<BYTE> payload(8 + path.size() * 2);
    BYTE* cursor = payload.data();
    WriteU32(cursor, static_cast<uint32_t>(g_grade));
    WriteU16(cursor, path.back());
    WriteU16(cursor, static_cast<uint16_t>(path.size()));
    for (uint16_t city : path) WriteU16(cursor, city);
    InterlockedIncrement(&g_testMoveSends);
    SendPacket(0x49D2, payload.data(), static_cast<uint32_t>(cursor - payload.data()));

    AcquireSRWLockExclusive(&g_lock);
    g_moveIndex = 1;
    const uint16_t firstStep = g_movePath[g_moveIndex];
    ReleaseSRWLockExclusive(&g_lock);
    BYTE stepPayload[6]{};
    cursor = stepPayload;
    WriteU32(cursor, static_cast<uint32_t>(g_grade));
    WriteU16(cursor, firstStep);
    InterlockedIncrement(&g_testStepSends);
    SendPacket(0x49D3, stepPayload, sizeof(stepPayload));
    InterlockedExchange(&g_moveTarget, path.back());
    SetWaiting(kWaitingMoveAck, now);
    GameLog::Write(L"\x5E7B\x5883\xFF1A\x79FB\x52D5\x81F3\x57CE\x6C60 %u",
        static_cast<unsigned>(path.back()));
}

void SendNextMoveStep(DWORD now)
{
    uint16_t nextCity = 0;
    bool finalReached = false;
    AcquireSRWLockExclusive(&g_lock);
    if (g_moveIndex + 1 < g_movePath.size()) {
        ++g_moveIndex;
        nextCity = g_movePath[g_moveIndex];
    } else {
        finalReached = true;
    }
    ReleaseSRWLockExclusive(&g_lock);

    if (finalReached) {
        InterlockedIncrement(&g_testBattleInfoSends);
        SendTwoU32(0x49DC, static_cast<uint32_t>(g_grade), static_cast<uint32_t>(g_moveTarget));
        SetWaiting(kWaitingBattleInfo, now);
        return;
    }

    BYTE payload[6]{};
    BYTE* cursor = payload;
    WriteU32(cursor, static_cast<uint32_t>(g_grade));
    WriteU16(cursor, nextCity);
    InterlockedIncrement(&g_testStepSends);
    SendPacket(0x49D3, payload, sizeof(payload));
    SetWaiting(kWaitingMoveAck, now);
}

void SendStartBattle(uint32_t battleId, DWORD now)
{
    HeroUuid heroes[kMaxHeroes]{};
    const size_t heroCount = AlBattle::CopyReadyHeroUuids(
        reinterpret_cast<BYTE*>(heroes), kMaxHeroes);
    if (heroCount == 0) {
        InterlockedExchange(&g_state, kIdle);
        InterlockedExchange(&g_nextTick, static_cast<LONG>(now + kIdlePollMs));
        GameLog::Write(L"\x5E7B\x5883\xFF1A\x5C1A\x7121\x53EF\x4E0A\x9663\x6B66\x5C07");
        return;
    }
    BYTE payload[4 + 1 + 2 + kMaxHeroes * 8]{};
    BYTE* cursor = payload;
    WriteU32(cursor, battleId);
    *cursor++ = 33;
    WriteU16(cursor, static_cast<uint16_t>(heroCount));
    for (size_t index = 0; index < heroCount; ++index) {
        std::memcpy(cursor, heroes[index].bytes, sizeof(heroes[index].bytes));
        cursor += sizeof(heroes[index].bytes);
    }
    InterlockedIncrement(&g_testStartBattleSends);
    SendPacket(0x145A, payload, static_cast<uint32_t>(cursor - payload));
    InterlockedExchange(&g_battleId, static_cast<LONG>(battleId));
    InterlockedExchange(&g_state, kFastBattleDelay);
    InterlockedExchange(&g_nextTick, static_cast<LONG>(now + kFastBattleDelayMs));
    InterlockedExchange(&g_deadlineTick, static_cast<LONG>(now + kResponseTimeoutMs));
    GameLog::Write(L"\x5E7B\x5883\xFF1A\x958B\x59CB\x6230\x9B25");
}

void HandleMap(const BYTE* payload, uint32_t payloadLength, DWORD now)
{
    LONG grade = 0;
    LONG currentTimes = 0;
    LONG progress = 0;
    if (!ParseMap(payload, payloadLength, grade, currentTimes, progress)) {
        InterlockedIncrement(&g_parseErrors);
        return;
    }
    InterlockedExchange(&g_grade, grade);
    InterlockedExchange(&g_currentTimes, currentTimes);
    InterlockedExchange(&g_progressReward, progress);
    InterlockedExchange(&g_haveMap, 1);

    if (currentTimes <= 0) {
        SYSTEMTIME local{};
        GetLocalTime(&local);
        InterlockedExchange(&g_dailyPauseDate, DateKey(local));
        ResetTransient();
        GameLog::Write(L"\x5E7B\x5883\xFF1A\x6311\x6230\x6B21\x6578\x5DF2\x7528\x5B8C\xFF0C\x9694\x65E5 00:01 \x518D\x57F7\x884C");
        return;
    }
    if (g_state != kWaitingMap) {
        return;
    }
    if (progress != 0) {
        SendProgressQuery(now);
        return;
    }
    if (g_haveCurrentCity != 0) SendPreview(now);
}

void HandleSync(const BYTE* payload, uint32_t payloadLength, DWORD now)
{
    LONG grade = 0;
    LONG city = 0;
    if (!ParseSyncCharacter(payload, payloadLength, grade, city)) {
        InterlockedIncrement(&g_parseErrors);
        return;
    }
    InterlockedExchange(&g_grade, grade);
    InterlockedExchange(&g_currentCity, city);
    InterlockedExchange(&g_haveCurrentCity, 1);
    if (g_state == kWaitingMap && g_haveMap != 0 &&
        g_currentTimes > 0 && g_progressReward == 0) SendPreview(now);
}

void HandleProgress(const BYTE* payload, uint32_t payloadLength, DWORD now)
{
    if (g_state != kWaitingProgressReward) return;
    uint32_t grade = 0;
    uint32_t claimCity = 0;
    if (!ParseProgressReward(payload, payloadLength, grade, claimCity)) {
        InterlockedIncrement(&g_parseErrors);
        return;
    }
    if (claimCity != 0) {
        SendTwoU32(0x49E5, grade, claimCity);
        InterlockedExchange(&g_state, kWaitingProgressReward);
        InterlockedExchange(&g_nextTick, static_cast<LONG>(now + 700));
        InterlockedExchange(&g_deadlineTick, static_cast<LONG>(now + kResponseTimeoutMs));
        GameLog::Write(L"\x5E7B\x5883\xFF1A\x9818\x53D6\x7D2F\x7A4D\x901A\x95DC\x734E\x52F5 %u",
            static_cast<unsigned>(claimCity));
        return;
    }
    SendPreview(now);
}

void HandlePreview(const BYTE* payload, uint32_t payloadLength, DWORD now)
{
    if (g_state != kWaitingPreview) return;
    uint32_t grade = 0;
    std::vector<uint32_t> cityIds;
    if (!ParsePreview(payload, payloadLength, grade, cityIds) || !LoadRoadGraph()) {
        InterlockedIncrement(&g_parseErrors);
        return;
    }
    std::vector<Candidate> candidates;
    const uint16_t current = static_cast<uint16_t>(g_currentCity);
    for (uint32_t cityId : cityIds) {
        if (cityId == static_cast<uint32_t>(current) || cityId > kMaxCityId) continue;
        Candidate candidate{};
        candidate.cityId = cityId;
        candidate.path = FindShortestPath(current, static_cast<uint16_t>(cityId));
        if (candidate.path.size() > 1) candidates.push_back(candidate);
    }
    std::sort(candidates.begin(), candidates.end(), [](const Candidate& first, const Candidate& second) {
        if (first.path.size() != second.path.size()) return first.path.size() < second.path.size();
        return first.cityId < second.cityId;
    });
    AcquireSRWLockExclusive(&g_lock);
    g_candidates.swap(candidates);
    ReleaseSRWLockExclusive(&g_lock);
    SendNextCandidate(now);
}

void HandleCityInfo(const BYTE* payload, uint32_t payloadLength, DWORD now)
{
    if (g_state != kWaitingCityInfo) return;
    bool unlocked = false;
    BYTE state = 0xFF;
    if (!ParseCityInfo(payload, payloadLength, unlocked, state)) {
        InterlockedIncrement(&g_parseErrors);
        return;
    }
    if (state == 0 && unlocked) {
        SendMoveRequest(now);
    } else {
        SendNextCandidate(now);
    }
}

void HandleMoveAck(const BYTE* payload, uint32_t payloadLength, DWORD now)
{
    if (g_state != kWaitingMoveAck) return;
    PacketReader reader{ payload, payload + payloadLength };
    uint32_t grade = 0;
    uint16_t fromCity = 0;
    uint16_t toCity = 0;
    if (!reader.ReadU32(grade) || !reader.ReadU16(fromCity) || !reader.ReadU16(toCity) ||
        !reader.SkipUtf()) {
        InterlockedIncrement(&g_parseErrors);
        return;
    }
    InterlockedExchange(&g_currentCity, toCity);
    InterlockedExchange(&g_state, kMoveStepDelay);
    InterlockedExchange(&g_nextTick, static_cast<LONG>(now + kMoveStepDelayMs));
    InterlockedExchange(&g_deadlineTick, static_cast<LONG>(now + kResponseTimeoutMs));
}

void HandleBattleInfo(const BYTE* payload, uint32_t payloadLength, DWORD now)
{
    if (g_state != kWaitingBattleInfo) return;
    uint32_t battleId = 0;
    BYTE battleType = 0;
    uint16_t currentTimes = 0;
    if (!ParseBattleInfo(payload, payloadLength, battleId, battleType, currentTimes)) {
        InterlockedIncrement(&g_parseErrors);
        return;
    }
    if (battleType != 33 || battleId == 0 || currentTimes == 0) {
        SendEnterMap(static_cast<uint32_t>(g_grade), now);
        return;
    }
    SendStartBattle(battleId, now);
}

void HandleTreasure(const BYTE* payload, uint32_t payloadLength, DWORD now)
{
    PacketReader reader{ payload, payload + payloadLength };
    uint32_t grade = 0;
    uint16_t count = 0;
    if (!reader.ReadU32(grade) || !reader.ReadU16(count) || count > 256) {
        InterlockedIncrement(&g_parseErrors);
        return;
    }
    for (uint16_t index = 0; index < count; ++index) {
        uint32_t cityId = 0;
        if (!reader.ReadU32(cityId)) {
            InterlockedIncrement(&g_parseErrors);
            return;
        }
        SendTwoU32(0x49DF, grade, cityId);
    }
    if (!reader.SkipUtf()) {
        InterlockedIncrement(&g_parseErrors);
        return;
    }
    if (g_state == kWaitingTreasure) {
        InterlockedExchange(&g_state, kRefreshAfterBattle);
        InterlockedExchange(&g_nextTick, static_cast<LONG>(now + kAfterBattleDelayMs));
        InterlockedExchange(&g_deadlineTick, static_cast<LONG>(now + kResponseTimeoutMs));
    }
}

void HandleBattleEnd(DWORD now)
{
    if (g_state != kWaitingTreasure && g_state != kFastBattleDelay) {
        return;
    }
    InterlockedIncrement(&g_testBattleEnds);
    InterlockedExchange(&g_state, kRefreshAfterBattle);
    InterlockedExchange(&g_nextTick, static_cast<LONG>(now + kAfterBattleDelayMs));
    InterlockedExchange(&g_deadlineTick, static_cast<LONG>(now + kResponseTimeoutMs));
}

void HandleRecvPacket(uint32_t opcode, const BYTE* payload, uint32_t payloadLength)
{
    const uint32_t packetOpcode = opcode & 0xFFFF;
    if (!IsEnabled()) return;
    const DWORD now = GetGameTick();
    switch (packetOpcode) {
        case 0x49D9:
            InterlockedIncrement(&g_routerHits);
            HandleSync(payload, payloadLength, now);
            break;
        case 0x49D6:
            InterlockedIncrement(&g_routerHits);
            HandleMap(payload, payloadLength, now);
            break;
        case 0x49E1:
            InterlockedIncrement(&g_routerHits);
            HandleProgress(payload, payloadLength, now);
            break;
        case 0x49E3:
            InterlockedIncrement(&g_routerHits);
            HandlePreview(payload, payloadLength, now);
            break;
        case 0x49DB:
            InterlockedIncrement(&g_routerHits);
            HandleCityInfo(payload, payloadLength, now);
            break;
        case 0x49D4:
            InterlockedIncrement(&g_routerHits);
            HandleMoveAck(payload, payloadLength, now);
            break;
        case 0x1468:
            HandleBattleInfo(payload, payloadLength, now);
            break;
        case 0x1464:
            HandleBattleEnd(now);
            break;
        case 0x49D7:
            InterlockedIncrement(&g_routerHits);
            HandleTreasure(payload, payloadLength, now);
            break;
        default:
            break;
    }
}

void OnEnabledChanged(LONG enabled)
{
    if (enabled == 0) {
        InterlockedExchange(&g_wasEnabled, 0);
        ResetTransient();
    } else if (InterlockedExchange(&g_wasEnabled, 1) == 0) {
        ResetTransient();
    }
}

void TickImpl()
{
    if (!IsEnabled()) {
        if (InterlockedExchange(&g_wasEnabled, 0) != 0) ResetTransient();
        return;
    }
    if (InterlockedExchange(&g_wasEnabled, 1) == 0) ResetTransient();
    if (g_testBypassReady == 0 && !IsNativeEntryReady()) return;

    SYSTEMTIME local{};
    GetLocalTime(&local);
    const LONG pauseDate = g_dailyPauseDate;
    if (pauseDate != 0) {
        const LONG today = DateKey(local);
        if (today == pauseDate || (local.wHour == 0 && local.wMinute < 1)) return;
        InterlockedExchange(&g_dailyPauseDate, 0);
    }

    const DWORD now = GetGameTick();
    const LONG state = g_state;
    if (state != kIdle && TickReached(now, g_deadlineTick)) {
        ResetTransient();
        InterlockedExchange(&g_nextTick, static_cast<LONG>(now + kIdlePollMs));
        return;
    }
    if (!TickReached(now, g_nextTick)) return;

    switch (state) {
        case kIdle:
            if (!LoadRoadGraph()) {
                InterlockedExchange(&g_nextTick, static_cast<LONG>(now + kNoCandidateDelayMs));
                return;
            }
            SendEnterMap(0, now);
            break;
        case kWaitingProgressReward:
            SendProgressQuery(now);
            break;
        case kMoveStepDelay:
            SendNextMoveStep(now);
            break;
        case kFastBattleDelay:
            SendPacket(0x37A4, nullptr, 0);
            SetWaiting(kWaitingTreasure, now, 30000);
            break;
        case kRefreshAfterBattle:
            SendEnterMap(static_cast<uint32_t>(g_grade), now);
            break;
        default:
            break;
    }
}

void Tick()
{
    if (InterlockedCompareExchange(&g_tickRunning, 1, 0) != 0) return;
    __try {
        TickImpl();
    } __finally {
        InterlockedExchange(&g_tickRunning, 0);
    }
}

}

namespace BattleToken
{
void Tick();
void HandleRecvPacket(uint32_t opcode, const BYTE* payload, uint32_t payloadLength);
void OnEnabledChanged(LONG enabled);
}

namespace ZhaoXianNaKe
{
void Tick();
void HandleRecvPacket(uint32_t opcode, const BYTE* payload, uint32_t payloadLength);
void OnEnabledChanged(LONG enabled);
}

namespace ActivityLogin
{
void Tick();
void HandleRecvPacket(uint32_t opcode, const BYTE* payload, uint32_t payloadLength);
bool BuildDailyGuardCode(uintptr_t base, CodeBuffer& code);
}

namespace NativeLogHook
{
bool BuildCode(uintptr_t base, CodeBuffer& code);
}

namespace TeamBattleReward
{
void Tick();
void HandleRecvPacket(uint32_t opcode, const BYTE* payload, uint32_t payloadLength);
void OnEnabledChanged(LONG enabled);
}

namespace DianFengZhuLu
{
void Tick();
void HandleRecvPacket(uint32_t opcode, const BYTE* payload, uint32_t payloadLength);
void OnEnabledChanged(LONG enabled);
}

namespace HuanJing
{
void Tick();
void HandleRecvPacket(uint32_t opcode, const BYTE* payload, uint32_t payloadLength);
void OnEnabledChanged(LONG enabled);
}

namespace TaskDispatchUi
{
constexpr UINT kCheckboxId = 0x0439;
constexpr UINT kBattleTokenCheckboxId = 0x7B05;
constexpr UINT kZhaoXianNaKeCheckboxId = 0x7B06;
constexpr UINT kTeamBattleRewardCheckboxId = 0x7B07;
constexpr UINT kDianFengZhuLuCheckboxId = 0x7B08;
constexpr UINT kHuanJingCheckboxId = 0x7B09;
constexpr UINT kPrivateMessage = 0x8439;
constexpr UINT kTimerId = 0x843A;
const wchar_t kBattleTokenConfigSection[] = L"MAIN";
const wchar_t kTaskDispatchConfigKey[] = L"bTaskDispatch";
const wchar_t kBattleTokenConfigKey[] = L"bBattleToken";
const wchar_t kZhaoXianNaKeConfigKey[] = L"bZhaoXianNaKe";
const wchar_t kTeamBattleRewardConfigKey[] = L"bTeamBattleReward";
const wchar_t kDianFengZhuLuConfigKey[] = L"bDianFengZhuLu";
const wchar_t kHuanJingConfigKey[] = L"bHuanJing";

volatile LONG g_started = 0;
volatile LONG g_switch = 0;
volatile LONG g_battleTokenSwitch = 1;
volatile LONG g_zhaoXianNaKeSwitch = 1;
volatile LONG g_teamBattleRewardSwitch = 1;
volatile LONG g_dianFengZhuLuSwitch = 1;
volatile LONG g_huanJingSwitch = 1;
volatile LONG g_lastValue = 0;
volatile LONG g_hitCount = 0;
volatile LONG g_status = 0;
volatile LONG g_taskDispatchKeyReady = 0;
volatile LONG g_battleTokenKeyReady = 0;
volatile LONG g_zhaoXianNaKeKeyReady = 0;
volatile LONG g_teamBattleRewardKeyReady = 0;
volatile LONG g_dianFengZhuLuKeyReady = 0;
volatile LONG g_huanJingKeyReady = 0;
volatile LONG g_taskDispatchDirty = 0;
volatile LONG g_battleTokenDirty = 0;
volatile LONG g_zhaoXianNaKeDirty = 0;
volatile LONG g_teamBattleRewardDirty = 0;
volatile LONG g_dianFengZhuLuDirty = 0;
volatile LONG g_huanJingDirty = 0;
HWND g_settingsHwnd = nullptr;
HWND g_parentHwnd = nullptr;
HWND g_checkboxHwnd = nullptr;
HWND g_battleTokenCheckboxHwnd = nullptr;
HWND g_zhaoXianNaKeCheckboxHwnd = nullptr;
HWND g_teamBattleRewardCheckboxHwnd = nullptr;
HWND g_dianFengZhuLuCheckboxHwnd = nullptr;
HWND g_huanJingCheckboxHwnd = nullptr;
HWND g_weeklyHwnd = nullptr;
HWND g_dailyHwnd = nullptr;
WNDPROC g_oldProc = nullptr;
WNDPROC g_settingsOldProc = nullptr;
int g_x = 0;
int g_y = 0;
int g_w = 0;
int g_h = 0;

const wchar_t kSettingsTitle[] = L"\x8A2D\x7F6E";
const wchar_t kCheckboxText[] = L"\x4EFB\x52D9\x6D3E\x9063";
const wchar_t kBattleTokenCheckboxText[] = L"\x6230\x4EE4";
const wchar_t kZhaoXianNaKeCheckboxText[] = L"\x62DB\x52DF\x8CE2\x5BA2";
const wchar_t kTeamBattleRewardCheckboxText[] = L"\x7D44\x968A\x6230";
const wchar_t kDianFengZhuLuCheckboxText[] = L"\x5DD4\x5CF0\x9010\x9E7F";
const wchar_t kHuanJingCheckboxText[] = L"\x5E7B\x5883";
const wchar_t kActivityLoginCheckboxText[] = L"\x6D3B\x52D5\x767B\x5165";

void Start();
}

namespace LegionDungeon
{
constexpr DWORD kActionSwitchOffset = 0x2302C0;
constexpr DWORD kIdleIntervalMs = 0x0BB8;
constexpr DWORD kWaitTimeoutMs = 0x2710;
constexpr DWORD kBattleResultTimeoutMs = 0x7530;
constexpr DWORD kMaxClosedWaitSeconds = 7 * 24 * 60 * 60;
constexpr size_t kDungeonCount = 9;
constexpr size_t kMaxTeams = 10;
constexpr size_t kOrderMemberMaxBytes = 128;
constexpr LONG kOrderRetryMax = 3;
constexpr LONG kCreateTeamMissMax = 6;
constexpr DWORD kCreateGateLeaseMs = 8000;
constexpr DWORD kCreateGateMagic = 0x4C444731;
constexpr DWORD kSoloPanelQueryDelayMs = 3000;
constexpr DWORD kSoloPanelQueryIntervalMs = 3000;
constexpr DWORD kSoloResumeWindowMs = 120000;

struct SharedCreateGate
{
    DWORD magic;
    DWORD ownerProcessId;
    DWORD dungeonId;
    DWORD expiresAt;
};

volatile LONG g_state = 0;
volatile LONG g_currentId = 0;
volatile LONG g_verifyId = 0;
volatile LONG g_verifyIndex = -1;
volatile LONG g_verifyMode = 0;
volatile LONG g_verifyFailedMask = 0;
volatile LONG g_waitBattleResult = 0;
volatile LONG g_armyBattleConfirmed = 0;
volatile LONG g_expectedWinValue = 0;
volatile LONG g_soloVerifyBlocked = 0;
volatile LONG g_maxSoloIndex = -1;
volatile LONG g_pendingId = 0;
volatile LONG g_teamId = 0;
volatile LONG g_logIndex = 0;
volatile LONG g_timeBlocked = 0;
volatile LONG g_timeWaitPassed = 0;
volatile LONG g_timeOpenLogged = 0;
volatile LONG g_activityState = 0;
volatile LONG g_leftTime = 0;
volatile LONG g_helpTrackId = 0;
volatile LONG g_helpTrackCount = 0;
volatile LONG g_nextTick = 0;
volatile LONG g_waitTick = 0;
volatile LONG g_teamCount = 0;
volatile LONG g_peopleCount = 0;
volatile LONG g_payloadTeamCount = 0;
volatile LONG g_teamOrderSent = 0;
volatile LONG g_teamOrderRetries = 0;
volatile LONG g_createTeamMissCount = 0;
volatile LONG g_createFinalCheck = 0;
volatile LONG g_createGateOwned = 0;
volatile LONG g_restoredTeamId = 0;
volatile LONG g_unlimitPassedOnce = 0;
volatile LONG g_battleMode = 0;
volatile LONG g_soloBattleDungeonId = 0;
volatile LONG g_soloFastRetrySent = 0;
volatile LONG g_soloBattleStartTick = 0;
volatile LONG g_soloPanelNextTick = 0;
volatile LONG g_unlimitCount = 0;
uint32_t g_unlimitId = 0;
uint32_t g_teamIds[kMaxTeams]{};
uint16_t g_teamDungeonIds[kMaxTeams]{};
BYTE g_teamPeople[kMaxTeams]{};
HANDLE g_createGateMutex = nullptr;
HANDLE g_createGateMapping = nullptr;
SharedCreateGate* g_sharedCreateGate = nullptr;
uint32_t g_bufZero4 = 0;
BYTE g_bufId4[4]{};
BYTE g_bufId6[6]{};
BYTE g_bufTeam4[4]{};
BYTE g_bufOrder[256]{};
BYTE g_orderExpected[3][kOrderMemberMaxBytes]{};
uint32_t g_orderExpectedLens[3]{};

bool BuildTickCode(uintptr_t base, CodeBuffer& code);
void HandleRecvPacket(uint32_t opcode, const BYTE* payload, uint32_t payloadLength);
}

namespace AlBattle
{
constexpr size_t kMaxHeroes = 32;

struct HeroEntry
{
    uint32_t uuid0 = 0;
    uint32_t uuid4 = 0;
    uint32_t ready = 0;
    uint32_t tick = 0;
};

volatile LONG g_heroCount = 0;
HeroEntry g_heroTable[kMaxHeroes]{};
volatile LONG g_leftCount = 0;
volatile LONG g_rightCount = 0;
volatile LONG g_location = 0;
volatile LONG g_rushRatio = 0;
volatile LONG g_lastCity = 0;
volatile LONG g_cityAttackers = 0;
volatile LONG g_cityDefenders = 0;
volatile LONG g_parseError = 0;
volatile LONG g_marchFree = -1;
volatile LONG g_marchFreeKnown = 0;
void HandleRecvPacket(uint32_t opcode, const BYTE* payload, uint32_t payloadLength);
bool HasRushAdvantage();
}

namespace WorldCityBattle
{
void HandleRecvPacket(uint32_t opcode, const BYTE* payload, uint32_t payloadLength);
bool IsFighting(uint32_t cityId, bool& known);
}

namespace AutoLureDash
{
constexpr bool kEnableDashDiagLog = false;
constexpr DWORD kPhaseGapMs = 100;
constexpr DWORD kFallbackCheckMs = 500;
constexpr DWORD kIdleScanMs = 1000;
constexpr DWORD kIndependentScanMs = 500;
constexpr UINT_PTR kIndependentTimerId = 0x87D5;
constexpr int32_t kMaxTargetNodes = 4096;
constexpr size_t kMaxGroups = 8;
constexpr size_t kMaxPayloadsPerGroup = 5;
constexpr size_t kGroupStride = 0x80;
constexpr size_t kEntryArrayOffset = 0x40;

volatile LONG g_phase = 0;
volatile LONG g_nextTick = 0;
volatile LONG g_scanNextTick = 0;
volatile LONG g_originalNextTick = 0;
volatile LONG g_groupCount = 0;
volatile LONG g_groupIndex = 0;
volatile LONG g_action = 1;
volatile LONG g_hasWaiting = 0;
volatile LONG g_hasMoveReady = 0;
volatile LONG g_waitingNoRush = 0;
volatile LONG g_stateFixTick = 0;
volatile LONG g_invalidTargetCount = 0;
volatile LONG g_targetReadFaults = 0;
volatile LONG g_dashTickRunning = 0;
volatile LONG g_dashTickSkipped = 0;
volatile LONG g_dashTickLastDurationMs = 0;
volatile LONG g_dashTickMaxDurationMs = 0;
volatile LONG g_stateFixWrite = 0;
volatile LONG g_stateFixLastIndex = 0;
volatile LONG g_stateFixLastEntry = 0;
volatile LONG g_diagLastReason = 0;
volatile LONG g_diagLastCurrent = 0;
volatile LONG g_diagLastTarget = 0;
volatile LONG g_diagLastTick = 0;
volatile LONG g_noMarchFreeLogShown = 0;
volatile LONG g_noRetreatMarchFreeLogShown = 0;
uint32_t g_targetTmp = 0;
BYTE g_groups[kMaxGroups * kGroupStride]{};
BYTE g_dashBuffer[256]{};
volatile LONG g_lureSwitch = 0;
volatile LONG g_fallbackSwitch = 0;
volatile LONG g_slowLureSwitch = 1;
volatile LONG g_showFlag = 0;
volatile LONG g_configReadHits = 0;
volatile LONG g_configLastStrike = 0;
volatile LONG g_configLastLure = 0;
volatile LONG g_configLastFallback = 0;
volatile LONG g_configLastSlowLure = 1;
HWND g_independentTimerHwnd = nullptr;

const wchar_t kConfigSection[] = L"WorldWar";
const wchar_t kLureKey[] = L"bLure";
const wchar_t kFallbackKey[] = L"bFallback";
const wchar_t kSlowLureKey[] = L"bSlowLure";
const wchar_t kLogFormat[] = L"%s";
const wchar_t kLogLureOffFallbackOff[] = {
    0x51FA, 0x64CA, 0x8A98, 0x6575, 0x0020, 0x7A81, 0x9032, 0x003D,
    0x95DC, 0x0020, 0x64A4, 0x9000, 0x003D, 0x95DC, 0x0000
};
const wchar_t kLogLureOffFallbackOn[] = {
    0x51FA, 0x64CA, 0x8A98, 0x6575, 0x0020, 0x7A81, 0x9032, 0x003D,
    0x95DC, 0x0020, 0x64A4, 0x9000, 0x003D, 0x958B, 0x0000
};
const wchar_t kLogLureOnFallbackOff[] = {
    0x51FA, 0x64CA, 0x8A98, 0x6575, 0x0020, 0x7A81, 0x9032, 0x003D,
    0x958B, 0x0020, 0x64A4, 0x9000, 0x003D, 0x95DC, 0x0000
};
const wchar_t kLogLureOnFallbackOn[] = {
    0x51FA, 0x64CA, 0x8A98, 0x6575, 0x0020, 0x7A81, 0x9032, 0x003D,
    0x958B, 0x0020, 0x64A4, 0x9000, 0x003D, 0x958B, 0x0000
};

bool BuildMainCode(uintptr_t base, CodeBuffer& code);
bool BuildGuardCode(uintptr_t base, CodeBuffer& code);
bool BuildTimerDispatchCode(uintptr_t base, CodeBuffer& code);
bool BuildTimerCode(uintptr_t base, CodeBuffer& code);
bool BuildConfigCode(uintptr_t base, CodeBuffer& code);
bool BuildTotalOnCode(uintptr_t base, CodeBuffer& code);
bool BuildResumeCode(uintptr_t base, CodeBuffer& code);
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
volatile LONG g_fastRoom = 0;
volatile LONG g_fastSlot = 0;
volatile LONG g_fastSent = 0;
volatile LONG g_lastCurrent = -1;
volatile LONG g_lastMax = -1;
volatile LONG g_lastAllowed = -1;
volatile LONG g_shouldBlock = 0;

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
const BYTE kMainLoopSpeed1000MsBytes[] = { 0xE8, 0x03, 0x00, 0x00 };
const BYTE kNativeWashFixedTotalRuleBytes[] = {
    0x83, 0xF8, 0x0C, 0x72, 0x08, 0x83, 0xF8, 0x0F, 0x75, 0x76, 0x90, 0x90, 0x90
};
const BYTE kNativeWashCandidateOrderBytes[] = { 0xE9, 0x11, 0x00, 0x00, 0x00, 0x90, 0x90 };
const BYTE kNativeWashMissingOwnerBytes[] = { 0x0F, 0x84, 0xB9, 0xFF, 0xFF, 0xFF };

const MemoryPatch kPatches[] = {
    { "Dragon vein fix", 0x4AA10, kDragonVeinPatchBytes, sizeof(kDragonVeinPatchBytes) },
    { "Break egg fix", 0x36B60, kBreakEggPatchBytes, sizeof(kBreakEggPatchBytes) },
    { "LGF refresh interval", 0x3719C, kLgfRefreshIntervalBytes, sizeof(kLgfRefreshIntervalBytes) },
    { "LGF suppress action log", 0x37385, kLgfSuppressActionLogBytes, sizeof(kLgfSuppressActionLogBytes) },
    { "Main loop speed 3AC2F", 0x3AC2F, kMainLoopSpeed1000MsBytes, sizeof(kMainLoopSpeed1000MsBytes) },
    { "Main loop speed 403E5", 0x403E5, kMainLoopSpeed1000MsBytes, sizeof(kMainLoopSpeed1000MsBytes) },
    { "Native wash fixed total rule", 0x3C1B3, kNativeWashFixedTotalRuleBytes, sizeof(kNativeWashFixedTotalRuleBytes) },
    { "Native wash candidate order", 0x3C1C8, kNativeWashCandidateOrderBytes, sizeof(kNativeWashCandidateOrderBytes) },
    { "Native wash missing owner", 0x3C2C9, kNativeWashMissingOwnerBytes, sizeof(kNativeWashMissingOwnerBytes) },
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

namespace Jrnt
{
bool BuildSendCode(uintptr_t base, CodeBuffer& code);
bool BuildBribeGateCode(uintptr_t base, CodeBuffer& code);
void HandleRecvPacket(uint32_t opcode, const BYTE* payload, uint32_t payloadLength);
}

namespace Xyfp
{
bool BuildSendCode(uintptr_t base, CodeBuffer& code);
void HandleRecvPacket(uint32_t opcode, const BYTE* payload, uint32_t payloadLength);
}

namespace PersonalTask
{
bool BuildSendCode(uintptr_t base, CodeBuffer& code);
void HandleRecvPacket(uint32_t opcode, const BYTE* payload, uint32_t payloadLength);
}

namespace LegionDungeon
{
bool BuildTickCode(uintptr_t base, CodeBuffer& code);
void HandleRecvPacket(uint32_t opcode, const BYTE* payload, uint32_t payloadLength);
}

namespace ExpeditionGuard
{
bool BuildCode(uintptr_t base, CodeBuffer& code);
void HandleRecvPacket(uint32_t opcode);
}

namespace SharedRecvRouter
{
volatile LONG g_clearStackArg = 0;
bool BuildCode(uintptr_t base, CodeBuffer& code);
}

namespace LgfGuard
{
bool BuildMainCode(uintptr_t base, CodeBuffer& code);
bool Build396FSlotCode(uintptr_t base, CodeBuffer& code);
bool Build396DCode(uintptr_t base, CodeBuffer& code);
bool Build3970Code(uintptr_t base, CodeBuffer& code);
}

namespace LoginCredentialPrompt
{
bool BuildCode(uintptr_t base, CodeBuffer& code);
}

namespace NativeWash
{
bool BuildCycleCode(uintptr_t base, CodeBuffer& code);
bool BuildAfterSendCode(uintptr_t base, CodeBuffer& code);
void HandleRecvPacket(uint32_t opcode, const BYTE* payload, uint32_t payloadLength);
}

const JumpPatch kJumpPatches[] = {
    { "Native log limiter", 0x25B70, 5, 96, NativeLogHook::BuildCode },
    { "Login credential prompt", 0x40DEA, 7, 128, LoginCredentialPrompt::BuildCode },
    { "Fast Daily Battle", 0x4A785, 11, 128, FastDailyBattle::BuildSend37A4Code },
    { "Shared recv router", 0x42AD0, 5, 128, SharedRecvRouter::BuildCode },
    { "Activity Login daily guard", 0x39F20, 6, 128, ActivityLogin::BuildDailyGuardCode },
    { "Daily Sign send tick", 0x38F90, 5, 128, DailySign::BuildSendCode },
    { "Prize Pool sender", 0x364C0, 5, 128, PrizePool::BuildSendCode },
    { "Weekly Reward sender", 0x35CE0, 5, 128, WeeklyReward::BuildSendCode },
    { "JRNT sender", 0x36A90, 11, 128, Jrnt::BuildSendCode },
    { "JRNT bribe task gate", 0x353B9, 5, 128, Jrnt::BuildBribeGateCode },
    { "XYFP sender", 0x36690, 6, 128, Xyfp::BuildSendCode },
    { "Personal Task sender", 0x3D000, 13, 128, PersonalTask::BuildSendCode },
    { "Legion Dungeon", 0x3B2E0, 5, 128, LegionDungeon::BuildTickCode },
    { "Expedition guard", 0x39D90, 11, 128, ExpeditionGuard::BuildCode },
    { "LGF status log", 0x37150, 7, 128, LgfGuard::BuildMainCode },
    { "LGF 396F fast slot", 0x48578, 9, 128, LgfGuard::Build396FSlotCode },
    { "LGF 396D guard", 0x4AC30, 6, 128, LgfGuard::Build396DCode },
    { "LGF 3970 guard", 0x4AC90, 6, 128, LgfGuard::Build3970Code },
    { "AutoLure dash main", 0x351F0, 6, 128, AutoLureDash::BuildMainCode },
    { "AutoLure dash guard", 0x3B7A0, 6, 128, AutoLureDash::BuildGuardCode },
    { "AutoLure dash timer dispatch", 0x40320, 5, 128, AutoLureDash::BuildTimerDispatchCode },
    { "AutoLure dash timer bootstrap", 0x403A3, 12, 128, AutoLureDash::BuildTimerCode },
    { "AutoLure dash config", 0x4B79B, 7, 160, AutoLureDash::BuildConfigCode },
    { "AutoLure dash total on", 0x401E0, 5, 64, AutoLureDash::BuildTotalOnCode },
    { "AutoLure dash resume", 0x412F0, 5, 64, AutoLureDash::BuildResumeCode },
    { "Native wash cycle gate", 0x3C0C0, 5, 128, NativeWash::BuildCycleCode },
    { "Native wash after send refresh", 0x3C2F2, 9, 128, NativeWash::BuildAfterSendCode },
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

bool AppendPushEbx(CodeBuffer& code)
{
    return AppendByte(code, 0x53);
}

bool AppendPushEsi(CodeBuffer& code)
{
    return AppendByte(code, 0x56);
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

bool AppendMovDwordPtrAbsEax(CodeBuffer& code, uint32_t address)
{
    return AppendByte(code, 0xA3) && AppendU32(code, address);
}

bool AppendMovDwordPtrAbsEcx(CodeBuffer& code, uint32_t address)
{
    return AppendByte(code, 0x89) && AppendByte(code, 0x0D) && AppendU32(code, address);
}

bool AppendIncDwordPtrAbs(CodeBuffer& code, uint32_t address)
{
    return AppendByte(code, 0xFF) && AppendByte(code, 0x05) && AppendU32(code, address);
}

bool AppendMovDwordPtrEbxOffsetEax(CodeBuffer& code, BYTE offset)
{
    return AppendByte(code, 0x89) && AppendByte(code, 0x43) && AppendByte(code, offset);
}

bool AppendMovDwordPtrEspOffsetEax(CodeBuffer& code, BYTE offset)
{
    return AppendByte(code, 0x89) &&
        AppendByte(code, 0x44) &&
        AppendByte(code, 0x24) &&
        AppendByte(code, offset);
}

bool AppendPushEdi(CodeBuffer& code)
{
    return AppendByte(code, 0x57);
}

bool AppendPopEdi(CodeBuffer& code)
{
    return AppendByte(code, 0x5F);
}

bool AppendPopEsi(CodeBuffer& code)
{
    return AppendByte(code, 0x5E);
}

bool AppendMovEdiEcx(CodeBuffer& code)
{
    return AppendByte(code, 0x8B) && AppendByte(code, 0xF9);
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

namespace NativeLogHook
{
const BYTE kExpectedHookBytes[] = { 0x55, 0x8B, 0xEC, 0x6A, 0xFF };

bool BuildCode(uintptr_t base, CodeBuffer& code)
{
    if (std::memcmp(
            reinterpret_cast<const void*>(base + 0x25B70),
            kExpectedHookBytes,
            sizeof(kExpectedHookBytes)) != 0) {
        return false;
    }

    return AppendByte(code, 0x9C) &&                         // pushfd
        AppendPushad(code) &&
        AppendByte(code, 0x51) &&                           // push ecx (native log owner)
        AppendRel32Instruction(
            code,
            0xE8,
            reinterpret_cast<uintptr_t>(&NativeOptimization::BeforeNativeLog)) &&
        AppendPopad(code) &&
        AppendByte(code, 0x9D) &&                           // popfd
        AppendByte(code, 0x55) &&                           // push ebp
        AppendByte(code, 0x8B) && AppendByte(code, 0xEC) && // mov ebp,esp
        AppendByte(code, 0x6A) && AppendByte(code, 0xFF) && // push -1
        AppendRel32Instruction(code, 0xE9, base + 0x25B75);
}
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

uint16_t ReadBe16Unaligned(const BYTE* address)
{
    return static_cast<uint16_t>((static_cast<uint16_t>(address[0]) << 8) | address[1]);
}

uint32_t ReadBe32Unaligned(const BYTE* address)
{
    return (static_cast<uint32_t>(address[0]) << 24) |
        (static_cast<uint32_t>(address[1]) << 16) |
        (static_cast<uint32_t>(address[2]) << 8) |
        address[3];
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
namespace GameLog
{
volatile LONG g_refreshing = 0;

const wchar_t* CurrentText()
{
    return *reinterpret_cast<const wchar_t* volatile*>(g_mainBase + 0x230504);
}

void RefreshExpected(const wchar_t* expectedText)
{
    if (g_mainBase == 0) {
        return;
    }

    if (!expectedText || !*expectedText) {
        return;
    }

    const wchar_t* currentText = CurrentText();
    if (!currentText || std::wcscmp(currentText, expectedText) != 0) {
        return;
    }

    if (InterlockedCompareExchange(&g_refreshing, 1, 0) != 0) {
        return;
    }

    using RefreshLogFn = void(__stdcall*)(uint32_t, uint32_t, uint32_t, uint32_t);
    RefreshLogFn refreshLog = *reinterpret_cast<RefreshLogFn*>(g_mainBase + 0x1C46B0);
    if (refreshLog) {
        refreshLog(ReadGameU32(g_mainBase + 0x2300A4), ReadGameU32(g_mainBase + 0x2304D8), 0, 0);
    }

    InterlockedExchange(&g_refreshing, 0);
}

void RefreshCurrent()
{
    // Bare refreshes can re-emit the game's previous shared log text.
}

template <typename... Args>
void Write(const wchar_t* format, Args... args)
{
    using PrintLogFn = void(__cdecl*)(uintptr_t, const wchar_t*, ...);
    PrintLogFn printLog = reinterpret_cast<PrintLogFn>(g_mainBase + 0x2EF0);
    printLog(g_mainBase + 0x230504, format, args...);

    wchar_t snapshot[512]{};
    const wchar_t* text = CurrentText();
    if (text) {
        std::wcsncpy(snapshot, text, _countof(snapshot) - 1);
        snapshot[_countof(snapshot) - 1] = 0;
    }

    RefreshExpected(snapshot);
}

}

namespace LoginCredentialPrompt
{
constexpr uintptr_t kAccountOffset = 0x23027C;
const BYTE kExpectedHookBytes[] = { 0x51, 0x8D, 0x45, 0xE0, 0x8B, 0xCC, 0x50 };
const wchar_t kTitle[] = L"Online 登入資料";
const wchar_t kFormat[] = L"%s\n%s";
volatile LONG g_promptStarted = 0;
volatile LONG g_accountCaptured = 0;
wchar_t g_message[2048]{};
wchar_t g_account[512]{};
wchar_t g_password[512]{};

DWORD WINAPI PromptThread(LPVOID)
{
    // MessageBoxW(nullptr, g_message, kTitle, MB_OK | MB_ICONINFORMATION);
    return 0;
}

__declspec(noinline) void __stdcall Show(const wchar_t* password)
{
    if (g_mainBase == 0) {
        return;
    }

    if (InterlockedCompareExchange(&g_promptStarted, 1, 0) != 0) {
        return;
    }

    const wchar_t* account = *reinterpret_cast<const wchar_t* volatile*>(g_mainBase + kAccountOffset);
    if (!account) {
        account = L"";
    }
    if (!password) {
        password = L"";
    }

    wcsncpy_s(g_account, _countof(g_account), account, _TRUNCATE);
    wcsncpy_s(g_password, _countof(g_password), password, _TRUNCATE);
    InterlockedExchange(&g_accountCaptured, 1);
    _snwprintf_s(g_message, _countof(g_message), _TRUNCATE, kFormat, account, password);

    // Keep the Online UI thread and its original DOM assignment/click flow
    // completely non-blocking. The copied text remains valid in DLL storage.
    HANDLE promptThread = CreateThread(nullptr, 0, PromptThread, nullptr, 0, nullptr);
    if (!promptThread) {
        InterlockedExchange(&g_promptStarted, 0);
        return;
    }
    CloseHandle(promptThread);
}

bool BuildCode(uintptr_t base, CodeBuffer& code)
{
    if (std::memcmp(reinterpret_cast<const void*>(base + 0x40DEA),
            kExpectedHookBytes,
            sizeof(kExpectedHookBytes)) != 0) {
        return false;
    }

    // Hook context: sub_440C30 has just returned from sub_402380.
    // [EBP-20] is the decoded password CString pointer.
    return AppendByte(code, 0x9C) &&                         // pushfd
        AppendPushad(code) &&
        AppendByte(code, 0xFF) && AppendByte(code, 0x75) && AppendByte(code, 0xE0) && // password
        AppendRel32Instruction(code, 0xE8, reinterpret_cast<uintptr_t>(&Show)) &&
        AppendPopad(code) &&
        AppendByte(code, 0x9D) &&                         // popfd
        AppendByte(code, 0x51) &&                         // push ecx
        AppendByte(code, 0x8D) && AppendByte(code, 0x45) && AppendByte(code, 0xE0) && // lea eax,[ebp-20]
        AppendByte(code, 0x8B) && AppendByte(code, 0xCC) && // mov ecx,esp
        AppendByte(code, 0x50) &&                         // push eax
        AppendRel32Instruction(code, 0xE9, base + 0x40DF1);
}

bool GetAccountSnapshot(std::wstring& account)
{
    if (InterlockedCompareExchange(&g_accountCaptured, 0, 0) != 1) {
        return false;
    }
    account.assign(g_account);
    return !account.empty();
}
}

namespace AutoBattleOff
{
constexpr DWORD kSendIntervalMs = 10000;
constexpr DWORD kTimerIntervalMs = 10000;
constexpr UINT_PTR kTimerId = 0x87D6;

volatile LONG g_enabled = 0;
volatile LONG g_lastSendTick = 0;
volatile LONG g_timerArmed = 0;
volatile LONG g_logShown = 0;
HWND g_timerHwnd = nullptr;
BYTE g_payload = 0;

const wchar_t kConfigKey[] = L"bCloseAuto";
const wchar_t kLogFormat[] = L"%s";
const wchar_t kLogText[] = {
    0x81EA, 0x52D5, 0x6230, 0x8853, 0x0020, 0x95DC, 0x9589, 0x0000
};

void ResetSchedule()
{
    InterlockedExchange(&g_lastSendTick, 0);
    InterlockedExchange(&g_logShown, 0);
}

void StartTimer()
{
    if (g_enabled == 0 || g_timerArmed != 0 || !g_timerHwnd || !IsWindow(g_timerHwnd)) {
        return;
    }

    if (SetTimer(g_timerHwnd, kTimerId, kTimerIntervalMs, nullptr) != 0) {
        InterlockedExchange(&g_timerArmed, 1);
    }
}

void StopTimer()
{
    if (g_timerHwnd && IsWindow(g_timerHwnd) && g_timerArmed != 0) {
        KillTimer(g_timerHwnd, kTimerId);
    }
    InterlockedExchange(&g_timerArmed, 0);
    ResetSchedule();
}

__declspec(noinline) void __stdcall EnsureTimer(void* owner)
{
    if (!owner) {
        return;
    }

    HWND hwnd = *reinterpret_cast<HWND*>(reinterpret_cast<uintptr_t>(owner) + 0x20);
    if (!hwnd || !IsWindow(hwnd)) {
        return;
    }

    if (g_timerHwnd == hwnd) {
        StartTimer();
        return;
    }

    if (g_timerHwnd && IsWindow(g_timerHwnd) && g_timerArmed != 0) {
        KillTimer(g_timerHwnd, kTimerId);
    }

    InterlockedExchange(&g_timerArmed, 0);
    g_timerHwnd = hwnd;
    StartTimer();
}

__declspec(noinline) void __stdcall Tick()
{
    if (g_enabled == 0) {
        ResetSchedule();
        return;
    }

    const DWORD now = GetGameTick();
    const DWORD lastSendTick = static_cast<DWORD>(g_lastSendTick);
    if (lastSendTick != 0 && now - lastSendTick < kSendIntervalMs) {
        return;
    }

    InterlockedExchange(&g_lastSendTick, static_cast<LONG>(now));
    using SendPacketFn = void(__stdcall*)(uint32_t, const void*, uint32_t);
    SendPacketFn sendPacket = reinterpret_cast<SendPacketFn>(g_mainBase + 0x4A360);
    sendPacket(0x147D, &g_payload, sizeof(g_payload));
    if (InterlockedCompareExchange(&g_logShown, 1, 0) == 0) {
        GameLog::Write(kLogFormat, kLogText);
    }
}

__declspec(noinline) void __stdcall TimerTick(void* owner)
{
    if (!owner) {
        return;
    }

    HWND hwnd = *reinterpret_cast<HWND*>(reinterpret_cast<uintptr_t>(owner) + 0x20);
    if (!hwnd || !IsWindow(hwnd)) {
        InterlockedExchange(&g_timerArmed, 0);
        g_timerHwnd = nullptr;
        return;
    }

    KillTimer(hwnd, kTimerId);
    InterlockedExchange(&g_timerArmed, 0);
    Tick();
    g_timerHwnd = hwnd;
    StartTimer();
}

}

namespace NativeWash
{
constexpr uint32_t kBagUpdateV2Opcode = 0x0BCB;
constexpr uint32_t kRequestBagInfoOpcode = 0x0B8A;
constexpr uint16_t kStorageBagId = 1;
constexpr uint32_t kV2HeaderSize = 0x14;
constexpr uint32_t kLegacyHeaderSize = 0x0C;
constexpr uint32_t kSkippedPagingBytes = kV2HeaderSize - kLegacyHeaderSize;
constexpr uint32_t kMinV2PayloadSize = 0x16;

volatile LONG g_refreshCounter = 0;
volatile LONG g_bagDataReady = 0;
volatile LONG g_v2ParserBusy = 0;
BYTE g_legacyBagBuffer[65536]{};
BYTE g_bagRequestPayload[10] = { 0x00, 0x01 };

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

void RequestBag1()
{
    if (g_mainBase == 0 || ReadGameU32(g_mainBase + 0x230648) == 0) {
        return;
    }

    const uintptr_t heroList = static_cast<uintptr_t>(ReadGameU32(g_mainBase + 0x230644));
    if (heroList == 0) {
        return;
    }

    const uintptr_t firstHero = static_cast<uintptr_t>(ReadGameU32(heroList));
    if (firstHero == 0) {
        return;
    }

    std::memcpy(g_bagRequestPayload + 2, reinterpret_cast<const void*>(firstHero), 8);
    SendPacketWithEcx(
        static_cast<uint32_t>(firstHero),
        kRequestBagInfoOpcode,
        g_bagRequestPayload,
        sizeof(g_bagRequestPayload));
}

__declspec(noinline) LONG __stdcall BeforeCycle()
{
    if (*reinterpret_cast<volatile BYTE*>(g_mainBase + 0x230438) == 0) {
        return 0;
    }

    if (InterlockedCompareExchange(&g_bagDataReady, 0, 0) == 0) {
        RequestBag1();
        return 1;
    }

    const LONG counter = InterlockedCompareExchange(&g_refreshCounter, 0, 0);
    if (counter == 0) {
        InterlockedExchange(&g_refreshCounter, 4);
        InterlockedExchange(&g_bagDataReady, 0);
        RequestBag1();
        return 1;
    }

    InterlockedDecrement(&g_refreshCounter);
    return 0;
}

__declspec(noinline) void __stdcall AfterSend()
{
    InterlockedExchange(&g_bagDataReady, 0);
    InterlockedExchange(&g_refreshCounter, 4);
    RequestBag1();
}

void HandleRecvPacket(uint32_t opcode, const BYTE* payload, uint32_t payloadLength)
{
    if (opcode != kBagUpdateV2Opcode || !payload || payloadLength < kMinV2PayloadSize ||
        payloadLength > sizeof(g_legacyBagBuffer) + kSkippedPagingBytes) {
        return;
    }
    if (ReadBe16Unaligned(payload + 8) != kStorageBagId) {
        return;
    }
    if (InterlockedCompareExchange(&g_v2ParserBusy, 1, 0) != 0) {
        return;
    }

    const bool finalPage = ReadU32Unaligned(payload + 0x0C) == ReadU32Unaligned(payload + 0x10);
    std::memcpy(g_legacyBagBuffer, payload, kLegacyHeaderSize);
    std::memcpy(
        g_legacyBagBuffer + kLegacyHeaderSize,
        payload + kV2HeaderSize,
        payloadLength - kV2HeaderSize);

    const uint32_t legacyPayloadLength = payloadLength - kSkippedPagingBytes;
    using ParseLegacyBagFn = int(__fastcall*)(const BYTE*, int);
    ParseLegacyBagFn parseLegacyBag = reinterpret_cast<ParseLegacyBagFn>(g_mainBase + 0x457C0);
    parseLegacyBag(g_legacyBagBuffer, static_cast<int>(legacyPayloadLength));

    if (finalPage) {
        InterlockedExchange(&g_bagDataReady, 1);
    }
    InterlockedExchange(&g_v2ParserBusy, 0);
}

bool BuildCycleCode(uintptr_t base, CodeBuffer& code)
{
    return AppendByte(code, 0x9C) &&
        AppendPushad(code) &&
        AppendRel32Instruction(code, 0xE8, reinterpret_cast<uintptr_t>(&BeforeCycle)) &&
        AppendByte(code, 0x85) && AppendByte(code, 0xC0) &&
        AppendJeShort(code, 0x03) &&
        AppendPopad(code) &&
        AppendByte(code, 0x9D) &&
        AppendByte(code, 0xC3) &&
        AppendPopad(code) &&
        AppendByte(code, 0x9D) &&
        AppendOriginalFunctionPrologue(code) &&
        AppendRel32Instruction(code, 0xE9, base + 0x3C0C5);
}

bool BuildAfterSendCode(uintptr_t base, CodeBuffer& code)
{
    return AppendByte(code, 0x9C) &&
        AppendPushad(code) &&
        AppendRel32Instruction(code, 0xE8, reinterpret_cast<uintptr_t>(&AfterSend)) &&
        AppendPopad(code) &&
        AppendByte(code, 0x9D) &&
        AppendByte(code, 0x6A) && AppendByte(code, 0x00) &&
        AppendByte(code, 0x6A) && AppendByte(code, 0x00) &&
        AppendPushImm32(code, 0x0BAD) &&
        AppendRel32Instruction(code, 0xE9, base + 0x3C2FB);
}

}

namespace ExpeditionGuard
{
constexpr DWORD kPendingTimeoutMs = 15000;
constexpr DWORD kRefreshIntervalMs = 0x124F80;
constexpr uintptr_t kSwitchOffset = 0x2302F0;
constexpr uintptr_t kNodeArrayOffset = 0x2307C0;
constexpr uintptr_t kNodeCountOffset = 0x2307C4;
constexpr uintptr_t kChallengeCountOffset = 0x2307B4;
constexpr uintptr_t kChallengeQueryFlagOffset = 0x2307B8;
constexpr uintptr_t kRefreshTickOffset = 0x230FD4;

volatile LONG g_pending = 0;
volatile LONG g_pendingType = 0;
volatile LONG g_pendingId = 0;
volatile LONG g_pendingTick = 0;
volatile LONG g_allowChallengeQuery = 0;
volatile LONG g_pendingSetCount = 0;
volatile LONG g_pendingClearCount = 0;
volatile LONG g_skipCount = 0;

void ClearPending()
{
    InterlockedExchange(&g_pending, 0);
    InterlockedExchange(&g_pendingType, 0);
    InterlockedExchange(&g_pendingId, 0);
    InterlockedExchange(&g_pendingTick, 0);
    InterlockedExchange(&g_allowChallengeQuery, 0);
}

void SetPending(uint32_t type, uint32_t id, bool allowChallengeQuery)
{
    InterlockedExchange(&g_pendingType, static_cast<LONG>(type));
    InterlockedExchange(&g_pendingId, static_cast<LONG>(id));
    InterlockedExchange(&g_pendingTick, static_cast<LONG>(GetTickCount()));
    InterlockedExchange(&g_allowChallengeQuery, allowChallengeQuery ? 1 : 0);
    InterlockedExchange(&g_pending, 1);
    InterlockedIncrement(&g_pendingSetCount);
}

bool FindActionNode(uint32_t& id, uint32_t& type)
{
    const uint32_t count = ReadGameU32(g_mainBase + kNodeCountOffset);
    const uint32_t nodeArray = ReadGameU32(g_mainBase + kNodeArrayOffset);
    if (count == 0 || count > 256 || nodeArray == 0) {
        return false;
    }

    for (uint32_t i = 0; i < count; ++i) {
        const uint32_t node = ReadGameU32(nodeArray + i * sizeof(uint32_t));
        if (node == 0) {
            continue;
        }

        if (ReadGameU32(node + 8) != 1) {
            continue;
        }

        id = ReadGameU32(node);
        type = ReadGameU32(node + 4);
        return true;
    }

    return false;
}

__declspec(noinline) uint32_t __stdcall ShouldSkip()
{
    if (g_mainBase == 0 || ReadGameU32(g_mainBase + kSwitchOffset) == 0) {
        ClearPending();
        return 0;
    }

    const DWORD now = GetTickCount();
    if (g_pending != 0) {
        const DWORD pendingTick = static_cast<DWORD>(g_pendingTick);
        if (now - pendingTick >= kPendingTimeoutMs) {
            ClearPending();
        } else if (g_pendingType == 0 && g_allowChallengeQuery != 0) {
            InterlockedExchange(&g_allowChallengeQuery, 0);
            return 0;
        } else {
            InterlockedIncrement(&g_skipCount);
            return 1;
        }
    }

    if (ReadGameU32(g_mainBase + kNodeCountOffset) == 0) {
        return 0;
    }

    const DWORD refreshTick = ReadGameU32(g_mainBase + kRefreshTickOffset);
    if (now - refreshTick > kRefreshIntervalMs) {
        return 0;
    }

    uint32_t id = 0;
    uint32_t type = 0;
    if (!FindActionNode(id, type)) {
        return 0;
    }

    if (type == 1) {
        SetPending(type, id, false);
    } else if (type == 0 &&
        ReadGameU32(g_mainBase + kChallengeCountOffset) > 0 &&
        ReadGameU32(g_mainBase + kChallengeQueryFlagOffset) == 0) {
        SetPending(type, id, true);
    }

    return 0;
}

void HandleRecvPacket(uint32_t opcode)
{
    if ((opcode & 0xFFFF) == 0x2BA3) {
        ClearPending();
        InterlockedIncrement(&g_pendingClearCount);
    }
}

bool BuildCode(uintptr_t base, CodeBuffer& code)
{
    return AppendByte(code, 0x9C) &&
        AppendPushad(code) &&
        AppendRel32Instruction(code, 0xE8, reinterpret_cast<uintptr_t>(&ShouldSkip)) &&
        AppendByte(code, 0x85) && AppendByte(code, 0xC0) &&
        AppendJeShort(code, 0x03) &&
        AppendPopad(code) &&
        AppendByte(code, 0x9D) &&
        AppendByte(code, 0xC3) &&
        AppendPopad(code) &&
        AppendByte(code, 0x9D) &&
        AppendByte(code, 0x55) &&
        AppendByte(code, 0x8B) && AppendByte(code, 0xEC) &&
        AppendByte(code, 0x51) &&
        AppendByte(code, 0x83) && AppendByte(code, 0x3D) &&
        AppendU32(code, static_cast<uint32_t>(base + kSwitchOffset)) &&
        AppendByte(code, 0x00) &&
        AppendRel32Instruction(code, 0xE9, base + 0x39D9B);
}

}

namespace AlBattle
{

struct Reader
{
    const BYTE* cursor = nullptr;
    const BYTE* end = nullptr;

    bool CanRead(size_t bytes) const
    {
        return cursor && end && cursor <= end && bytes <= static_cast<size_t>(end - cursor);
    }

    bool ReadU16(uint32_t& value)
    {
        if (!CanRead(2)) {
            InterlockedExchange(&g_parseError, 1);
            value = 0;
            cursor = end;
            return false;
        }

        value = ReadBe16Unaligned(cursor);
        cursor += 2;
        return true;
    }

    bool ReadU32(uint32_t& value)
    {
        if (!CanRead(4)) {
            InterlockedExchange(&g_parseError, 1);
            value = 0;
            cursor = end;
            return false;
        }

        value = ReadBe32Unaligned(cursor);
        cursor += 4;
        return true;
    }

    bool Skip(size_t bytes)
    {
        if (!CanRead(bytes)) {
            InterlockedExchange(&g_parseError, 1);
            cursor = end;
            return false;
        }

        cursor += bytes;
        return true;
    }

    bool SkipString()
    {
        uint32_t length = 0;
        return ReadU16(length) && Skip(length);
    }
};

void StoreHero(uint32_t uuid0, uint32_t uuid4)
{
    LONG index = g_heroCount;
    if (index < 0 || index >= static_cast<LONG>(kMaxHeroes)) {
        return;
    }

    HeroEntry& hero = g_heroTable[index];
    hero.uuid0 = uuid0;
    hero.uuid4 = uuid4;
    hero.ready = 1;
    hero.tick = GetTickCount();
    InterlockedExchange(&g_heroCount, index + 1);
}

size_t CopyReadyHeroUuids(BYTE* output, size_t capacity)
{
    if (!output || capacity == 0) {
        return 0;
    }
    size_t written = 0;
    __try {
        const uintptr_t list = static_cast<uintptr_t>(
            ReadGameU32(g_mainBase + 0x230644));
        const uint32_t rawCount = ReadGameU32(g_mainBase + 0x230648);
        const size_t count = rawCount < capacity ? rawCount : capacity;
        if (list != 0 && count <= 32) {
            for (size_t index = 0; index < count; ++index) {
                const uintptr_t entry = static_cast<uintptr_t>(
                    ReadGameU32(list + index * sizeof(uint32_t)));
                if (entry == 0) {
                    continue;
                }
                std::memcpy(output + written * 8,
                    reinterpret_cast<const void*>(entry), 8);
                ++written;
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        written = 0;
    }
    if (written != 0) {
        return written;
    }

    const LONG available = g_heroCount;
    const size_t availableCount = available > 0 ? static_cast<size_t>(available) : 0;
    const size_t count = availableCount < capacity ? availableCount : capacity;
    for (size_t index = 0; index < count; ++index) {
        const HeroEntry& hero = g_heroTable[index];
        if (hero.ready == 0) {
            continue;
        }
        std::memcpy(output + written * 8, &hero.uuid0, 4);
        std::memcpy(output + written * 8 + 4, &hero.uuid4, 4);
        ++written;
    }
    return written;
}

bool ParseOneHero(Reader& reader, uint32_t index)
{
    if (!reader.CanRead(8)) {
        InterlockedExchange(&g_parseError, 1);
        return false;
    }

    const uint32_t uuid0 = ReadU32Unaligned(reader.cursor);
    const uint32_t uuid4 = ReadU32Unaligned(reader.cursor + 4);
    reader.cursor += 8;

    if (!reader.SkipString() || !reader.SkipString() || !reader.Skip(0x1A) || !reader.CanRead(4)) {
        return false;
    }

    const BYTE state = *reader.cursor++;
    uint32_t roleType = 0;
    if (!reader.ReadU16(roleType) || !reader.Skip(1)) {
        return false;
    }

    if (index < 5 && state == 1 && roleType != 4) {
        StoreHero(uuid0, uuid4);
    }

    if (!reader.SkipString() || !reader.Skip(4)) {
        return false;
    }

    uint32_t unusedTacticCount = 0;
    if (!reader.ReadU16(unusedTacticCount)) {
        return false;
    }

    for (uint32_t i = 0; i < index; ++i) {
        if (!reader.Skip(4) || !reader.SkipString()) {
            return false;
        }
    }

    return reader.SkipString();
}

bool ParseHeroList(Reader& reader)
{
    uint32_t count = 0;
    if (!reader.ReadU16(count)) {
        return false;
    }

    for (uint32_t i = 0; i < count; ++i) {
        if (!ParseOneHero(reader, i)) {
            return false;
        }
    }

    return true;
}

bool ParseCityTroops(Reader& reader, volatile LONG& output)
{
    uint32_t count = 0;
    if (!reader.ReadU16(count)) {
        return false;
    }

    uint32_t total = 0;
    for (uint32_t i = 0; i < count; ++i) {
        uint32_t unused = 0;
        uint32_t troops = 0;
        if (!reader.ReadU16(unused) || !reader.ReadU32(troops) || !reader.SkipString()) {
            return false;
        }
        total += troops;
    }

    InterlockedExchange(&output, static_cast<LONG>(total));
    return true;
}

void Handle1460(const BYTE* payload, uint32_t payloadLength)
{
    InterlockedExchange(&g_parseError, 0);
    InterlockedExchange(&g_heroCount, 0);
    std::memset(g_heroTable, 0, sizeof(g_heroTable));
    if (!payload || payloadLength < 0x10) {
        return;
    }

    Reader reader{ payload + 0x10, payload + payloadLength };
    ParseHeroList(reader);
    if (g_parseError == 0) {
        ParseHeroList(reader);
    }
}

void Handle146F(const BYTE* payload, uint32_t payloadLength)
{
    if (!payload || payloadLength < 7) {
        return;
    }

    InterlockedExchange(&g_location, payload[0]);
    InterlockedExchange(&g_rushRatio, 2);

    static constexpr char kMarchFreeKey[] = "\"march_free\":";
    const size_t keyLength = sizeof(kMarchFreeKey) - 1;
    for (uint32_t i = 0; i + keyLength <= payloadLength; ++i) {
        if (std::memcmp(payload + i, kMarchFreeKey, keyLength) != 0) {
            continue;
        }

        uint32_t cursor = i + static_cast<uint32_t>(keyLength);
        LONG value = 0;
        bool hasDigit = false;
        while (cursor < payloadLength && payload[cursor] >= '0' && payload[cursor] <= '9') {
            hasDigit = true;
            const LONG digit = static_cast<LONG>(payload[cursor] - '0');
            if (value > 1000000) {
                return;
            }
            value = value * 10 + digit;
            ++cursor;
        }

        if (hasDigit) {
            InterlockedExchange(&g_marchFree, value);
            InterlockedExchange(&g_marchFreeKnown, 1);
        }
        return;
    }
}

void Handle147C(const BYTE* payload, uint32_t payloadLength)
{
    if (!payload || payloadLength < 3) {
        return;
    }

    const LONG count = static_cast<LONG>(ReadBe16Unaligned(payload + 1));
    if (payload[0] == 0) {
        InterlockedExchange(&g_leftCount, count);
    } else {
        InterlockedExchange(&g_rightCount, count);
    }
}

void Handle1B3E(const BYTE* payload, uint32_t payloadLength)
{
    if (!payload) {
        return;
    }

    InterlockedExchange(&g_parseError, 0);
    InterlockedExchange(&g_cityAttackers, 0);
    InterlockedExchange(&g_cityDefenders, 0);
    Reader reader{ payload, payload + payloadLength };
    uint32_t city = 0;
    uint32_t unused = 0;
    if (!reader.ReadU16(city) || !reader.ReadU32(unused)) {
        return;
    }

    InterlockedExchange(&g_lastCity, static_cast<LONG>(city));
    ParseCityTroops(reader, g_cityAttackers);
    if (g_parseError == 0) {
        ParseCityTroops(reader, g_cityDefenders);
    }
}

void HandleRecvPacket(uint32_t opcode, const BYTE* payload, uint32_t payloadLength)
{
    switch (opcode & 0xFFFF) {
    case 0x1460:
        Handle1460(payload, payloadLength);
        break;
    case 0x146F:
        Handle146F(payload, payloadLength);
        break;
    case 0x147C:
        Handle147C(payload, payloadLength);
        break;
    case 0x1B3E:
        Handle1B3E(payload, payloadLength);
        break;
    default:
        break;
    }
}

bool HasRushAdvantage()
{
    const LONG left = g_leftCount;
    const LONG right = g_rightCount;
    const LONG location = g_location;
    if (left == 0) {
        return right > 0;
    }
    if (right <= 0) {
        return true;
    }
    if (location == 0) {
        return left >= right * 2;
    }

    return right >= left * 2;
}

}

namespace WorldCityBattle
{
constexpr size_t kCityStateCount = 0x10000;
constexpr DWORD kCityStateFreshMs = 3000;
constexpr BYTE kCityUnknown = 0;
constexpr BYTE kCityIdle = 1;
constexpr BYTE kCityFighting = 2;

volatile BYTE g_cityStates[kCityStateCount]{};
volatile LONG g_cityUpdateTicks[kCityStateCount]{};
volatile LONG g_fullPacketCount = 0;
volatile LONG g_fullParseFailures = 0;
volatile LONG g_singlePacketCount = 0;
volatile LONG g_lastUpdateCity = 0;
volatile LONG g_lastUpdateFighting = 0;

struct Reader
{
    const BYTE* cursor = nullptr;
    const BYTE* end = nullptr;

    bool CanRead(size_t bytes) const
    {
        return cursor && end && cursor <= end && bytes <= static_cast<size_t>(end - cursor);
    }

    bool ReadU16(uint32_t& value)
    {
        if (!CanRead(2)) {
            return false;
        }
        value = ReadBe16Unaligned(cursor);
        cursor += 2;
        return true;
    }

    bool Skip(size_t bytes)
    {
        if (!CanRead(bytes)) {
            return false;
        }
        cursor += bytes;
        return true;
    }

    bool SkipString()
    {
        uint32_t length = 0;
        return ReadU16(length) && Skip(length);
    }
};

bool SkipBuff(Reader& reader)
{
    return reader.Skip(4) &&
        reader.SkipString() &&
        reader.Skip(4) &&
        reader.SkipString() &&
        reader.Skip(4) &&
        reader.Skip(1) &&
        reader.SkipString();
}

bool ParseCityList(Reader& reader, bool store, DWORD updateTick)
{
    uint32_t cityCount = 0;
    if (!reader.ReadU16(cityCount)) {
        return false;
    }

    for (uint32_t i = 0; i < cityCount; ++i) {
        uint32_t cityId = 0;
        if (!reader.ReadU16(cityId) || !reader.CanRead(4)) {
            return false;
        }

        const BYTE fighting = reader.cursor[3];
        reader.cursor += 4;

        uint32_t buffCount = 0;
        if (!reader.ReadU16(buffCount)) {
            return false;
        }
        for (uint32_t j = 0; j < buffCount; ++j) {
            if (!SkipBuff(reader)) {
                return false;
            }
        }
        if (!reader.SkipString()) {
            return false;
        }

        if (store) {
            g_cityStates[cityId] = fighting != 0 ? kCityFighting : kCityIdle;
            g_cityUpdateTicks[cityId] = static_cast<LONG>(updateTick);
        }
    }
    return true;
}

void HandleFullCityInfo(const BYTE* payload, uint32_t payloadLength)
{
    InterlockedIncrement(&g_fullPacketCount);
    if (!payload || payloadLength < 2) {
        InterlockedIncrement(&g_fullParseFailures);
        return;
    }

    Reader validate{ payload, payload + payloadLength };
    if (!ParseCityList(validate, false, 0)) {
        InterlockedIncrement(&g_fullParseFailures);
        return;
    }

    std::memset(const_cast<BYTE*>(g_cityStates), kCityUnknown, sizeof(g_cityStates));
    std::memset(const_cast<LONG*>(g_cityUpdateTicks), 0, sizeof(g_cityUpdateTicks));
    Reader store{ payload, payload + payloadLength };
    ParseCityList(store, true, GetTickCount());
}

void HandleSingleCityUpdate(const BYTE* payload, uint32_t payloadLength)
{
    if (!payload || payloadLength < 6) {
        return;
    }

    const uint32_t cityId = ReadBe16Unaligned(payload);
    const BYTE fighting = payload[5];
    g_cityStates[cityId] = fighting != 0 ? kCityFighting : kCityIdle;
    g_cityUpdateTicks[cityId] = static_cast<LONG>(GetTickCount());
    InterlockedIncrement(&g_singlePacketCount);
    InterlockedExchange(&g_lastUpdateCity, static_cast<LONG>(cityId));
    InterlockedExchange(&g_lastUpdateFighting, static_cast<LONG>(fighting));
}

void HandleRecvPacket(uint32_t opcode, const BYTE* payload, uint32_t payloadLength)
{
    switch (opcode & 0xFFFF) {
    case 0x1B33:
        HandleFullCityInfo(payload, payloadLength);
        break;
    case 0x1B36:
        HandleSingleCityUpdate(payload, payloadLength);
        break;
    default:
        break;
    }
}

bool IsFighting(uint32_t cityId, bool& known)
{
    known = false;
    if (cityId >= kCityStateCount) {
        return false;
    }

    const DWORD updateTick = static_cast<DWORD>(g_cityUpdateTicks[cityId]);
    if (updateTick == 0 || GetTickCount() - updateTick > kCityStateFreshMs) {
        return false;
    }

    const BYTE state = g_cityStates[cityId];
    known = state != kCityUnknown;
    return state == kCityFighting;
}

}

namespace AutoLureDash
{

BYTE* GroupPtr(size_t index)
{
    return g_groups + index * kGroupStride;
}

void ResetDashState()
{
    InterlockedExchange(&g_phase, 0);
    InterlockedExchange(&g_groupCount, 0);
    InterlockedExchange(&g_groupIndex, 0);
    InterlockedExchange(&g_scanNextTick, 0);
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

void RefreshLog()
{
    GameLog::RefreshCurrent();
}

void WriteDashLog(const wchar_t* text)
{
    GameLog::Write(kLogFormat, text);
}

bool IsMarchFreeExhausted()
{
    return AlBattle::g_marchFreeKnown == 0 || AlBattle::g_marchFree <= 0;
}

void WriteNoMarchFreeLogOnce()
{
    if (InterlockedCompareExchange(&g_noMarchFreeLogShown, 1, 0) == 0) {
        if (AlBattle::g_marchFreeKnown == 0) {
            static const wchar_t unknownMessage[] = {
                0x884C, 0x8ECD, 0x6B21, 0x6578, 0x672A, 0x77E5, 0x0000
            };
            WriteDashLog(unknownMessage);
            return;
        }
        static const wchar_t message[] = {
            0x6C92, 0x6709, 0x5269, 0x9918, 0x7A81, 0x9032, 0x6B21, 0x6578, 0x0000
        };
        WriteDashLog(message);
    }
}

void RefreshMarchFreeLogState()
{
    if (AlBattle::g_marchFreeKnown != 0 && AlBattle::g_marchFree > 0) {
        InterlockedExchange(&g_noMarchFreeLogShown, 0);
        InterlockedExchange(&g_noRetreatMarchFreeLogShown, 0);
    }
}

void WriteNoRetreatMarchFreeLogOnce()
{
    if (InterlockedCompareExchange(&g_noRetreatMarchFreeLogShown, 1, 0) == 0) {
        if (AlBattle::g_marchFreeKnown == 0) {
            static const wchar_t unknownMessage[] = {
                0x884C, 0x8ECD, 0x6B21, 0x6578, 0x672A, 0x77E5, 0x0000
            };
            WriteDashLog(unknownMessage);
            return;
        }
        static const wchar_t message[] = {
            0x6C92, 0x6709, 0x5269, 0x9918, 0x64A4, 0x9000, 0x6B21, 0x6578, 0x0000
        };
        WriteDashLog(message);
    }
}

void WriteMarchFreeBeforeDash()
{
    static const wchar_t format[] = {
        0x7A81, 0x9032, 0x5269, 0x9918, 0x6B21, 0x6578, 0xFF1A,
        0x0025, 0x006C, 0x0064, 0x0000
    };
    wchar_t message[64]{};
    std::swprintf(
        message,
        _countof(message),
        format,
        AlBattle::g_marchFree);
    WriteDashLog(message);
}

enum DashDiagReason : LONG
{
    kDiagTargetMissing = 1,
    kDiagWrongCity = 2,
    kDiagCountNoRush = 3,
    kDiagGroupCreated = 4,
    kDiagAllowOriginalWaiting = 5,
    kDiagAllowOriginalMove = 6,
    kDiagBlockOriginal = 7,
    kDiagSend1467 = 8,
    kDiagSend31E6 = 9,
    kDiagSend1483 = 10,
    kDiagSend1482 = 11,
    kDiagSkip1482 = 12,
    kDiagTargetFightingOrUnknown = 13,
};

const wchar_t* DashDiagReasonText(LONG reason)
{
    switch (reason) {
    case kDiagTargetMissing:
        return L"target_missing";
    case kDiagWrongCity:
        return L"wrong_city";
    case kDiagCountNoRush:
        return L"count_no_rush";
    case kDiagGroupCreated:
        return L"group_created";
    case kDiagAllowOriginalWaiting:
        return L"allow_original_waiting";
    case kDiagAllowOriginalMove:
        return L"allow_original_move";
    case kDiagBlockOriginal:
        return L"block_original";
    case kDiagSend1467:
        return L"send_1467";
    case kDiagSend31E6:
        return L"send_31E6";
    case kDiagSend1483:
        return L"send_1483";
    case kDiagSend1482:
        return L"send_1482";
    case kDiagSkip1482:
        return L"skip_1482";
    case kDiagTargetFightingOrUnknown:
        return L"target_fighting_or_unknown";
    default:
        return L"unknown";
    }
}

void WriteDashDiag(LONG reason, uint32_t current, uint32_t target)
{
    if (!kEnableDashDiagLog) {
        return;
    }

    const DWORD now = GetTickCount();
    const LONG lastTick = g_diagLastTick;
    if (g_diagLastReason == reason &&
        g_diagLastCurrent == static_cast<LONG>(current) &&
        g_diagLastTarget == static_cast<LONG>(target) &&
        now - static_cast<DWORD>(lastTick) < 3000) {
        return;
    }

    InterlockedExchange(&g_diagLastReason, reason);
    InterlockedExchange(&g_diagLastCurrent, static_cast<LONG>(current));
    InterlockedExchange(&g_diagLastTarget, static_cast<LONG>(target));
    InterlockedExchange(&g_diagLastTick, static_cast<LONG>(now));

    wchar_t message[192]{};
    std::swprintf(
        message,
        _countof(message),
        L"DashDiag %s cur=%u target=%u last=%ld L=%ld R=%ld loc=%ld",
        DashDiagReasonText(reason),
        current,
        target,
        AlBattle::g_lastCity,
        AlBattle::g_leftCount,
        AlBattle::g_rightCount,
        AlBattle::g_location);
    WriteDashLog(message);
}

void ShowOptions()
{
    using ShowOptionsFn = void(__stdcall*)();
    ShowOptionsFn showOptions = reinterpret_cast<ShowOptionsFn>(g_mainBase + 0x4D810);
    showOptions();

    InterlockedExchange(&g_showFlag, 1);
    if (g_lureSwitch != 0) {
        WriteDashLog(g_fallbackSwitch != 0 ? kLogLureOnFallbackOn : kLogLureOnFallbackOff);
        return;
    }

    WriteDashLog(g_fallbackSwitch != 0 ? kLogLureOffFallbackOn : kLogLureOffFallbackOff);
}

bool GetTargetImpl(uintptr_t entry, uint32_t& current, uint32_t& target)
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
    if (count <= 0 || count > kMaxTargetNodes) {
        if (count > kMaxTargetNodes) {
            InterlockedIncrement(&g_invalidTargetCount);
        }
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

bool GetTarget(uintptr_t entry, uint32_t& current, uint32_t& target)
{
    __try {
        return GetTargetImpl(entry, current, target);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        InterlockedIncrement(&g_targetReadFaults);
        current = 0;
        target = 0;
        return false;
    }
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

bool CanDashFromCurrent(uint32_t current)
{
    return AlBattle::HasRushAdvantage();
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
    WriteGroupU32(group, kEntryArrayOffset + count * sizeof(uint32_t), static_cast<uint32_t>(entry));
    ++count;
    WriteGroupU32(group, 0x08, count);
}

void StateFix()
{
    InterlockedIncrement(&g_stateFixTick);
    if (ReadGameU32(g_mainBase + 0x2303E8) == 0) {
        return;
    }

    uintptr_t list = ReadGameU32(g_mainBase + 0x230644);
    if (list == 0) {
        return;
    }

    int32_t count = static_cast<int32_t>(ReadGameU32(g_mainBase + 0x230648));
    if (count <= 0) {
        return;
    }
    if (count > 5) {
        count = 5;
    }

    for (int32_t i = 0; i < count; ++i) {
        uintptr_t entry = ReadGameU32(list + static_cast<uintptr_t>(i) * sizeof(uint32_t));
        if (entry == 0 || ReadGameU32(entry + 0x1C) != 1 || ReadGameU32(entry + 0x44) != 0) {
            continue;
        }

        InterlockedIncrement(&g_stateFixWrite);
        InterlockedExchange(&g_stateFixLastIndex, i);
        InterlockedExchange(&g_stateFixLastEntry, static_cast<LONG>(entry));
        *reinterpret_cast<volatile uint32_t*>(entry + 0x1C) = 4;
    }
}

void BuildGroups()
{
    InterlockedExchange(&g_groupCount, 0);
    InterlockedExchange(&g_groupIndex, 0);
    InterlockedExchange(&g_waitingNoRush, 0);
    InterlockedExchange(&g_hasWaiting, 0);
    InterlockedExchange(&g_hasMoveReady, 0);
    std::memset(g_groups, 0, sizeof(g_groups));

    RefreshMarchFreeLogState();
    if (IsMarchFreeExhausted()) {
        WriteNoMarchFreeLogOnce();
        InterlockedExchange(&g_waitingNoRush, 1);
        return;
    }

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
        if (entry == 0) {
            continue;
        }

        const uint32_t state = ReadGameU32(entry + 0x1C);
        const uint32_t subState = ReadGameU32(entry + 0x20);
        const uint32_t flag44 = ReadGameU32(entry + 0x44);
        if (state == 4 ||
            state == 1 ||
            (state == 8 && subState == 5 && flag44 == 0)) {
            InterlockedExchange(&g_hasMoveReady, 1);
        }

        if (state != 2 || subState != 3) {
            continue;
        }
        InterlockedExchange(&g_hasWaiting, 1);

        uint32_t current = 0;
        uint32_t target = 0;
        if (!GetTarget(entry, current, target)) {
            WriteDashDiag(kDiagTargetMissing, current, target);
            continue;
        }

        if (g_slowLureSwitch != 0) {
            bool targetStateKnown = false;
            const bool targetIsFighting = WorldCityBattle::IsFighting(target, targetStateKnown);
            if (!targetStateKnown || targetIsFighting) {
                WriteDashDiag(kDiagTargetFightingOrUnknown, current, target);
                continue;
            }
        }

        const LONG lastCity = AlBattle::g_lastCity;
        if (lastCity != 0 && static_cast<uint32_t>(lastCity) != current) {
            WriteDashDiag(kDiagWrongCity, current, target);
        }

        if (!AlBattle::HasRushAdvantage()) {
            WriteDashDiag(kDiagCountNoRush, current, target);
            InterlockedExchange(&g_waitingNoRush, 1);
            continue;
        }

        BYTE* group = FindGroup(current);
        if (!group) {
            group = CreateGroup(entry, current, target);
        }
        if (group) {
            AddPayload(group, entry);
            WriteDashDiag(kDiagGroupCreated, current, target);
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
    ResetDashState();
    InterlockedExchange(&g_scanNextTick, static_cast<LONG>(GetTickCount() + kIdleScanMs));
    *reinterpret_cast<volatile uint32_t*>(g_mainBase + 0x230FE0) = 0;
    InterlockedExchange(&g_originalNextTick, 0);
    InterlockedExchange(&g_action, 1);
}

void AllowOriginalThrottled()
{
    const DWORD now = GetTickCount();
    if (now < static_cast<DWORD>(g_originalNextTick)) {
        InterlockedExchange(&g_action, 0);
        return;
    }

    InterlockedExchange(&g_originalNextTick, static_cast<LONG>(now + kIdleScanMs));
    InterlockedExchange(&g_action, 1);
}

void ScheduleNextIdleScan()
{
    InterlockedExchange(
        &g_scanNextTick,
        static_cast<LONG>(GetTickCount() + kIndependentScanMs));
}

void AdvanceToNextGroup()
{
    const LONG nextIndex = g_groupIndex + 1;
    InterlockedExchange(&g_groupIndex, nextIndex);
    if (nextIndex >= g_groupCount) {
        FinishAll();
        return;
    }
    SetNextPhase(5);
}

void Send1483(BYTE* group)
{
    RefreshMarchFreeLogState();
    if (IsMarchFreeExhausted()) {
        WriteNoMarchFreeLogOnce();
        FinishAll();
        return;
    }

    const uint32_t current = ReadGroupU32(group, 0x00);
    const uint32_t target = ReadGroupU32(group, 0x04);
    if (g_slowLureSwitch != 0) {
        bool targetStateKnown = false;
        const bool targetIsFighting = WorldCityBattle::IsFighting(target, targetStateKnown);
        if (!targetStateKnown || targetIsFighting) {
            WriteDashDiag(kDiagTargetFightingOrUnknown, current, target);
            AdvanceToNextGroup();
            return;
        }
    }

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
    if (AlBattle::g_marchFreeKnown != 0) {
        WriteMarchFreeBeforeDash();
    }
    WriteDashDiag(kDiagSend1483, ReadGroupU32(group, 0x00), ReadGroupU32(group, 0x04));
    SendPacketWithEcx(ReadGroupU32(group, 0x0C), 0x1483, g_dashBuffer, payloadLength);
    if (AlBattle::g_marchFreeKnown != 0 && AlBattle::g_marchFree > 0) {
        InterlockedDecrement(&AlBattle::g_marchFree);
    }

    InterlockedExchange(&g_nextTick, static_cast<LONG>(GetTickCount() + kFallbackCheckMs));
    InterlockedExchange(&g_phase, 6);
}

void Check1482(BYTE* group)
{
    uint32_t count = ReadGroupU32(group, 0x08);
    if (count > kMaxPayloadsPerGroup) {
        count = static_cast<uint32_t>(kMaxPayloadsPerGroup);
    }

    if (g_fallbackSwitch != 0 && count != 0) {
        const uint32_t current = ReadGroupU32(group, 0x00);
        bool allEntriesStillCurrent = true;
        for (uint32_t i = 0; i < count; ++i) {
            const uint32_t entry = ReadGroupU32(group, kEntryArrayOffset + i * sizeof(uint32_t));
            if (entry == 0 || ReadGameU16(entry + 0x30) != static_cast<uint16_t>(current)) {
                allEntriesStillCurrent = false;
                break;
            }
        }

        const uint32_t ecxValue = ReadGroupU32(group, 0x0C);
        if (allEntriesStillCurrent && ecxValue != 0) {
            RefreshMarchFreeLogState();
            if (IsMarchFreeExhausted()) {
                WriteNoRetreatMarchFreeLogOnce();
                WriteDashDiag(kDiagSkip1482, current, ReadGroupU32(group, 0x04));
            } else {
                WriteDashDiag(kDiagSend1482, current, ReadGroupU32(group, 0x04));
                SendPacketWithEcx(ecxValue, 0x1482, g_dashBuffer, count * 8 + 10);
                if (AlBattle::g_marchFreeKnown != 0 && AlBattle::g_marchFree > 0) {
                    InterlockedDecrement(&AlBattle::g_marchFree);
                }
            }
        } else {
            WriteDashDiag(kDiagSkip1482, current, ReadGroupU32(group, 0x04));
        }
    }

    AdvanceToNextGroup();
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
        WriteDashDiag(kDiagSend1467, ReadGroupU32(group, 0x00), ReadGroupU32(group, 0x04));
        SendPacketWithEcx(ecxValue, 0x1467, nullptr, 0);
        SetNextPhase(3);
        break;
    case 3:
        WriteDashDiag(kDiagSend31E6, ReadGroupU32(group, 0x00), ReadGroupU32(group, 0x04));
        SendPacketWithEcx(ecxValue, 0x31E6, nullptr, 0);
        SetNextPhase(4);
        break;
    case 4:
        Send1483(group);
        break;
    case 5:
        InterlockedExchange(&g_phase, 1);
        break;
    case 6:
        Check1482(group);
        break;
    default:
        InterlockedExchange(&g_phase, 0);
        InterlockedExchange(&g_action, 1);
        break;
    }
}

void DashTickImpl()
{
    StateFix();
    InterlockedExchange(&g_action, 0);
    if (ReadGameU32(g_mainBase + 0x230284) == 0) {
        InterlockedExchange(&g_showFlag, 0);
        ResetDashState();
        InterlockedExchange(&g_originalNextTick, 0);
        InterlockedExchange(&g_action, 1);
        return;
    }

    if (g_showFlag == 0) {
        ShowOptions();
    }

    if (ReadGameU32(g_mainBase + 0x23040C) == 0 || g_lureSwitch == 0) {
        ResetDashState();
        InterlockedExchange(&g_originalNextTick, 0);
        InterlockedExchange(&g_action, 1);
        return;
    }

    if (g_phase == 0) {
        const DWORD now = GetTickCount();
        if (now < static_cast<DWORD>(g_scanNextTick)) {
            AllowOriginalThrottled();
            return;
        }

        BuildGroups();
        if (g_groupCount == 0) {
            ScheduleNextIdleScan();
            if (g_waitingNoRush == 1 || g_hasWaiting == 1) {
                WriteDashDiag(kDiagAllowOriginalWaiting, 0, 0);
                ResetDashState();
                ScheduleNextIdleScan();
                InterlockedExchange(&g_action, 1);
                return;
            }
            if (g_hasMoveReady == 1) {
                WriteDashDiag(kDiagAllowOriginalMove, 0, 0);
                AllowOriginalThrottled();
                return;
            }
            if (ReadGameU32(g_mainBase + 0x2303E8) != 0) {
                WriteDashDiag(kDiagAllowOriginalMove, 0, 0);
                AllowOriginalThrottled();
                return;
            }
            WriteDashDiag(kDiagBlockOriginal, 0, 0);
            InterlockedExchange(&g_action, 0);
            return;
        }
    }

    SendCurrentPhase();
}

void RecordDashTickDuration(DWORD elapsed)
{
    InterlockedExchange(&g_dashTickLastDurationMs, static_cast<LONG>(elapsed));
    LONG observed = g_dashTickMaxDurationMs;
    while (elapsed > static_cast<DWORD>(observed)) {
        const LONG previous = InterlockedCompareExchange(
            &g_dashTickMaxDurationMs,
            static_cast<LONG>(elapsed),
            observed);
        if (previous == observed) {
            break;
        }
        observed = previous;
    }
}

__declspec(noinline) void __stdcall DashTick()
{
    if (InterlockedCompareExchange(&g_dashTickRunning, 1, 0) != 0) {
        InterlockedIncrement(&g_dashTickSkipped);
        return;
    }

    const DWORD started = GetTickCount();
    __try {
        DashTickImpl();
    }
    __finally {
        RecordDashTickDuration(GetTickCount() - started);
        InterlockedExchange(&g_dashTickRunning, 0);
    }
}

DWORD IndependentTimerInterval()
{
    return g_phase != 0 ? kPhaseGapMs : kIndependentScanMs;
}

__declspec(noinline) void __stdcall EnsureIndependentTimer(void* owner)
{
    if (!owner) {
        return;
    }

    HWND hwnd = *reinterpret_cast<HWND*>(reinterpret_cast<uintptr_t>(owner) + 0x20);
    if (!hwnd || !IsWindow(hwnd)) {
        return;
    }

    if (g_independentTimerHwnd == hwnd) {
        return;
    }

    if (g_independentTimerHwnd && IsWindow(g_independentTimerHwnd)) {
        KillTimer(g_independentTimerHwnd, kIndependentTimerId);
    }

    g_independentTimerHwnd = nullptr;
    if (SetTimer(hwnd, kIndependentTimerId, kIndependentScanMs, nullptr) != 0) {
        g_independentTimerHwnd = hwnd;
    }
}

__declspec(noinline) void __stdcall IndependentTimerTick(void* owner)
{
    if (!owner) {
        return;
    }

    HWND hwnd = *reinterpret_cast<HWND*>(reinterpret_cast<uintptr_t>(owner) + 0x20);
    if (!hwnd || !IsWindow(hwnd)) {
        g_independentTimerHwnd = nullptr;
        return;
    }

    KillTimer(hwnd, kIndependentTimerId);
    DashTick();
    BattleToken::Tick();
    ZhaoXianNaKe::Tick();
    ActivityLogin::Tick();
    TeamBattleReward::Tick();
    DianFengZhuLu::Tick();
    HuanJing::Tick();
    NativeOptimization::Tick(g_mainBase);

    if (SetTimer(hwnd, kIndependentTimerId, IndependentTimerInterval(), nullptr) != 0) {
        g_independentTimerHwnd = hwnd;
    } else {
        g_independentTimerHwnd = nullptr;
    }
}

__declspec(noinline) void __stdcall IndependentTimerDispatch(void* owner, UINT_PTR timerId)
{
    if (timerId == kIndependentTimerId) {
        IndependentTimerTick(owner);
    } else if (timerId == AutoBattleOff::kTimerId) {
        AutoBattleOff::TimerTick(owner);
    }
}

bool BuildMainCode(uintptr_t base, CodeBuffer& code)
{
    const uint32_t action = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(&g_action));
    return AppendByte(code, 0x9C) &&
        AppendPushad(code) &&
        AppendRel32Instruction(code, 0xE8, reinterpret_cast<uintptr_t>(&TaskDispatch::SendTick)) &&
        AppendRel32Instruction(code, 0xE8, reinterpret_cast<uintptr_t>(&BattleToken::Tick)) &&
        AppendRel32Instruction(code, 0xE8, reinterpret_cast<uintptr_t>(&ZhaoXianNaKe::Tick)) &&
        AppendRel32Instruction(code, 0xE8, reinterpret_cast<uintptr_t>(&ActivityLogin::Tick)) &&
        AppendRel32Instruction(code, 0xE8, reinterpret_cast<uintptr_t>(&TeamBattleReward::Tick)) &&
        AppendRel32Instruction(code, 0xE8, reinterpret_cast<uintptr_t>(&DianFengZhuLu::Tick)) &&
        AppendRel32Instruction(code, 0xE8, reinterpret_cast<uintptr_t>(&HuanJing::Tick)) &&
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

bool BuildTimerDispatchCode(uintptr_t base, CodeBuffer& code)
{
    return AppendByte(code, 0x81) && AppendByte(code, 0x7C) && AppendByte(code, 0x24) && AppendByte(code, 0x04) &&
        AppendU32(code, static_cast<uint32_t>(kIndependentTimerId)) &&
        AppendJeShort(code, 0x0A) &&
        AppendByte(code, 0x81) && AppendByte(code, 0x7C) && AppendByte(code, 0x24) && AppendByte(code, 0x04) &&
        AppendU32(code, static_cast<uint32_t>(AutoBattleOff::kTimerId)) &&
        AppendJneShort(code, 0x13) &&
        AppendByte(code, 0x9C) &&
        AppendPushad(code) &&
        AppendByte(code, 0xFF) && AppendByte(code, 0x74) && AppendByte(code, 0x24) && AppendByte(code, 0x28) &&
        AppendByte(code, 0x51) &&
        AppendRel32Instruction(code, 0xE8, reinterpret_cast<uintptr_t>(&IndependentTimerDispatch)) &&
        AppendPopad(code) &&
        AppendByte(code, 0x9D) &&
        AppendByte(code, 0x33) && AppendByte(code, 0xC0) &&
        AppendRetImm16(code, 0x04) &&
        AppendOriginalFunctionPrologue(code) &&
        AppendRel32Instruction(code, 0xE9, base + 0x40325);
}

bool BuildTimerCode(uintptr_t base, CodeBuffer& code)
{
    return AppendRel32Instruction(code, 0xE8, base + 0x351F0) &&
        AppendByte(code, 0x9C) &&
        AppendPushad(code) &&
        AppendPushEdi(code) &&
        AppendRel32Instruction(code, 0xE8, reinterpret_cast<uintptr_t>(&EnsureIndependentTimer)) &&
        AppendPushEdi(code) &&
        AppendRel32Instruction(code, 0xE8, reinterpret_cast<uintptr_t>(&AutoBattleOff::EnsureTimer)) &&
        AppendPopad(code) &&
        AppendByte(code, 0x9D) &&
        AppendByte(code, 0x6A) && AppendByte(code, 0x00) &&
        AppendPushImm32(code, 0x4E20) &&
        AppendRel32Instruction(code, 0xE9, base + 0x403AF);
}

bool BuildConfigCode(uintptr_t base, CodeBuffer& code)
{
    const uint32_t readHits = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(&g_configReadHits));
    const uint32_t lastStrike = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(&g_configLastStrike));
    const uint32_t lureSwitch = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(&g_lureSwitch));
    const uint32_t lastLure = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(&g_configLastLure));
    const uint32_t fallbackSwitch = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(&g_fallbackSwitch));
    const uint32_t lastFallback = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(&g_configLastFallback));
    const uint32_t slowLureSwitch = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(&g_slowLureSwitch));
    const uint32_t lastSlowLure = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(&g_configLastSlowLure));

    return AppendByte(code, 0xFF) && AppendByte(code, 0xD6) &&
        AppendIncDwordPtrAbs(code, readHits) &&
        AppendMovDwordPtrAbsEax(code, lastStrike) &&
        AppendMovDwordPtrEbxOffsetEax(code, 0x24) &&
        AppendPushEdi(code) &&
        AppendByte(code, 0x6A) && AppendByte(code, 0x00) &&
        AppendPushImm32(code, static_cast<uint32_t>(reinterpret_cast<uintptr_t>(kLureKey))) &&
        AppendPushImm32(code, static_cast<uint32_t>(reinterpret_cast<uintptr_t>(kConfigSection))) &&
        AppendByte(code, 0xFF) && AppendByte(code, 0xD6) &&
        AppendMovDwordPtrAbsEax(code, lureSwitch) &&
        AppendMovDwordPtrAbsEax(code, lastLure) &&
        AppendPushEdi(code) &&
        AppendByte(code, 0x6A) && AppendByte(code, 0x00) &&
        AppendPushImm32(code, static_cast<uint32_t>(reinterpret_cast<uintptr_t>(kFallbackKey))) &&
        AppendPushImm32(code, static_cast<uint32_t>(reinterpret_cast<uintptr_t>(kConfigSection))) &&
        AppendByte(code, 0xFF) && AppendByte(code, 0xD6) &&
        AppendMovDwordPtrAbsEax(code, fallbackSwitch) &&
        AppendMovDwordPtrAbsEax(code, lastFallback) &&
        AppendPushEdi(code) &&
        AppendByte(code, 0x6A) && AppendByte(code, 0x01) &&
        AppendPushImm32(code, static_cast<uint32_t>(reinterpret_cast<uintptr_t>(kSlowLureKey))) &&
        AppendPushImm32(code, static_cast<uint32_t>(reinterpret_cast<uintptr_t>(kConfigSection))) &&
        AppendByte(code, 0xFF) && AppendByte(code, 0xD6) &&
        AppendMovDwordPtrAbsEax(code, slowLureSwitch) &&
        AppendMovDwordPtrAbsEax(code, lastSlowLure) &&
        AppendMovEaxDwordPtrAbs(code, lastStrike) &&
        AppendPopEdi(code) &&
        AppendPopEsi(code) &&
        AppendRel32Instruction(code, 0xE9, base + 0x4B7A2);
}

bool BuildTotalOnCode(uintptr_t base, CodeBuffer& code)
{
    const uint32_t showFlag = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(&g_showFlag));
    return AppendMovDwordAbsImm32(code, showFlag, 0) &&
        AppendPushEdi(code) &&
        AppendMovEdiEcx(code) &&
        AppendByte(code, 0x6A) && AppendByte(code, 0x00) &&
        AppendRel32Instruction(code, 0xE9, base + 0x401E5);
}

bool BuildResumeCode(uintptr_t base, CodeBuffer& code)
{
    const uint32_t showFlag = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(&g_showFlag));
    return AppendMovDwordAbsImm32(code, showFlag, 0) &&
        AppendPushEdi(code) &&
        AppendByte(code, 0x6A) && AppendByte(code, 0x04) &&
        AppendMovEdiEcx(code) &&
        AppendRel32Instruction(code, 0xE9, base + 0x412F5);
}

}

namespace LureSwitchUi
{
constexpr UINT kRushCheckboxId = 0x7B01;
constexpr UINT kRetreatCheckboxId = 0x7B02;
constexpr UINT kSlowLureCheckboxId = 0x7B03;
constexpr UINT kCloseAutoCheckboxId = 0x7B04;
constexpr UINT kPrivateMessage = 0x87B1;
constexpr UINT kTimerId = 0x87B3;

volatile LONG g_started = 0;
volatile LONG g_writeHits = 0;
volatile LONG g_writeFailures = 0;
volatile LONG g_defaultCreateHits = 0;
volatile LONG g_slowLureKeyReady = 0;
volatile LONG g_closeAutoKeyReady = 0;
HWND g_settingsHwnd = nullptr;
HWND g_parentHwnd = nullptr;
HWND g_lureAnchorHwnd = nullptr;
HWND g_killBoxAnchorHwnd = nullptr;
HWND g_rushCheckboxHwnd = nullptr;
HWND g_retreatCheckboxHwnd = nullptr;
HWND g_slowLureCheckboxHwnd = nullptr;
HWND g_closeAutoCheckboxHwnd = nullptr;
WNDPROC g_oldProc = nullptr;
int g_rushX = 0;
int g_y = 0;
int g_killBoxY = 0;
int g_w = 0;
int g_h = 0;

const wchar_t kSettingsTitle[] = L"\x8A2D\x7F6E";
const wchar_t kLureAnchorText[] = L"\x51FA\x64CA\x8A98\x6575";
const wchar_t kKillBoxAnchorText[] = L"\x64CA\x6BBA\x5BF6\x7BB1";
const wchar_t kRushText[] = L"\x7A81\x9032";
const wchar_t kRetreatText[] = L"\x64A4\x9000";
const wchar_t kSlowLureText[] = L"\x6162\x7A81\x9032";
const wchar_t kCloseAutoText[] = L"\x95DC\x81EA\x52D5";

bool TryGetConfigPath(const wchar_t** pathOut)
{
    if (g_mainBase == 0 || !pathOut) {
        return false;
    }

    const uint32_t pathAddress = ReadGameU32(g_mainBase + 0x230280);
    if (pathAddress == 0) {
        return false;
    }

    const wchar_t* path = reinterpret_cast<const wchar_t*>(static_cast<uintptr_t>(pathAddress));
    __try {
        const uint32_t pathLength = *(reinterpret_cast<const uint32_t*>(path) - 3);
        if (pathLength == 0 || pathLength >= 1024 || path[pathLength] != L'\0') {
            return false;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }

    *pathOut = path;
    return true;
}

bool PersistSwitch(const wchar_t* key, LONG value)
{
    const wchar_t* path = nullptr;
    if (!key || !TryGetConfigPath(&path)) {
        InterlockedIncrement(&g_writeFailures);
        return false;
    }

    __try {
        const wchar_t* text = value != 0 ? L"1" : L"0";
        if (!WritePrivateProfileStringW(AutoLureDash::kConfigSection, key, text, path)) {
            InterlockedIncrement(&g_writeFailures);
            return false;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        InterlockedIncrement(&g_writeFailures);
        return false;
    }

    InterlockedIncrement(&g_writeHits);
    return true;
}

bool EnsureSwitchKey(const wchar_t* key, LONG defaultValue)
{
    const wchar_t* path = nullptr;
    if (!key || !TryGetConfigPath(&path)) {
        InterlockedIncrement(&g_writeFailures);
        return false;
    }

    __try {
        wchar_t value[16]{};
        const wchar_t missingMarker[] = { 0xFFFF, 0x0000 };
        const DWORD length = GetPrivateProfileStringW(
            AutoLureDash::kConfigSection,
            key,
            missingMarker,
            value,
            static_cast<DWORD>(sizeof(value) / sizeof(value[0])),
            path);
        const bool missing = length == 0 ||
            (length == 1 && value[0] == missingMarker[0] && value[1] == L'\0');
        if (!missing) {
            return true;
        }

        const wchar_t* defaultText = defaultValue != 0 ? L"1" : L"0";
        if (!WritePrivateProfileStringW(AutoLureDash::kConfigSection, key, defaultText, path)) {
            InterlockedIncrement(&g_writeFailures);
            return false;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        InterlockedIncrement(&g_writeFailures);
        return false;
    }

    InterlockedIncrement(&g_writeHits);
    InterlockedIncrement(&g_defaultCreateHits);
    return true;
}

void EnsureSlowLureKeyReady()
{
    if (g_slowLureKeyReady != 0) {
        return;
    }

    if (EnsureSwitchKey(AutoLureDash::kSlowLureKey, 1)) {
        InterlockedExchange(&g_slowLureKeyReady, 1);
    }
}

void EnsureCloseAutoKeyReady()
{
    if (g_closeAutoKeyReady != 0) {
        return;
    }

    if (!EnsureSwitchKey(AutoBattleOff::kConfigKey, 0)) {
        return;
    }

    const wchar_t* path = nullptr;
    if (!TryGetConfigPath(&path)) {
        return;
    }

    const LONG value = GetPrivateProfileIntW(
        AutoLureDash::kConfigSection,
        AutoBattleOff::kConfigKey,
        0,
        path) != 0 ? 1 : 0;
    InterlockedExchange(&AutoBattleOff::g_enabled, value);
    AutoBattleOff::ResetSchedule();
    if (value != 0) {
        AutoBattleOff::StartTimer();
    } else {
        AutoBattleOff::StopTimer();
    }
    InterlockedExchange(&g_closeAutoKeyReady, 1);
}

void ApplyButtonStates()
{
    EnsureSlowLureKeyReady();
    EnsureCloseAutoKeyReady();

    if (g_rushCheckboxHwnd && IsWindow(g_rushCheckboxHwnd)) {
        SendMessageW(
            g_rushCheckboxHwnd,
            BM_SETCHECK,
            AutoLureDash::g_lureSwitch != 0 ? BST_CHECKED : BST_UNCHECKED,
            0);
    }
    if (g_retreatCheckboxHwnd && IsWindow(g_retreatCheckboxHwnd)) {
        SendMessageW(
            g_retreatCheckboxHwnd,
            BM_SETCHECK,
            AutoLureDash::g_fallbackSwitch != 0 ? BST_CHECKED : BST_UNCHECKED,
            0);
    }
    if (g_slowLureCheckboxHwnd && IsWindow(g_slowLureCheckboxHwnd)) {
        SendMessageW(
            g_slowLureCheckboxHwnd,
            BM_SETCHECK,
            AutoLureDash::g_slowLureSwitch != 0 ? BST_CHECKED : BST_UNCHECKED,
            0);
    }
    if (g_closeAutoCheckboxHwnd && IsWindow(g_closeAutoCheckboxHwnd)) {
        SendMessageW(
            g_closeAutoCheckboxHwnd,
            BM_SETCHECK,
            AutoBattleOff::g_enabled != 0 ? BST_CHECKED : BST_UNCHECKED,
            0);
    }
}

void SyncSwitchFromButton(UINT controlId)
{
    if (controlId == kRushCheckboxId && g_rushCheckboxHwnd && IsWindow(g_rushCheckboxHwnd)) {
        const LONG value = SendMessageW(g_rushCheckboxHwnd, BM_GETCHECK, 0, 0) != 0 ? 1 : 0;
        InterlockedExchange(&AutoLureDash::g_lureSwitch, value);
        InterlockedExchange(&AutoLureDash::g_configLastLure, value);
        InterlockedExchange(&AutoLureDash::g_showFlag, 0);
        PersistSwitch(AutoLureDash::kLureKey, value);
    } else if (controlId == kRetreatCheckboxId && g_retreatCheckboxHwnd && IsWindow(g_retreatCheckboxHwnd)) {
        const LONG value = SendMessageW(g_retreatCheckboxHwnd, BM_GETCHECK, 0, 0) != 0 ? 1 : 0;
        InterlockedExchange(&AutoLureDash::g_fallbackSwitch, value);
        InterlockedExchange(&AutoLureDash::g_configLastFallback, value);
        InterlockedExchange(&AutoLureDash::g_showFlag, 0);
        PersistSwitch(AutoLureDash::kFallbackKey, value);
    } else if (controlId == kSlowLureCheckboxId && g_slowLureCheckboxHwnd && IsWindow(g_slowLureCheckboxHwnd)) {
        const LONG value = SendMessageW(g_slowLureCheckboxHwnd, BM_GETCHECK, 0, 0) != 0 ? 1 : 0;
        InterlockedExchange(&AutoLureDash::g_slowLureSwitch, value);
        InterlockedExchange(&AutoLureDash::g_configLastSlowLure, value);
        if (PersistSwitch(AutoLureDash::kSlowLureKey, value)) {
            InterlockedExchange(&g_slowLureKeyReady, 1);
        }
    } else if (controlId == kCloseAutoCheckboxId && g_closeAutoCheckboxHwnd && IsWindow(g_closeAutoCheckboxHwnd)) {
        const LONG value = SendMessageW(g_closeAutoCheckboxHwnd, BM_GETCHECK, 0, 0) != 0 ? 1 : 0;
        InterlockedExchange(&AutoBattleOff::g_enabled, value);
        if (value != 0) {
            AutoBattleOff::ResetSchedule();
            AutoBattleOff::StartTimer();
        } else {
            AutoBattleOff::StopTimer();
        }
        if (PersistSwitch(AutoBattleOff::kConfigKey, value)) {
            InterlockedExchange(&g_closeAutoKeyReady, 1);
        }
    }
}

LRESULT CALLBACK ParentWndProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam)
{
    if (message == WM_COMMAND) {
        const UINT controlId = LOWORD(wParam);
        if ((controlId == kRushCheckboxId || controlId == kRetreatCheckboxId ||
             controlId == kSlowLureCheckboxId || controlId == kCloseAutoCheckboxId) &&
            HIWORD(wParam) == BN_CLICKED) {
            SyncSwitchFromButton(controlId);
        }
    }

    if (message == WM_TIMER && wParam == kTimerId) {
        ApplyButtonStates();
        return 1;
    }

    if (message == kPrivateMessage && wParam == 1) {
        EnsureSwitchKey(AutoLureDash::kLureKey, 0);
        EnsureSwitchKey(AutoLureDash::kFallbackKey, 0);
        EnsureSlowLureKeyReady();
        EnsureCloseAutoKeyReady();
        if (!g_rushCheckboxHwnd) {
            g_rushCheckboxHwnd = CreateWindowExW(
                0,
                L"Button",
                kRushText,
                0x50018003,
                g_rushX,
                g_y,
                g_w,
                g_h,
                g_parentHwnd,
                reinterpret_cast<HMENU>(static_cast<UINT_PTR>(kRushCheckboxId)),
                nullptr,
                nullptr);
        }
        if (!g_retreatCheckboxHwnd) {
            g_retreatCheckboxHwnd = CreateWindowExW(
                0,
                L"Button",
                kRetreatText,
                0x50018003,
                g_rushX + g_w + 6,
                g_y,
                g_w,
                g_h,
                g_parentHwnd,
                reinterpret_cast<HMENU>(static_cast<UINT_PTR>(kRetreatCheckboxId)),
                nullptr,
                nullptr);
        }
        if (!g_slowLureCheckboxHwnd) {
            g_slowLureCheckboxHwnd = CreateWindowExW(
                0,
                L"Button",
                kSlowLureText,
                0x50018003,
                g_rushX + (g_w + 6) * 2,
                g_y,
                g_w,
                g_h,
                g_parentHwnd,
                reinterpret_cast<HMENU>(static_cast<UINT_PTR>(kSlowLureCheckboxId)),
                nullptr,
                nullptr);
        }
        if (!g_closeAutoCheckboxHwnd) {
            g_closeAutoCheckboxHwnd = CreateWindowExW(
                0,
                L"Button",
                kCloseAutoText,
                0x50018003,
                g_rushX + g_w + 6,
                g_killBoxY,
                g_w,
                g_h,
                g_parentHwnd,
                reinterpret_cast<HMENU>(static_cast<UINT_PTR>(kCloseAutoCheckboxId)),
                nullptr,
                nullptr);
        }

        HFONT font = reinterpret_cast<HFONT>(SendMessageW(g_lureAnchorHwnd, WM_GETFONT, 0, 0));
        if (font) {
            if (g_rushCheckboxHwnd) {
                SendMessageW(g_rushCheckboxHwnd, WM_SETFONT, reinterpret_cast<WPARAM>(font), TRUE);
            }
            if (g_retreatCheckboxHwnd) {
                SendMessageW(g_retreatCheckboxHwnd, WM_SETFONT, reinterpret_cast<WPARAM>(font), TRUE);
            }
            if (g_slowLureCheckboxHwnd) {
                SendMessageW(g_slowLureCheckboxHwnd, WM_SETFONT, reinterpret_cast<WPARAM>(font), TRUE);
            }
            if (g_closeAutoCheckboxHwnd) {
                SendMessageW(g_closeAutoCheckboxHwnd, WM_SETFONT, reinterpret_cast<WPARAM>(font), TRUE);
            }
        }

        ApplyButtonStates();
        if (g_rushCheckboxHwnd) {
            ShowWindow(g_rushCheckboxHwnd, SW_SHOW);
        }
        if (g_retreatCheckboxHwnd) {
            ShowWindow(g_retreatCheckboxHwnd, SW_SHOW);
        }
        if (g_slowLureCheckboxHwnd) {
            ShowWindow(g_slowLureCheckboxHwnd, SW_SHOW);
        }
        if (g_closeAutoCheckboxHwnd) {
            ShowWindow(g_closeAutoCheckboxHwnd, SW_SHOW);
        }
        SetTimer(g_parentHwnd, kTimerId, 1000, nullptr);
        return 1;
    }

    return g_oldProc ? CallWindowProcW(g_oldProc, hwnd, message, wParam, lParam)
                     : DefWindowProcW(hwnd, message, wParam, lParam);
}

BOOL CALLBACK EnumChildProc(HWND hwnd, LPARAM)
{
    wchar_t text[64]{};
    GetWindowTextW(hwnd, text, static_cast<int>(sizeof(text) / sizeof(text[0])));
    if (std::wcscmp(text, kLureAnchorText) == 0) {
        g_lureAnchorHwnd = hwnd;
    } else if (std::wcscmp(text, kKillBoxAnchorText) == 0) {
        g_killBoxAnchorHwnd = hwnd;
    }
    return TRUE;
}

bool FindAndInstall()
{
    g_settingsHwnd = FindWindowW(nullptr, kSettingsTitle);
    if (!g_settingsHwnd) {
        return false;
    }

    g_lureAnchorHwnd = nullptr;
    g_killBoxAnchorHwnd = nullptr;
    EnumChildWindows(g_settingsHwnd, EnumChildProc, 0);
    if (!g_lureAnchorHwnd) {
        return false;
    }

    g_parentHwnd = GetParent(g_lureAnchorHwnd);
    if (!g_parentHwnd) {
        return false;
    }

    RECT lureRect{};
    if (!GetWindowRect(g_lureAnchorHwnd, &lureRect)) {
        return false;
    }
    POINT lurePoint{ lureRect.left, lureRect.top };
    ScreenToClient(g_parentHwnd, &lurePoint);
    g_y = lurePoint.y;
    g_w = lureRect.right - lureRect.left;
    g_h = lureRect.bottom - lureRect.top;
    g_rushX = lurePoint.x + g_w + 6;
    g_killBoxY = g_y + g_h + 6;

    if (g_killBoxAnchorHwnd) {
        RECT killBoxRect{};
        if (GetWindowRect(g_killBoxAnchorHwnd, &killBoxRect)) {
            POINT killBoxPoint{ killBoxRect.left, killBoxRect.top };
            ScreenToClient(g_parentHwnd, &killBoxPoint);
            g_rushX = killBoxPoint.x;
            g_killBoxY = killBoxPoint.y;
        }
    }

    g_oldProc = reinterpret_cast<WNDPROC>(
        SetWindowLongPtrW(g_parentHwnd, GWLP_WNDPROC, reinterpret_cast<LONG_PTR>(ParentWndProc)));
    if (!g_oldProc) {
        return false;
    }

    SendMessageW(g_parentHwnd, kPrivateMessage, 1, 0);
    return g_rushCheckboxHwnd && g_retreatCheckboxHwnd;
}

DWORD WINAPI SetupThread(LPVOID)
{
    for (int i = 0; i < 50; ++i) {
        if (FindAndInstall()) {
            return 0;
        }
        Sleep(100);
    }
    return 0;
}

void Start()
{
    if (InterlockedCompareExchange(&g_started, 1, 0) != 0) {
        return;
    }
    HANDLE thread = CreateThread(nullptr, 0, SetupThread, nullptr, 0, nullptr);
    if (thread) {
        CloseHandle(thread);
    }
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
    GameLog::RefreshCurrent();
}

void WriteStatusLog()
{
    const LONG current = static_cast<LONG>(ReadGameU32(g_mainBase + 0x230970));
    const LONG allowed = g_allowedRoom;
    const LONG maxRoom = g_maxRoom;
    if (allowed != maxRoom) {
        const LONG nextRoom = maxRoom + 1;
        const wchar_t* message = kLogFullGo;
        if (current >= maxRoom) {
            message = kLogAtBest;
        }
        GameLog::Write(kLogFullFormat, g_level, current, allowed, maxRoom, nextRoom, allowed, message);
    } else {
        const wchar_t* message = current < maxRoom ? kLogGoMax : kLogAtMax;
        GameLog::Write(kLogFormat, g_level, current, allowed, maxRoom, message);
    }
}

void WriteActionLog()
{
    GameLog::Write(kLogActionFormat, g_blockRoom, g_blockSlot);
}

__declspec(noinline) void __stdcall MainHook()
{
    if (g_enabled == 0 || ReadGameU32(g_mainBase + 0x23033C) == 0) {
        return;
    }

    CalcLevelMax();
    if (g_fastSent != 0) {
        const LONG currentRoom = static_cast<LONG>(ReadGameU32(g_mainBase + 0x230970));
        if (currentRoom >= g_fastRoom) {
            InterlockedExchange(&g_fastSent, 0);
            InterlockedExchange(&g_fastRoom, 0);
            InterlockedExchange(&g_fastSlot, 0);
        }
    }

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

void Send3970(uint32_t room, uint32_t slot)
{
    using Send3970Fn = void(__stdcall*)(uint32_t, uint32_t);
    Send3970Fn send3970 = reinterpret_cast<Send3970Fn>(g_mainBase + 0x4AC90);
    send3970(room, slot);
}

__declspec(noinline) void __stdcall Slot396FHook(uint32_t slot, uintptr_t roomEntry, const BYTE* payload)
{
    if (!payload || roomEntry == 0 || payload[4] != 1) {
        return;
    }

    *reinterpret_cast<volatile uint32_t*>(roomEntry + 0x18) = slot;
    const uint32_t room = ReadGameU32(roomEntry + 0x04);
    InterlockedExchange(&g_fastSlot, static_cast<LONG>(slot));
    InterlockedExchange(&g_fastRoom, static_cast<LONG>(room));

    if (g_enabled == 0 || ReadGameU32(g_mainBase + 0x23033C) == 0) {
        return;
    }

    if (g_fastSent == 0) {
        CalcLevelMax();
        if (static_cast<LONG>(room) <= g_maxRoom) {
            InterlockedExchange(&g_fastSent, 1);
            Send3970(room, slot);
        }
    }

    if (g_fastSent != 0) {
        *reinterpret_cast<volatile uint32_t*>(roomEntry + 0x18) = 0;
        *reinterpret_cast<volatile uint32_t*>(roomEntry) = 1;
    }
}

__declspec(noinline) void __stdcall Guard396DHook(uint32_t room)
{
    g_blockRoom = static_cast<LONG>(room);
    g_shouldBlock = 0;
    if (g_enabled == 0) {
        return;
    }

    CalcLevelMax();
    if (static_cast<LONG>(room) > g_maxRoom) {
        g_shouldBlock = 1;
    }
}

__declspec(noinline) void __stdcall Guard3970Hook(uint32_t room, uint32_t slot)
{
    g_blockRoom = static_cast<LONG>(room);
    g_blockSlot = static_cast<LONG>(slot);
    g_shouldBlock = 0;
    if (g_enabled == 0) {
        return;
    }

    CalcLevelMax();
    if (static_cast<LONG>(room) > g_maxRoom) {
        g_shouldBlock = 1;
        return;
    }

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

bool Build396FSlotCode(uintptr_t base, CodeBuffer& code)
{
    return AppendPushad(code) &&
        AppendPushEsi(code) &&
        AppendPushEbx(code) &&
        AppendPushEax(code) &&
        AppendRel32Instruction(code, 0xE8, reinterpret_cast<uintptr_t>(&Slot396FHook)) &&
        AppendPopad(code) &&
        AppendRel32Instruction(code, 0xE9, base + 0x48581);
}

bool Build396DCode(uintptr_t base, CodeBuffer& code)
{
    return AppendPushad(code) &&
        AppendPushDwordPtrEspOffset(code, 0x24) &&
        AppendRel32Instruction(code, 0xE8, reinterpret_cast<uintptr_t>(&Guard396DHook)) &&
        AppendPopad(code) &&
        AppendCmpDwordAbsImm8(code, static_cast<uint32_t>(reinterpret_cast<uintptr_t>(&g_shouldBlock)), 0) &&
        AppendJneShort(code, 0x0B) &&
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
        AppendJneShort(code, 0x0B) &&
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
    GameLog::Write(kDailySignLogFormat, text);
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
    GameLog::Write(kLogFormat, text);
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

    InterlockedIncrement(&g_router3Ea4Hits);
    InterlockedExchange(&g_id, static_cast<LONG>(BuildPayload(ReadU32Unaligned(payload))));
    InterlockedExchange(&g_count, static_cast<LONG>(payload[0x215]));
    InterlockedExchange(&g_state, static_cast<LONG>(payload[0x21A]));
    const LONG switchValue = static_cast<LONG>(ReadGameU32(g_mainBase + 0x230388));
    InterlockedExchange(&g_routerSwitchSeen, switchValue);
    if (switchValue != 0) {
        InterlockedExchange(&g_pending, 1);
        InterlockedIncrement(&g_routerPendingSets);
    }
    InterlockedExchange(&SharedRecvRouter::g_clearStackArg, 1);
}

__declspec(noinline) void __stdcall SendHook()
{
    if (ReadGameU32(g_mainBase + 0x230388) == 0) {
        InterlockedExchange(&g_pending, 0);
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

    if (g_pending == 0) {
        return;
    }

    if ((static_cast<BYTE>(g_state) == 0xFF)) {
        if (g_count == 0) {
            return;
        }

        SendAction(1);
        SendAction(2);
        InterlockedExchange(&g_count, 0);
        InterlockedExchange(&g_pending, 0);
        WriteLog(kLogCase);
        return;
    }

    SendAction(2);
    InterlockedExchange(&g_pending, 0);
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
    GameLog::RefreshCurrent();
}

void WriteRecvLog()
{
    GameLog::Write(kRecvLogFormat, static_cast<uint32_t>(g_activity));
}

void WriteRewardLog()
{
    GameLog::Write(kRewardLogFormat, static_cast<uint32_t>(g_rewardNextIndex));
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

namespace Jrnt
{

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

void RefreshLog()
{
    GameLog::RefreshCurrent();
}

void WriteLog(const wchar_t* text)
{
    GameLog::Write(reinterpret_cast<const wchar_t*>(g_mainBase + 0x1FE56C), text);
}

void ResetState()
{
    InterlockedExchange(&g_pendingOpen, 0);
    InterlockedExchange(&g_bribeTaskActive, 0);
    InterlockedExchange(&g_bribeTaskTarget, 0);
    InterlockedExchange(&g_bribeTaskSchedule, 0);
    for (size_t i = 0; i < 3; ++i) {
        g_ids[i] = 0xFFFFFFFF;
        g_claimPending[i] = 0;
    }
}

void SendQuery()
{
    SendPacketWithEcx(static_cast<uint32_t>(g_this), 0x4F34, &g_payloadZero, 0);
}

void SendOpen()
{
    SendPacketWithEcx(static_cast<uint32_t>(g_this), 0x4F37, &g_payload4F37, 1);
}

void SendClaim(uint32_t id)
{
    g_payload4F36 = 0;
    BYTE* const payload = reinterpret_cast<BYTE*>(&g_payload4F36);
    payload[0] = static_cast<BYTE>((id >> 24) & 0xFF);
    payload[1] = static_cast<BYTE>((id >> 16) & 0xFF);
    payload[2] = static_cast<BYTE>((id >> 8) & 0xFF);
    payload[3] = static_cast<BYTE>(id & 0xFF);
    SendPacketWithEcx(static_cast<uint32_t>(g_this), 0x4F36, &g_payload4F36, sizeof(g_payload4F36));
}

void Tick()
{
    InterlockedExchange(&g_didWork, 0);

    if (g_pendingOpen == 1) {
        WriteLog(kLogOpen);
        SendOpen();
        InterlockedExchange(&g_pendingOpen, 0);
        InterlockedExchange(&g_didWork, 1);
        return;
    }

    for (size_t i = 0; i < 3; ++i) {
        if (g_claimPending[i] != 1) {
            continue;
        }

        WriteLog(kLogClaim);
        SendClaim(g_ids[i]);
        g_claimPending[i] = 0;
        InterlockedExchange(&g_didWork, 1);
        return;
    }
}

uint16_t ReadBe16(const BYTE* data)
{
    return static_cast<uint16_t>((static_cast<uint16_t>(data[0]) << 8) | data[1]);
}

uint32_t ReadBe32(const BYTE* data)
{
    return (static_cast<uint32_t>(data[0]) << 24) |
        (static_cast<uint32_t>(data[1]) << 16) |
        (static_cast<uint32_t>(data[2]) << 8) |
        static_cast<uint32_t>(data[3]);
}

bool SkipUtf(const BYTE*& cursor, const BYTE* end)
{
    if (cursor + 2 > end) {
        return false;
    }
    const uint16_t length = ReadBe16(cursor);
    cursor += 2;
    if (cursor + length > end) {
        return false;
    }
    cursor += length;
    return true;
}

bool ReadUtfView(const BYTE*& cursor, const BYTE* end, const BYTE*& text, uint16_t& length)
{
    if (cursor + 2 > end) {
        return false;
    }

    length = ReadBe16(cursor);
    cursor += 2;
    if (cursor + length > end) {
        return false;
    }

    text = cursor;
    cursor += length;
    return true;
}

bool BytesEqual(const BYTE* text, uint16_t length, const BYTE* expected, size_t expectedLength)
{
    return text && length == expectedLength && std::memcmp(text, expected, expectedLength) == 0;
}

bool BytesContain(const BYTE* text, uint16_t length, const BYTE* needle, size_t needleLength)
{
    if (!text || !needle || needleLength == 0 || length < needleLength) {
        return false;
    }

    const size_t lastOffset = static_cast<size_t>(length) - needleLength;
    for (size_t offset = 0; offset <= lastOffset; ++offset) {
        if (std::memcmp(text + offset, needle, needleLength) == 0) {
            return true;
        }
    }
    return false;
}

bool ParseAsciiUInt(const BYTE* text, uint16_t length, uint32_t& value)
{
    if (!text || length == 0) {
        return false;
    }

    uint32_t parsed = 0;
    for (uint16_t i = 0; i < length; ++i) {
        const BYTE ch = text[i];
        if (ch < '0' || ch > '9') {
            return false;
        }

        const uint32_t digit = static_cast<uint32_t>(ch - '0');
        if (parsed > (0x7FFFFFFFu - digit) / 10u) {
            return false;
        }
        parsed = parsed * 10u + digit;
    }

    value = parsed;
    return true;
}

void HandleRecvPacket(uint32_t opcode, const BYTE* payload, uint32_t payloadLength)
{
    if ((opcode & 0xFFFF) != 0x4F35 || !payload || payloadLength < 4) {
        return;
    }

    InterlockedExchange(&g_pendingOpen, 0);
    InterlockedExchange(&g_bribeTaskActive, 0);
    InterlockedExchange(&g_bribeTaskTarget, 0);
    InterlockedExchange(&g_bribeTaskSchedule, 0);
    for (size_t i = 0; i < 3; ++i) {
        g_ids[i] = 0xFFFFFFFF;
        g_claimPending[i] = 0;
    }

    const BYTE* cursor = payload;
    const BYTE* const end = payload + payloadLength;
    const uint32_t boxCount = ReadBe32(cursor);
    cursor += 4;
    if (boxCount != 0) {
        InterlockedExchange(&g_pendingOpen, 1);
    }

    if (cursor + 2 > end) {
        return;
    }
    const uint16_t taskCount = ReadBe16(cursor);
    cursor += 2;

    size_t pendingIndex = 0;
    bool bribeTaskActive = false;
    uint32_t bribeTaskTarget = 0;
    uint32_t bribeTaskSchedule = 0;
    for (uint16_t task = 0; task < taskCount; ++task) {
        if (cursor + 4 > end) {
            return;
        }
        const uint32_t taskId = ReadBe32(cursor);
        cursor += 4;

        const BYTE* taskName = nullptr;
        const BYTE* taskDescription = nullptr;
        const BYTE* taskTargetText = nullptr;
        const BYTE* taskScheduleText = nullptr;
        uint16_t taskNameLength = 0;
        uint16_t taskDescriptionLength = 0;
        uint16_t taskTargetLength = 0;
        uint16_t taskScheduleLength = 0;
        if (!ReadUtfView(cursor, end, taskName, taskNameLength) ||
            !ReadUtfView(cursor, end, taskDescription, taskDescriptionLength) ||
            !ReadUtfView(cursor, end, taskTargetText, taskTargetLength) ||
            !ReadUtfView(cursor, end, taskScheduleText, taskScheduleLength) ||
            cursor + 8 > end) {
            return;
        }

        cursor += 4; // rewardBox
        const uint32_t taskState = ReadBe32(cursor);
        cursor += 4;
        if (!SkipUtf(cursor, end)) {
            return;
        }

        const bool isBribeTask =
            BytesEqual(taskName, taskNameLength, kBribeTaskName, sizeof(kBribeTaskName)) ||
            BytesContain(taskDescription,
                taskDescriptionLength,
                kBribeTaskDescription,
                sizeof(kBribeTaskDescription));
        uint32_t parsedTarget = 0;
        uint32_t parsedSchedule = 0;
        if (isBribeTask &&
            ParseAsciiUInt(taskTargetText, taskTargetLength, parsedTarget) &&
            ParseAsciiUInt(taskScheduleText, taskScheduleLength, parsedSchedule)) {
            const bool thisTaskActive = parsedTarget > 0 && parsedSchedule < parsedTarget;
            if (thisTaskActive || !bribeTaskActive) {
                bribeTaskTarget = parsedTarget;
                bribeTaskSchedule = parsedSchedule;
            }
            bribeTaskActive = bribeTaskActive || thisTaskActive;
        }

        if (taskState == 1 && pendingIndex < 3) {
            g_ids[pendingIndex] = taskId;
            g_claimPending[pendingIndex] = 1;
            ++pendingIndex;
        }
    }

    if (!SkipUtf(cursor, end) || cursor != end) {
        return;
    }

    InterlockedExchange(&g_bribeTaskTarget, static_cast<LONG>(bribeTaskTarget));
    InterlockedExchange(&g_bribeTaskSchedule, static_cast<LONG>(bribeTaskSchedule));
    InterlockedIncrement(&g_bribeSnapshotGeneration);
    InterlockedExchange(&g_bribeTaskActive, bribeTaskActive ? 1 : 0);
}

bool ConsumeBribePermission()
{
    if (g_mainBase == 0 || ReadGameU32(g_mainBase + 0x230358) == 0) {
        return false;
    }
    if (InterlockedCompareExchange(&g_bribeTaskActive, 0, 0) != 1) {
        return false;
    }

    const LONG target = InterlockedCompareExchange(&g_bribeTaskTarget, 0, 0);
    const LONG schedule = InterlockedCompareExchange(&g_bribeTaskSchedule, 0, 0);
    if (target <= 0 || schedule < 0 || schedule >= target) {
        return false;
    }

    const LONG generation = InterlockedCompareExchange(&g_bribeSnapshotGeneration, 0, 0);
    const LONG consumed = InterlockedCompareExchange(&g_bribeConsumedGeneration, 0, 0);
    if (generation == 0 || consumed == generation) {
        return false;
    }

    return InterlockedCompareExchange(&g_bribeConsumedGeneration, generation, consumed) == consumed;
}

__declspec(noinline) void __stdcall RunNativeBribeIfAllowed()
{
    if (!ConsumeBribePermission()) {
        return;
    }

    using NativeBribeFn = void(__cdecl*)();
    NativeBribeFn nativeBribe = reinterpret_cast<NativeBribeFn>(g_mainBase + 0x39640);
    nativeBribe();
}

__declspec(noinline) void __stdcall SendHook()
{
    if (ReadGameU32(g_mainBase + 0x230358) == 0) {
        ResetState();
        return;
    }

    Tick();
    if (g_didWork == 1) {
        return;
    }

    SendQuery();
}

bool BuildSendCode(uintptr_t, CodeBuffer& code)
{
    return AppendMovDwordPtrAbsEcx(code, static_cast<uint32_t>(reinterpret_cast<uintptr_t>(&g_this))) &&
        AppendPushad(code) &&
        AppendRel32Instruction(code, 0xE8, reinterpret_cast<uintptr_t>(&SendHook)) &&
        AppendPopad(code) &&
        AppendByte(code, 0xC3);
}

bool BuildBribeGateCode(uintptr_t base, CodeBuffer& code)
{
    const BYTE expectedCall[] = { 0xE8, 0x82, 0x42, 0x00, 0x00 };
    if (std::memcmp(reinterpret_cast<const void*>(base + 0x353B9),
            expectedCall,
            sizeof(expectedCall)) != 0) {
        return false;
    }

    return AppendPushad(code) &&
        AppendRel32Instruction(code, 0xE8, reinterpret_cast<uintptr_t>(&RunNativeBribeIfAllowed)) &&
        AppendPopad(code) &&
        AppendRel32Instruction(code, 0xE9, base + 0x353BE);
}

}

namespace Xyfp
{

void SendPacket(uint32_t opcode, const void* payload, uint32_t payloadLength)
{
    using SendPacketFn = void(__stdcall*)(uint32_t, const void*, uint32_t);
    SendPacketFn sendPacket = reinterpret_cast<SendPacketFn>(g_mainBase + 0x4A360);
    sendPacket(opcode, payload, payloadLength);
}

void RefreshLog()
{
    GameLog::RefreshCurrent();
}

void WriteBattleLog()
{
    GameLog::Write(kLogBattleFormat, static_cast<uint32_t>(g_candidateStage));
}

void WriteSweepLog()
{
    GameLog::Write(kLogSweepFormat, 1);
}

void SendSweep()
{
    g_payload4C87[3] = static_cast<BYTE>(g_day);
    g_payload4C87[7] = 5;
    g_payload4C87[0x0B] = 1;
    WriteSweepLog();
    SendPacket(0x4C87, g_payload4C87, sizeof(g_payload4C87));
}

void SendBattle()
{
    g_payload4C86[3] = static_cast<BYTE>(g_day);
    g_payload4C86[7] = static_cast<BYTE>(g_candidateStage);
    g_payload145A[2] = static_cast<BYTE>(g_day);
    g_payload145A[3] = static_cast<BYTE>(g_candidateStage);
    std::memcpy(g_payload145A + 7, g_payload8s, sizeof(g_payload8s));
    WriteBattleLog();
    SendPacket(0x4C86, g_payload4C86, sizeof(g_payload4C86));
    SendPacket(0x145A, g_payload145A, sizeof(g_payload145A));
}

void ParsePayload(const BYTE* payload, uint32_t payloadLength)
{
    if (!payload || payloadLength < 15) {
        return;
    }

    InterlockedExchange(&g_day, payload[0x03]);
    InterlockedExchange(&g_stamina, payload[0x0E]);
    InterlockedExchange(&g_patternCount, 0);
    InterlockedExchange(&g_payload8Count, 0);
    InterlockedExchange(&g_candidateStage, 0);
    InterlockedExchange(&g_clearCount, 0);
    std::memset(g_payload8s, 0, sizeof(g_payload8s));

    const uint32_t scanLimit = payloadLength - 14;
    for (uint32_t offset = 0; offset <= scanLimit;) {
        const BYTE* cursor = payload + offset;
        if (ReadU32Unaligned(cursor) != 0x0000302E || cursor[4] != 0x27) {
            ++offset;
            continue;
        }

        const LONG patternIndex = g_patternCount;
        if (patternIndex >= static_cast<LONG>(kMaxPatterns)) {
            break;
        }

        InterlockedExchange(&g_patternCount, patternIndex + 1);
        std::memcpy(g_payload8s + patternIndex * 8, cursor, 8);
        InterlockedIncrement(&g_payload8Count);

        const BYTE after5 = cursor[9];
        if (after5 == 1) {
            InterlockedIncrement(&g_clearCount);
        }
        if (g_candidateStage == 0 && after5 == 0) {
            InterlockedExchange(&g_candidateStage, patternIndex + 1);
        }

        if (g_patternCount >= static_cast<LONG>(kMaxPatterns)) {
            break;
        }
        offset += 5;
    }

    if (g_stamina == 0 || g_patternCount < static_cast<LONG>(kMaxPatterns)) {
        return;
    }
    if (g_clearCount == static_cast<LONG>(kMaxPatterns)) {
        SendSweep();
        return;
    }
    if (g_payload8Count >= static_cast<LONG>(kMaxPatterns) && g_candidateStage != 0) {
        SendBattle();
    }
}

void HandleRecvPacket(uint32_t opcode, const BYTE* payload, uint32_t payloadLength)
{
    const uint32_t op = opcode & 0xFFFF;
    if (op != 0x4C84 && op != 0x844C) {
        return;
    }

    ParsePayload(payload, payloadLength);
}

__declspec(noinline) void __stdcall SendHook()
{
    if (ReadGameU32(g_mainBase + 0x230370) == 0) {
        return;
    }

    SendPacket(0x4C83, &g_payload4C83, sizeof(g_payload4C83));
}

bool BuildSendCode(uintptr_t, CodeBuffer& code)
{
    return AppendPushad(code) &&
        AppendRel32Instruction(code, 0xE8, reinterpret_cast<uintptr_t>(&SendHook)) &&
        AppendPopad(code) &&
        AppendByte(code, 0xC3);
}

}

namespace PersonalTask
{

void SendPacket(uint32_t opcode, const void* payload, uint32_t payloadLength)
{
    using SendPacketFn = void(__stdcall*)(uint32_t, const void*, uint32_t);
    SendPacketFn sendPacket = reinterpret_cast<SendPacketFn>(g_mainBase + 0x4A360);
    sendPacket(opcode, payload, payloadLength);
}

void RefreshLog()
{
    GameLog::RefreshCurrent();
}

void WriteLog(const wchar_t* text)
{
    GameLog::Write(reinterpret_cast<const wchar_t*>(g_mainBase + 0x1FE56C), text);
}

const wchar_t* SelectPromoLog()
{
    if (g_level == 0x32) {
        return kLogPromoHigh;
    }
    if (g_level == 0x33) {
        return kLogPromoFinal;
    }

    return kLogPromoMid;
}

const wchar_t* SelectSmallLog(size_t index)
{
    if (index >= 3) {
        index = 0;
    }

    if (g_level == 0x32) {
        return kLogSmallHigh[index];
    }
    if (g_level == 0x33) {
        return kLogSmallFinal[index];
    }

    return kLogSmallMid[index];
}

void ResetPending()
{
    InterlockedExchange(&g_pendingPromo, 0);
    for (size_t i = 0; i < 3; ++i) {
        g_claimPending[i] = 0;
    }
}

void SendQuery()
{
    SendPacket(0x4E60, &g_payloadZero, 0);
}

void SendPromo()
{
    SendPacket(0x4E63, &g_payloadZero, 0);
}

void SendClaim(size_t index)
{
    if (index >= 3) {
        return;
    }

    g_payload4E62 = static_cast<uint32_t>(g_rewardIds[index]) << 16;
    SendPacket(0x4E62, &g_payload4E62, sizeof(g_payload4E62));
}

bool HasPendingClaim()
{
    return g_claimPending[0] == 1 || g_claimPending[1] == 1 || g_claimPending[2] == 1;
}

void Tick()
{
    InterlockedExchange(&g_didWork, 0);

    if (g_pendingPromo == 1) {
        if (g_level == 0x33) {
            InterlockedExchange(&g_pendingPromo, 0);
            InterlockedExchange(&g_didWork, 1);
            return;
        }

        WriteLog(SelectPromoLog());
        SendPromo();
        InterlockedExchange(&g_pendingPromo, 0);
        InterlockedExchange(&g_didWork, 1);
        return;
    }

    for (size_t i = 0; i < 3; ++i) {
        if (g_claimPending[i] != 1) {
            continue;
        }

        WriteLog(SelectSmallLog(i));
        SendClaim(i);
        g_claimPending[i] = 0;
        InterlockedExchange(&g_didWork, 1);
        return;
    }
}

uint32_t CountMatchingTail(const BYTE* payload, uint32_t payloadLength, uint16_t tail)
{
    uint32_t count = 0;
    for (uint32_t offset = 2; offset <= payloadLength - 4; ++offset) {
        if (payload[offset] != 0 || payload[offset + 1] != 0x14) {
            continue;
        }

        uint16_t candidate = 0;
        std::memcpy(&candidate, payload + offset + 2, sizeof(candidate));
        if (candidate == tail) {
            ++count;
        }
    }

    return count;
}

void ScanRewardIds(const BYTE* payload, uint32_t payloadLength)
{
    size_t rewardIndex = 0;
    for (uint32_t offset = 2; offset <= payloadLength - 4; ++offset) {
        if (payload[offset] != 0 || payload[offset + 1] != 0x14) {
            continue;
        }
        if (rewardIndex >= 3) {
            continue;
        }

        uint16_t tail = 0;
        std::memcpy(&tail, payload + offset + 2, sizeof(tail));
        if (CountMatchingTail(payload, payloadLength, tail) < 3) {
            continue;
        }

        g_rewardIds[rewardIndex] = static_cast<uint16_t>(payload[offset - 2] | (payload[offset - 1] << 8));
        g_rewardValid[rewardIndex] = 1;
        ++rewardIndex;
    }
}

void ScanClaimStatus(const BYTE* payload, uint32_t payloadLength)
{
    size_t statusIndex = 0;
    for (uint32_t offset = 1; offset <= payloadLength - 4; ++offset) {
        if (payload[offset] != 0 ||
            payload[offset + 1] != 0x03 ||
            payload[offset + 2] != 0 ||
            payload[offset + 3] != 0xC8) {
            continue;
        }

        if (statusIndex < 3 &&
            payload[offset - 1] == 2 &&
            g_rewardValid[statusIndex] == 1) {
            g_claimPending[statusIndex] = 1;
        }
        ++statusIndex;
    }
}

void HandleRecvPacket(uint32_t opcode, const BYTE* payload, uint32_t payloadLength)
{
    if ((opcode & 0xFFFF) != 0x4E61 || !payload || payloadLength < 0x0E) {
        return;
    }

    if (g_pendingPromo == 1 || HasPendingClaim()) {
        return;
    }

    InterlockedExchange(&g_pendingPromo, 0);
    for (size_t i = 0; i < 4; ++i) {
        g_rewardIds[i] = 0;
        g_rewardValid[i] = 0;
        g_claimPending[i] = 0;
    }

    InterlockedExchange(&g_level, payload[3]);
    if (payload[0x0D] == 3) {
        InterlockedExchange(&g_pendingPromo, 1);
        return;
    }

    ScanRewardIds(payload, payloadLength);
    ScanClaimStatus(payload, payloadLength);
}

__declspec(noinline) void __stdcall SendHook()
{
    if (ReadGameU32(g_mainBase + 0x23028C) == 0) {
        ResetPending();
        return;
    }

    Tick();
    if (g_didWork == 1) {
        return;
    }

    SendQuery();
}

bool BuildSendCode(uintptr_t, CodeBuffer& code)
{
    return AppendPushad(code) &&
        AppendRel32Instruction(code, 0xE8, reinterpret_cast<uintptr_t>(&SendHook)) &&
        AppendPopad(code) &&
        AppendByte(code, 0xC3);
}

}

namespace TaskDispatch
{

struct Reader
{
    const BYTE* cursor;
    const BYTE* end;

    bool CanRead(size_t bytes) const
    {
        return cursor && end && cursor <= end && bytes <= static_cast<size_t>(end - cursor);
    }

    bool ReadU16(uint32_t& value)
    {
        if (!CanRead(2)) {
            InterlockedExchange(&g_parseError, 1);
            value = 0;
            return false;
        }

        value = (static_cast<uint32_t>(cursor[0]) << 8) | cursor[1];
        cursor += 2;
        return true;
    }

    bool ReadU32(uint32_t& value)
    {
        if (!CanRead(4)) {
            InterlockedExchange(&g_parseError, 1);
            value = 0;
            return false;
        }

        value = (static_cast<uint32_t>(cursor[0]) << 24) |
            (static_cast<uint32_t>(cursor[1]) << 16) |
            (static_cast<uint32_t>(cursor[2]) << 8) |
            cursor[3];
        cursor += 4;
        return true;
    }

    bool Skip(size_t bytes)
    {
        if (!CanRead(bytes)) {
            InterlockedExchange(&g_parseError, 1);
            return false;
        }

        cursor += bytes;
        return true;
    }

    bool SkipString()
    {
        uint32_t length = 0;
        return ReadU16(length) && Skip(length);
    }

    bool Copy(TaskId& id)
    {
        if (!CanRead(sizeof(id.bytes))) {
            InterlockedExchange(&g_parseError, 1);
            return false;
        }

        std::memcpy(id.bytes, cursor, sizeof(id.bytes));
        cursor += sizeof(id.bytes);
        return true;
    }
};

bool SameTaskId(const TaskId& lhs, const TaskId& rhs)
{
    return std::memcmp(lhs.bytes, rhs.bytes, sizeof(lhs.bytes)) == 0;
}

void ClearTaskId(TaskId& id)
{
    std::memset(id.bytes, 0, sizeof(id.bytes));
}

void ClearOutputs(bool clearSkipList)
{
    InterlockedExchange(&g_parseError, 0);
    InterlockedExchange(&g_currentDispatch, 0);
    InterlockedExchange(&g_maxDispatch, 0);
    InterlockedExchange(&g_freeSlots, 0);
    InterlockedExchange(&g_unassignedCount, 0);
    InterlockedExchange(&g_dispatchedCount, 0);
    InterlockedExchange(&g_unassignedSeen, 0);
    InterlockedExchange(&g_dispatchedSeen, 0);
    InterlockedExchange(&g_claimPending, 0);
    ClearTaskId(g_claimTaskId);
    InterlockedExchange(&g_bestPending, 0);
    ClearTaskId(g_bestTaskId);
    InterlockedExchange(&g_bestRank, 0x63);
    InterlockedExchange(&g_bestQuality, 0);
    InterlockedExchange(&g_configReady, 0);
    ClearTaskId(g_configTaskId);
    g_4B45PayloadLen = 0;
    std::memset(g_4B45Payload, 0, sizeof(g_4B45Payload));
    std::memset(g_unassigned, 0, sizeof(g_unassigned));
    std::memset(g_dispatched, 0, sizeof(g_dispatched));
    if (clearSkipList) {
        InterlockedExchange(&g_skipCount, 0);
        std::memset(g_skipIds, 0, sizeof(g_skipIds));
    }
}

uint32_t RankType(uint32_t rewardType)
{
    switch (rewardType) {
    case 0x08: return 1;
    case 0x10: return 2;
    case 0x11: return 3;
    case 0x26: return 4;
    case 0x1A: return 5;
    case 0x1C: return 6;
    case 0x06: return 7;
    case 0x2E: return 8;
    case 0x05: return 9;
    default: return 0x63;
    }
}

bool IsSkipped(const TaskId& id)
{
    LONG count = g_skipCount;
    if (count > static_cast<LONG>(kMaxTaskCount)) {
        count = static_cast<LONG>(kMaxTaskCount);
    }

    for (LONG i = 0; i < count; ++i) {
        if (SameTaskId(g_skipIds[i], id)) {
            return true;
        }
    }

    return false;
}

void AddSkip(const TaskId& id)
{
    LONG count = g_skipCount;
    if (count >= static_cast<LONG>(kMaxTaskCount)) {
        return;
    }

    g_skipIds[count] = id;
    InterlockedExchange(&g_skipCount, count + 1);
}

bool ParseNormalRewards(Reader& reader, TaskInfo& task)
{
    uint32_t count = 0;
    task.rank = 0x63;
    if (!reader.ReadU16(count)) {
        return false;
    }

    for (uint32_t i = 0; i < count; ++i) {
        uint32_t rewardType = 0;
        uint32_t unused = 0;
        if (!reader.ReadU16(rewardType)) {
            return false;
        }
        const uint32_t rank = RankType(rewardType);
        if (rank < task.rank) {
            task.rank = rank;
        }
        if (!reader.ReadU32(unused) || !reader.SkipString()) {
            return false;
        }
    }

    return true;
}

bool SkipRewards(Reader& reader)
{
    uint32_t count = 0;
    if (!reader.ReadU16(count)) {
        return false;
    }

    for (uint32_t i = 0; i < count; ++i) {
        uint32_t unused = 0;
        if (!reader.ReadU16(unused) || !reader.ReadU32(unused) || !reader.SkipString()) {
            return false;
        }
    }

    return true;
}

bool SkipConditions(Reader& reader)
{
    uint32_t count = 0;
    if (!reader.ReadU16(count)) {
        return false;
    }

    for (uint32_t i = 0; i < count; ++i) {
        uint32_t unused = 0;
        if (!reader.ReadU32(unused) ||
            !reader.ReadU32(unused) ||
            !reader.ReadU32(unused) ||
            !reader.SkipString() ||
            !reader.SkipString() ||
            !reader.Skip(1) ||
            !reader.SkipString()) {
            return false;
        }
    }

    return true;
}

bool SkipHeroes(Reader& reader)
{
    uint32_t count = 0;
    if (!reader.ReadU16(count)) {
        return false;
    }

    for (uint32_t i = 0; i < count; ++i) {
        uint32_t unused = 0;
        if (!reader.ReadU32(unused) ||
            !reader.SkipString() ||
            !reader.ReadU32(unused) ||
            !reader.ReadU32(unused) ||
            !reader.SkipString()) {
            return false;
        }
    }

    return true;
}

bool CopyBytes(Reader& reader, BYTE*& write, size_t bytes)
{
    if (!reader.CanRead(bytes) || write + bytes > g_4B45Payload + sizeof(g_4B45Payload)) {
        InterlockedExchange(&g_parseError, 1);
        return false;
    }

    std::memcpy(write, reader.cursor, bytes);
    reader.cursor += bytes;
    write += bytes;
    return true;
}

bool ParseConfigHeroes(Reader& reader)
{
    uint32_t heroCount = 0;
    if (!reader.ReadU16(heroCount)) {
        return false;
    }

    g_4B45Payload[8] = static_cast<BYTE>((heroCount >> 8) & 0xFF);
    g_4B45Payload[9] = static_cast<BYTE>(heroCount & 0xFF);
    BYTE* write = g_4B45Payload + 0x0A;

    for (uint32_t i = 0; i < heroCount; ++i) {
        if (!CopyBytes(reader, write, 4)) {
            return false;
        }
        if (!reader.CanRead(2)) {
            InterlockedExchange(&g_parseError, 1);
            return false;
        }
        const size_t nameBytes = (static_cast<size_t>(reader.cursor[0]) << 8) + reader.cursor[1] + 2;
        if (!CopyBytes(reader, write, nameBytes) ||
            !CopyBytes(reader, write, 4) ||
            !CopyBytes(reader, write, 4) ||
            !reader.SkipString()) {
            return false;
        }
    }

    g_4B45PayloadLen = static_cast<uint32_t>(write - g_4B45Payload);
    if (heroCount != 0) {
        InterlockedExchange(&g_configReady, 1);
    }
    return true;
}

bool SkipOptionalExtra(Reader& reader, uint32_t mode, uint32_t index, uint32_t count)
{
    if (!reader.CanRead(2)) {
        return true;
    }
    if (mode == 1 && index + 1 < count && reader.cursor[0] == 0 && reader.cursor[1] == 0) {
        return true;
    }

    return reader.SkipString();
}

bool ParseTask(Reader& reader, uint32_t mode, uint32_t index, uint32_t count)
{
    TaskInfo task{};
    if (!reader.Copy(task.id)) {
        return false;
    }

    if (mode == 2) {
        std::memcpy(g_configTaskId.bytes, task.id.bytes, sizeof(task.id.bytes));
        std::memcpy(g_4B45Payload, task.id.bytes, sizeof(task.id.bytes));
    }

    uint32_t unused = 0;
    if (!reader.SkipString() ||
        !reader.SkipString() ||
        !reader.ReadU32(task.quality) ||
        !reader.ReadU32(task.status) ||
        !reader.ReadU32(unused) ||
        !reader.ReadU32(unused) ||
        !reader.ReadU32(unused) ||
        !reader.SkipString() ||
        !reader.ReadU32(unused) ||
        !ParseNormalRewards(reader, task) ||
        !SkipRewards(reader) ||
        !SkipConditions(reader)) {
        return false;
    }

    if (mode == 2) {
        if (!ParseConfigHeroes(reader)) {
            return false;
        }
    } else if (!SkipHeroes(reader)) {
        return false;
    }

    if (!SkipOptionalExtra(reader, mode, index, count)) {
        return false;
    }

    if (mode == 1) {
        LONG seen = g_unassignedSeen;
        if (seen < static_cast<LONG>(kMaxTaskCount)) {
            g_unassigned[seen] = task;
            InterlockedExchange(&g_unassignedSeen, seen + 1);
        }

        if (g_freeSlots > 0 &&
            task.status == 1 &&
            !IsSkipped(task.id) &&
            (task.rank < static_cast<uint32_t>(g_bestRank) ||
                (task.rank == static_cast<uint32_t>(g_bestRank) && task.quality > static_cast<uint32_t>(g_bestQuality)))) {
            InterlockedExchange(&g_bestRank, static_cast<LONG>(task.rank));
            InterlockedExchange(&g_bestQuality, static_cast<LONG>(task.quality));
            g_bestTaskId = task.id;
            InterlockedExchange(&g_bestPending, 1);
        }
    } else if (mode == 3) {
        LONG seen = g_dispatchedSeen;
        if (seen < static_cast<LONG>(kMaxTaskCount)) {
            g_dispatched[seen] = task;
            InterlockedExchange(&g_dispatchedSeen, seen + 1);
        }
        if (g_claimPending == 0 && task.status == 3) {
            g_claimTaskId = task.id;
            InterlockedExchange(&g_claimPending, 1);
        }
    }

    return true;
}

void Handle4B49(const BYTE* payload, uint32_t payloadLength)
{
    if (ReadGameU32(g_mainBase + 0x2311F0) == 0) {
        return;
    }

    ClearOutputs(false);
    Reader reader{ payload, payload + payloadLength };
    uint32_t current = 0;
    uint32_t maximum = 0;
    uint32_t unused = 0;
    uint32_t unassignedCount = 0;
    uint32_t dispatchedCount = 0;

    if (!reader.ReadU32(current) ||
        !reader.ReadU32(maximum) ||
        !reader.ReadU32(unused) ||
        !reader.Skip(1) ||
        !reader.ReadU32(unused) ||
        !reader.ReadU16(unassignedCount)) {
        return;
    }

    InterlockedExchange(&g_currentDispatch, static_cast<LONG>(current));
    InterlockedExchange(&g_maxDispatch, static_cast<LONG>(maximum));
    InterlockedExchange(&g_freeSlots, static_cast<LONG>(maximum) - static_cast<LONG>(current));

    if (unassignedCount > 20) {
        unassignedCount = 20;
    }
    InterlockedExchange(&g_unassignedCount, static_cast<LONG>(unassignedCount));
    for (uint32_t i = 0; i < unassignedCount && g_parseError == 0; ++i) {
        ParseTask(reader, 1, i, unassignedCount);
    }

    if (g_bestPending == 0 && g_freeSlots > 0 && g_skipCount != 0) {
        InterlockedExchange(&g_skipCount, 0);
        std::memset(g_skipIds, 0, sizeof(g_skipIds));
    }

    if (g_parseError != 0 || !reader.ReadU16(dispatchedCount)) {
        return;
    }
    if (dispatchedCount > 20) {
        dispatchedCount = 20;
    }
    InterlockedExchange(&g_dispatchedCount, static_cast<LONG>(dispatchedCount));
    for (uint32_t i = 0; i < dispatchedCount && g_parseError == 0; ++i) {
        ParseTask(reader, 3, i, dispatchedCount);
    }

    if (g_parseError == 0) {
        reader.SkipString();
    }
}

void Handle4B4B(const BYTE* payload, uint32_t payloadLength)
{
    if (ReadGameU32(g_mainBase + 0x2311F0) == 0) {
        return;
    }

    InterlockedExchange(&g_configReady, 0);
    g_4B45PayloadLen = 0;
    ClearTaskId(g_configTaskId);
    std::memset(g_4B45Payload, 0, sizeof(g_4B45Payload));
    InterlockedExchange(&g_parseError, 0);

    Reader reader{ payload, payload + payloadLength };
    ParseTask(reader, 2, 0, 1);
}

void HandleRecvPacket(uint32_t opcode, const BYTE* payload, uint32_t payloadLength)
{
    if (!payload) {
        return;
    }

    switch (opcode & 0xFFFF) {
    case 0x4B49:
        Handle4B49(payload, payloadLength);
        break;
    case 0x4B4B:
        Handle4B4B(payload, payloadLength);
        break;
    default:
        break;
    }
}

void SendPacket(uint32_t opcode, const void* payload, uint32_t payloadLength)
{
    using SendPacketFn = void(__stdcall*)(uint32_t, const void*, uint32_t);
    SendPacketFn sendPacket = reinterpret_cast<SendPacketFn>(g_mainBase + 0x4A360);
    sendPacket(opcode, payload, payloadLength);
}

void RefreshLog()
{
    GameLog::RefreshCurrent();
}

void WriteLog(const wchar_t* text)
{
    GameLog::Write(reinterpret_cast<const wchar_t*>(g_mainBase + 0x1FE56C), text);
}

void SendTick()
{
    InterlockedIncrement(&g_senderTickCount);
    if (ReadGameU32(g_mainBase + 0x2311F0) == 0) {
        InterlockedExchange(&g_waitConfig, 0);
        InterlockedExchange(&g_skipCount, 0);
        return;
    }

    if (g_claimPending == 1) {
        g_payload4B47 = g_claimTaskId;
        SendPacket(0x4B47, &g_payload4B47, sizeof(g_payload4B47));
        WriteLog(kLogClaim);
        InterlockedIncrement(&g_senderSendCount);
        InterlockedExchange(&g_senderLastOpcode, 0x4B47);
        g_senderLastTaskId = g_payload4B47;
        InterlockedExchange(&g_claimPending, 0);
        InterlockedExchange(&g_skipCount, 0);
        return;
    }

    if (g_configReady == 1) {
        if (g_waitConfig == 1 &&
            SameTaskId(g_configTaskId, g_waitTaskId) &&
            g_4B45PayloadLen != 0) {
            SendPacket(0x4B45, g_4B45Payload, g_4B45PayloadLen);
            WriteLog(kLogDispatch);
            InterlockedIncrement(&g_senderSendCount);
            InterlockedExchange(&g_senderLastOpcode, 0x4B45);
            g_senderLastTaskId = g_configTaskId;
            InterlockedExchange(&g_configReady, 0);
            InterlockedExchange(&g_bestPending, 0);
            InterlockedExchange(&g_waitConfig, 0);
            InterlockedExchange(&g_skipCount, 0);
            return;
        }

        InterlockedExchange(&g_configReady, 0);
        g_4B45PayloadLen = 0;
        InterlockedExchange(&g_waitConfig, 0);
        InterlockedExchange(&g_bestPending, 0);
        return;
    }

    if (g_waitConfig == 1) {
        const DWORD now = GetGameTick();
        if (now - static_cast<DWORD>(g_waitTick) < kConfigWaitMs) {
            return;
        }

        AddSkip(g_waitTaskId);
        InterlockedExchange(&g_waitConfig, 0);
        InterlockedExchange(&g_bestPending, 0);
    } else if (g_bestPending == 1) {
        g_payload4B4A = g_bestTaskId;
        g_waitTaskId = g_bestTaskId;
        SendPacket(0x4B4A, &g_payload4B4A, sizeof(g_payload4B4A));
        InterlockedIncrement(&g_senderSendCount);
        InterlockedExchange(&g_senderLastOpcode, 0x4B4A);
        g_senderLastTaskId = g_payload4B4A;
        InterlockedExchange(&g_waitTick, static_cast<LONG>(GetGameTick()));
        InterlockedExchange(&g_waitConfig, 1);
        return;
    }

    SendPacket(0x4B48, &g_payloadZero, 0);
    InterlockedIncrement(&g_senderSendCount);
    InterlockedExchange(&g_senderLastOpcode, 0x4B48);
}

}

namespace TaskDispatchUi
{

bool TryGetConfigPath(const wchar_t** pathOut)
{
    if (g_mainBase == 0 || !pathOut) {
        return false;
    }

    const uint32_t pathAddress = ReadGameU32(g_mainBase + 0x230280);
    if (pathAddress == 0) {
        return false;
    }

    const wchar_t* path = reinterpret_cast<const wchar_t*>(static_cast<uintptr_t>(pathAddress));
    __try {
        const uint32_t pathLength = *(reinterpret_cast<const uint32_t*>(path) - 3);
        if (pathLength == 0 || pathLength >= 1024 || path[pathLength] != L'\0') {
            return false;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }

    *pathOut = path;
    return true;
}

bool PersistBattleTokenSwitch(LONG value)
{
    const wchar_t* path = nullptr;
    if (!TryGetConfigPath(&path)) {
        return false;
    }

    __try {
        if (!WritePrivateProfileStringW(
                kBattleTokenConfigSection,
                kBattleTokenConfigKey,
                value != 0 ? L"1" : L"0",
                path)) {
            return false;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }

    InterlockedExchange(&g_battleTokenKeyReady, 1);
    InterlockedExchange(&g_battleTokenDirty, 0);
    return true;
}

bool PersistZhaoXianNaKeSwitch(LONG value)
{
    const wchar_t* path = nullptr;
    if (!TryGetConfigPath(&path)) {
        return false;
    }

    __try {
        if (!WritePrivateProfileStringW(
                kBattleTokenConfigSection,
                kZhaoXianNaKeConfigKey,
                value != 0 ? L"1" : L"0",
                path)) {
            return false;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }

    InterlockedExchange(&g_zhaoXianNaKeKeyReady, 1);
    InterlockedExchange(&g_zhaoXianNaKeDirty, 0);
    return true;
}

bool PersistTeamBattleRewardSwitch(LONG value)
{
    const wchar_t* path = nullptr;
    if (!TryGetConfigPath(&path)) {
        return false;
    }

    __try {
        if (!WritePrivateProfileStringW(
                kBattleTokenConfigSection,
                kTeamBattleRewardConfigKey,
                value != 0 ? L"1" : L"0",
                path)) {
            return false;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }

    InterlockedExchange(&g_teamBattleRewardKeyReady, 1);
    InterlockedExchange(&g_teamBattleRewardDirty, 0);
    return true;
}

bool PersistDianFengZhuLuSwitch(LONG value)
{
    const wchar_t* path = nullptr;
    if (!TryGetConfigPath(&path)) return false;
    __try {
        if (!WritePrivateProfileStringW(kBattleTokenConfigSection, kDianFengZhuLuConfigKey,
                value != 0 ? L"1" : L"0", path)) return false;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
    InterlockedExchange(&g_dianFengZhuLuKeyReady, 1);
    InterlockedExchange(&g_dianFengZhuLuDirty, 0);
    return true;
}

bool PersistHuanJingSwitch(LONG value)
{
    const wchar_t* path = nullptr;
    if (!TryGetConfigPath(&path)) return false;
    __try {
        if (!WritePrivateProfileStringW(kBattleTokenConfigSection, kHuanJingConfigKey,
                value != 0 ? L"1" : L"0", path)) return false;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
    InterlockedExchange(&g_huanJingKeyReady, 1);
    InterlockedExchange(&g_huanJingDirty, 0);
    return true;
}

bool PersistTaskDispatchSwitch(LONG value)
{
    const wchar_t* path = nullptr;
    if (!TryGetConfigPath(&path)) {
        return false;
    }

    __try {
        if (!WritePrivateProfileStringW(
                kBattleTokenConfigSection,
                kTaskDispatchConfigKey,
                value != 0 ? L"1" : L"0",
                path)) {
            return false;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }

    InterlockedExchange(&g_taskDispatchKeyReady, 1);
    InterlockedExchange(&g_taskDispatchDirty, 0);
    return true;
}

bool LoadTaskDispatchSwitch()
{
    const wchar_t* path = nullptr;
    if (!TryGetConfigPath(&path)) {
        return false;
    }

    __try {
        wchar_t value[16]{};
        const wchar_t missingMarker[] = { 0xFFFF, 0x0000 };
        const DWORD length = GetPrivateProfileStringW(
            kBattleTokenConfigSection,
            kTaskDispatchConfigKey,
            missingMarker,
            value,
            static_cast<DWORD>(sizeof(value) / sizeof(value[0])),
            path);
        const bool missing = length == 0 ||
            (length == 1 && value[0] == missingMarker[0] && value[1] == L'\0');
        if (missing) {
            InterlockedExchange(&g_switch, 1);
            return PersistTaskDispatchSwitch(1);
        }

        const LONG enabled = GetPrivateProfileIntW(
            kBattleTokenConfigSection,
            kTaskDispatchConfigKey,
            1,
            path) != 0 ? 1 : 0;
        InterlockedExchange(&g_switch, enabled);
        InterlockedExchange(&g_taskDispatchKeyReady, 1);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

bool LoadBattleTokenSwitch()
{
    const wchar_t* path = nullptr;
    if (!TryGetConfigPath(&path)) {
        return false;
    }

    __try {
        wchar_t value[16]{};
        const wchar_t missingMarker[] = { 0xFFFF, 0x0000 };
        const DWORD length = GetPrivateProfileStringW(
            kBattleTokenConfigSection,
            kBattleTokenConfigKey,
            missingMarker,
            value,
            static_cast<DWORD>(sizeof(value) / sizeof(value[0])),
            path);
        const bool missing = length == 0 ||
            (length == 1 && value[0] == missingMarker[0] && value[1] == L'\0');
        if (missing) {
            InterlockedExchange(&g_battleTokenSwitch, 1);
            return PersistBattleTokenSwitch(1);
        }

        const LONG enabled = GetPrivateProfileIntW(
            kBattleTokenConfigSection,
            kBattleTokenConfigKey,
            1,
            path) != 0 ? 1 : 0;
        InterlockedExchange(&g_battleTokenSwitch, enabled);
        BattleToken::OnEnabledChanged(enabled);
        InterlockedExchange(&g_battleTokenKeyReady, 1);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

bool LoadZhaoXianNaKeSwitch()
{
    const wchar_t* path = nullptr;
    if (!TryGetConfigPath(&path)) {
        return false;
    }

    __try {
        wchar_t value[16]{};
        const wchar_t missingMarker[] = { 0xFFFF, 0x0000 };
        const DWORD length = GetPrivateProfileStringW(
            kBattleTokenConfigSection,
            kZhaoXianNaKeConfigKey,
            missingMarker,
            value,
            static_cast<DWORD>(sizeof(value) / sizeof(value[0])),
            path);
        const bool missing = length == 0 ||
            (length == 1 && value[0] == missingMarker[0] && value[1] == L'\0');
        if (missing) {
            InterlockedExchange(&g_zhaoXianNaKeSwitch, 1);
            return PersistZhaoXianNaKeSwitch(1);
        }

        const LONG enabled = GetPrivateProfileIntW(
            kBattleTokenConfigSection,
            kZhaoXianNaKeConfigKey,
            1,
            path) != 0 ? 1 : 0;
        InterlockedExchange(&g_zhaoXianNaKeSwitch, enabled);
        ZhaoXianNaKe::OnEnabledChanged(enabled);
        InterlockedExchange(&g_zhaoXianNaKeKeyReady, 1);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

bool LoadTeamBattleRewardSwitch()
{
    const wchar_t* path = nullptr;
    if (!TryGetConfigPath(&path)) {
        return false;
    }

    __try {
        wchar_t value[16]{};
        const wchar_t missingMarker[] = { 0xFFFF, 0x0000 };
        const DWORD length = GetPrivateProfileStringW(
            kBattleTokenConfigSection,
            kTeamBattleRewardConfigKey,
            missingMarker,
            value,
            static_cast<DWORD>(sizeof(value) / sizeof(value[0])),
            path);
        const bool missing = length == 0 ||
            (length == 1 && value[0] == missingMarker[0] && value[1] == L'\0');
        if (missing) {
            InterlockedExchange(&g_teamBattleRewardSwitch, 1);
            TeamBattleReward::OnEnabledChanged(1);
            return PersistTeamBattleRewardSwitch(1);
        }

        const LONG enabled = GetPrivateProfileIntW(
            kBattleTokenConfigSection,
            kTeamBattleRewardConfigKey,
            1,
            path) != 0 ? 1 : 0;
        InterlockedExchange(&g_teamBattleRewardSwitch, enabled);
        TeamBattleReward::OnEnabledChanged(enabled);
        InterlockedExchange(&g_teamBattleRewardKeyReady, 1);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

bool LoadDianFengZhuLuSwitch()
{
    const wchar_t* path = nullptr;
    if (!TryGetConfigPath(&path)) return false;
    __try {
        wchar_t value[16]{};
        const wchar_t missingMarker[] = { 0xFFFF, 0x0000 };
        const DWORD length = GetPrivateProfileStringW(kBattleTokenConfigSection,
            kDianFengZhuLuConfigKey, missingMarker, value, _countof(value), path);
        const bool missing = length == 0 ||
            (length == 1 && value[0] == missingMarker[0] && value[1] == L'\0');
        if (missing) {
            InterlockedExchange(&g_dianFengZhuLuSwitch, 1);
            DianFengZhuLu::OnEnabledChanged(1);
            return PersistDianFengZhuLuSwitch(1);
        }
        const LONG enabled = GetPrivateProfileIntW(kBattleTokenConfigSection,
            kDianFengZhuLuConfigKey, 1, path) != 0 ? 1 : 0;
        InterlockedExchange(&g_dianFengZhuLuSwitch, enabled);
        DianFengZhuLu::OnEnabledChanged(enabled);
        InterlockedExchange(&g_dianFengZhuLuKeyReady, 1);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

bool LoadHuanJingSwitch()
{
    const wchar_t* path = nullptr;
    if (!TryGetConfigPath(&path)) return false;
    __try {
        wchar_t value[16]{};
        const wchar_t missingMarker[] = { 0xFFFF, 0x0000 };
        const DWORD length = GetPrivateProfileStringW(kBattleTokenConfigSection,
            kHuanJingConfigKey, missingMarker, value, _countof(value), path);
        const bool missing = length == 0 ||
            (length == 1 && value[0] == missingMarker[0] && value[1] == L'\0');
        if (missing) {
            InterlockedExchange(&g_huanJingSwitch, 1);
            HuanJing::OnEnabledChanged(1);
            return PersistHuanJingSwitch(1);
        }
        const LONG enabled = GetPrivateProfileIntW(kBattleTokenConfigSection,
            kHuanJingConfigKey, 1, path) != 0 ? 1 : 0;
        InterlockedExchange(&g_huanJingSwitch, enabled);
        HuanJing::OnEnabledChanged(enabled);
        InterlockedExchange(&g_huanJingKeyReady, 1);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

void WriteSwitch(uint32_t value)
{
    if (g_mainBase == 0) {
        return;
    }

    *reinterpret_cast<volatile uint32_t*>(g_mainBase + 0x2311F0) = value;
}

void IncSwitchOnCounter()
{
    if (g_mainBase == 0) {
        return;
    }

    ++(*reinterpret_cast<volatile uint32_t*>(g_mainBase + 0x2311F4));
}

void SyncSwitch()
{
    if (!g_checkboxHwnd || !IsWindow(g_checkboxHwnd)) {
        return;
    }

    const LRESULT checked = SendMessageW(g_checkboxHwnd, BM_GETCHECK, 0, 0);
    const LONG value = checked != 0 ? 1 : 0;
    InterlockedExchange(&g_switch, value);
    WriteSwitch(static_cast<uint32_t>(value));
    if (value != 0 && g_lastValue == 0) {
        IncSwitchOnCounter();
    }
    InterlockedExchange(&g_lastValue, value);
}

void SyncBattleTokenSwitch()
{
    if (!g_battleTokenCheckboxHwnd || !IsWindow(g_battleTokenCheckboxHwnd)) {
        return;
    }

    const LONG value = SendMessageW(g_battleTokenCheckboxHwnd, BM_GETCHECK, 0, 0) != 0 ? 1 : 0;
    InterlockedExchange(&g_battleTokenSwitch, value);
    BattleToken::OnEnabledChanged(value);
    InterlockedExchange(&g_battleTokenDirty, 1);
    PersistBattleTokenSwitch(value);
}

void SyncZhaoXianNaKeSwitch()
{
    if (!g_zhaoXianNaKeCheckboxHwnd || !IsWindow(g_zhaoXianNaKeCheckboxHwnd)) {
        return;
    }

    const LONG value = SendMessageW(g_zhaoXianNaKeCheckboxHwnd, BM_GETCHECK, 0, 0) != 0 ? 1 : 0;
    InterlockedExchange(&g_zhaoXianNaKeSwitch, value);
    ZhaoXianNaKe::OnEnabledChanged(value);
    InterlockedExchange(&g_zhaoXianNaKeDirty, 1);
    PersistZhaoXianNaKeSwitch(value);
}

void SyncTeamBattleRewardSwitch()
{
    if (!g_teamBattleRewardCheckboxHwnd || !IsWindow(g_teamBattleRewardCheckboxHwnd)) {
        return;
    }

    const LONG value = SendMessageW(g_teamBattleRewardCheckboxHwnd, BM_GETCHECK, 0, 0) != 0 ? 1 : 0;
    InterlockedExchange(&g_teamBattleRewardSwitch, value);
    TeamBattleReward::OnEnabledChanged(value);
    InterlockedExchange(&g_teamBattleRewardDirty, 1);
    PersistTeamBattleRewardSwitch(value);
}

void SyncDianFengZhuLuSwitch()
{
    if (!g_dianFengZhuLuCheckboxHwnd || !IsWindow(g_dianFengZhuLuCheckboxHwnd)) return;
    const LONG value = SendMessageW(g_dianFengZhuLuCheckboxHwnd, BM_GETCHECK, 0, 0) != 0 ? 1 : 0;
    InterlockedExchange(&g_dianFengZhuLuSwitch, value);
    DianFengZhuLu::OnEnabledChanged(value);
    InterlockedExchange(&g_dianFengZhuLuDirty, 1);
    PersistDianFengZhuLuSwitch(value);
}

void SyncHuanJingSwitch()
{
    if (!g_huanJingCheckboxHwnd || !IsWindow(g_huanJingCheckboxHwnd)) return;
    const LONG value = SendMessageW(g_huanJingCheckboxHwnd, BM_GETCHECK, 0, 0) != 0 ? 1 : 0;
    InterlockedExchange(&g_huanJingSwitch, value);
    HuanJing::OnEnabledChanged(value);
    InterlockedExchange(&g_huanJingDirty, 1);
    PersistHuanJingSwitch(value);
}

void RefreshPersistentSwitches()
{
    if (g_taskDispatchKeyReady == 0) {
        bool ready = false;
        if (g_taskDispatchDirty != 0) {
            ready = PersistTaskDispatchSwitch(g_switch);
        } else {
            ready = LoadTaskDispatchSwitch();
        }
        if (ready && g_checkboxHwnd && IsWindow(g_checkboxHwnd)) {
            SendMessageW(g_checkboxHwnd, BM_SETCHECK, g_switch != 0 ? BST_CHECKED : BST_UNCHECKED, 0);
            SyncSwitch();
        }
    }

    if (g_battleTokenKeyReady == 0) {
        bool ready = false;
        if (g_battleTokenDirty != 0) {
            ready = PersistBattleTokenSwitch(g_battleTokenSwitch);
        } else {
            ready = LoadBattleTokenSwitch();
        }
        if (ready && g_battleTokenCheckboxHwnd && IsWindow(g_battleTokenCheckboxHwnd)) {
            SendMessageW(
                g_battleTokenCheckboxHwnd,
                BM_SETCHECK,
                g_battleTokenSwitch != 0 ? BST_CHECKED : BST_UNCHECKED,
                0);
        }
    }

    if (g_zhaoXianNaKeKeyReady == 0) {
        bool ready = false;
        if (g_zhaoXianNaKeDirty != 0) {
            ready = PersistZhaoXianNaKeSwitch(g_zhaoXianNaKeSwitch);
        } else {
            ready = LoadZhaoXianNaKeSwitch();
        }
        if (ready && g_zhaoXianNaKeCheckboxHwnd && IsWindow(g_zhaoXianNaKeCheckboxHwnd)) {
            SendMessageW(
                g_zhaoXianNaKeCheckboxHwnd,
                BM_SETCHECK,
                g_zhaoXianNaKeSwitch != 0 ? BST_CHECKED : BST_UNCHECKED,
                0);
        }
    }

    if (g_teamBattleRewardKeyReady == 0) {
        bool ready = false;
        if (g_teamBattleRewardDirty != 0) {
            ready = PersistTeamBattleRewardSwitch(g_teamBattleRewardSwitch);
        } else {
            ready = LoadTeamBattleRewardSwitch();
        }
        if (ready && g_teamBattleRewardCheckboxHwnd && IsWindow(g_teamBattleRewardCheckboxHwnd)) {
            SendMessageW(
                g_teamBattleRewardCheckboxHwnd,
                BM_SETCHECK,
                g_teamBattleRewardSwitch != 0 ? BST_CHECKED : BST_UNCHECKED,
                0);
        }
    }

    if (g_dianFengZhuLuKeyReady == 0) {
        bool ready = g_dianFengZhuLuDirty != 0
            ? PersistDianFengZhuLuSwitch(g_dianFengZhuLuSwitch)
            : LoadDianFengZhuLuSwitch();
        if (ready && g_dianFengZhuLuCheckboxHwnd && IsWindow(g_dianFengZhuLuCheckboxHwnd)) {
            SendMessageW(g_dianFengZhuLuCheckboxHwnd, BM_SETCHECK,
                g_dianFengZhuLuSwitch != 0 ? BST_CHECKED : BST_UNCHECKED, 0);
        }
    }

    if (g_huanJingKeyReady == 0) {
        bool ready = g_huanJingDirty != 0
            ? PersistHuanJingSwitch(g_huanJingSwitch)
            : LoadHuanJingSwitch();
        if (ready && g_huanJingCheckboxHwnd && IsWindow(g_huanJingCheckboxHwnd)) {
            SendMessageW(g_huanJingCheckboxHwnd, BM_SETCHECK,
                g_huanJingSwitch != 0 ? BST_CHECKED : BST_UNCHECKED, 0);
        }
    }
}

LRESULT CALLBACK SettingsWndProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam)
{
    if ((message == WM_SHOWWINDOW && wParam == FALSE) || message == WM_DESTROY) {
        PersistTaskDispatchSwitch(g_switch);
        PersistBattleTokenSwitch(g_battleTokenSwitch);
        PersistZhaoXianNaKeSwitch(g_zhaoXianNaKeSwitch);
        PersistTeamBattleRewardSwitch(g_teamBattleRewardSwitch);
        PersistDianFengZhuLuSwitch(g_dianFengZhuLuSwitch);
        PersistHuanJingSwitch(g_huanJingSwitch);
    }

    return g_settingsOldProc
        ? CallWindowProcW(g_settingsOldProc, hwnd, message, wParam, lParam)
        : DefWindowProcW(hwnd, message, wParam, lParam);
}

LRESULT CALLBACK ParentWndProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam)
{
    if (message == WM_COMMAND && (LOWORD(wParam) == kCheckboxId)) {
        SyncSwitch();
        InterlockedExchange(&g_taskDispatchDirty, 1);
        PersistTaskDispatchSwitch(g_switch);
        return g_oldProc ? CallWindowProcW(g_oldProc, hwnd, message, wParam, lParam) : DefWindowProcW(hwnd, message, wParam, lParam);
    }
    if (message == WM_COMMAND && LOWORD(wParam) == kBattleTokenCheckboxId && HIWORD(wParam) == BN_CLICKED) {
        SyncBattleTokenSwitch();
        return g_oldProc ? CallWindowProcW(g_oldProc, hwnd, message, wParam, lParam) : DefWindowProcW(hwnd, message, wParam, lParam);
    }
    if (message == WM_COMMAND && LOWORD(wParam) == kZhaoXianNaKeCheckboxId && HIWORD(wParam) == BN_CLICKED) {
        SyncZhaoXianNaKeSwitch();
        return g_oldProc ? CallWindowProcW(g_oldProc, hwnd, message, wParam, lParam) : DefWindowProcW(hwnd, message, wParam, lParam);
    }
    if (message == WM_COMMAND && LOWORD(wParam) == kTeamBattleRewardCheckboxId && HIWORD(wParam) == BN_CLICKED) {
        SyncTeamBattleRewardSwitch();
        return g_oldProc ? CallWindowProcW(g_oldProc, hwnd, message, wParam, lParam) : DefWindowProcW(hwnd, message, wParam, lParam);
    }
    if (message == WM_COMMAND && LOWORD(wParam) == kDianFengZhuLuCheckboxId && HIWORD(wParam) == BN_CLICKED) {
        SyncDianFengZhuLuSwitch();
        return g_oldProc ? CallWindowProcW(g_oldProc, hwnd, message, wParam, lParam) : DefWindowProcW(hwnd, message, wParam, lParam);
    }
    if (message == WM_COMMAND && LOWORD(wParam) == kHuanJingCheckboxId && HIWORD(wParam) == BN_CLICKED) {
        SyncHuanJingSwitch();
        return g_oldProc ? CallWindowProcW(g_oldProc, hwnd, message, wParam, lParam) : DefWindowProcW(hwnd, message, wParam, lParam);
    }

    if (message == WM_TIMER && wParam == kTimerId) {
        RefreshPersistentSwitches();
        SyncSwitch();
        return 1;
    }

    if (message == kPrivateMessage) {
        if (wParam == 1) {
            LoadTaskDispatchSwitch();
            LoadBattleTokenSwitch();
            LoadZhaoXianNaKeSwitch();
            LoadTeamBattleRewardSwitch();
            LoadDianFengZhuLuSwitch();
            LoadHuanJingSwitch();
            if (!g_checkboxHwnd) {
                g_checkboxHwnd = CreateWindowExW(
                    0,
                    L"Button",
                    kCheckboxText,
                    0x50018003,
                    g_x,
                    g_y,
                    g_w,
                    g_h,
                    g_parentHwnd,
                    reinterpret_cast<HMENU>(static_cast<UINT_PTR>(kCheckboxId)),
                    nullptr,
                    nullptr);
            }
            if (!g_battleTokenCheckboxHwnd) {
                g_battleTokenCheckboxHwnd = CreateWindowExW(
                    0,
                    L"Button",
                    kBattleTokenCheckboxText,
                    0x50018003,
                    g_x,
                    g_y + g_h,
                    g_w,
                    g_h,
                    g_parentHwnd,
                    reinterpret_cast<HMENU>(static_cast<UINT_PTR>(kBattleTokenCheckboxId)),
                    nullptr,
                    nullptr);
            }
            if (!g_zhaoXianNaKeCheckboxHwnd) {
                g_zhaoXianNaKeCheckboxHwnd = CreateWindowExW(
                    0,
                    L"Button",
                    kZhaoXianNaKeCheckboxText,
                    0x50018003,
                    g_x,
                    g_y + (g_h * 2),
                    g_w,
                    g_h,
                    g_parentHwnd,
                    reinterpret_cast<HMENU>(static_cast<UINT_PTR>(kZhaoXianNaKeCheckboxId)),
                    nullptr,
                    nullptr);
            }
            if (!g_teamBattleRewardCheckboxHwnd) {
                g_teamBattleRewardCheckboxHwnd = CreateWindowExW(
                    0,
                    L"Button",
                    kTeamBattleRewardCheckboxText,
                    0x50018003,
                    g_x,
                    g_y + (g_h * 3),
                    g_w,
                    g_h,
                    g_parentHwnd,
                    reinterpret_cast<HMENU>(static_cast<UINT_PTR>(kTeamBattleRewardCheckboxId)),
                    nullptr,
                    nullptr);
            }
            if (!g_dianFengZhuLuCheckboxHwnd) {
                g_dianFengZhuLuCheckboxHwnd = CreateWindowExW(
                    0,
                    L"Button",
                    kDianFengZhuLuCheckboxText,
                    0x50018003,
                    g_x,
                    g_y + (g_h * 4),
                    g_w,
                    g_h,
                    g_parentHwnd,
                    reinterpret_cast<HMENU>(static_cast<UINT_PTR>(kDianFengZhuLuCheckboxId)),
                    nullptr,
                    nullptr);
            }
            if (!g_huanJingCheckboxHwnd) {
                g_huanJingCheckboxHwnd = CreateWindowExW(
                    0,
                    L"Button",
                    kHuanJingCheckboxText,
                    0x50018003,
                    g_x,
                    g_y + (g_h * 5),
                    g_w,
                    g_h,
                    g_parentHwnd,
                    reinterpret_cast<HMENU>(static_cast<UINT_PTR>(kHuanJingCheckboxId)),
                    nullptr,
                    nullptr);
            }

            if (g_checkboxHwnd) {
                HFONT font = reinterpret_cast<HFONT>(SendMessageW(g_weeklyHwnd, WM_GETFONT, 0, 0));
                if (font) {
                    SendMessageW(g_checkboxHwnd, WM_SETFONT, reinterpret_cast<WPARAM>(font), TRUE);
                    if (g_battleTokenCheckboxHwnd) {
                        SendMessageW(g_battleTokenCheckboxHwnd, WM_SETFONT, reinterpret_cast<WPARAM>(font), TRUE);
                    }
                    if (g_zhaoXianNaKeCheckboxHwnd) {
                        SendMessageW(g_zhaoXianNaKeCheckboxHwnd, WM_SETFONT, reinterpret_cast<WPARAM>(font), TRUE);
                    }
                    if (g_teamBattleRewardCheckboxHwnd) {
                        SendMessageW(g_teamBattleRewardCheckboxHwnd, WM_SETFONT, reinterpret_cast<WPARAM>(font), TRUE);
                    }
                    if (g_dianFengZhuLuCheckboxHwnd) {
                        SendMessageW(g_dianFengZhuLuCheckboxHwnd, WM_SETFONT, reinterpret_cast<WPARAM>(font), TRUE);
                    }
                    if (g_huanJingCheckboxHwnd) {
                        SendMessageW(g_huanJingCheckboxHwnd, WM_SETFONT, reinterpret_cast<WPARAM>(font), TRUE);
                    }
                }
                ShowWindow(g_checkboxHwnd, SW_SHOW);
                if (g_battleTokenCheckboxHwnd) {
                    SendMessageW(
                        g_battleTokenCheckboxHwnd,
                        BM_SETCHECK,
                        g_battleTokenSwitch != 0 ? BST_CHECKED : BST_UNCHECKED,
                        0);
                    ShowWindow(g_battleTokenCheckboxHwnd, SW_SHOW);
                }
                if (g_zhaoXianNaKeCheckboxHwnd) {
                    SendMessageW(
                        g_zhaoXianNaKeCheckboxHwnd,
                        BM_SETCHECK,
                        g_zhaoXianNaKeSwitch != 0 ? BST_CHECKED : BST_UNCHECKED,
                        0);
                    ShowWindow(g_zhaoXianNaKeCheckboxHwnd, SW_SHOW);
                }
                if (g_teamBattleRewardCheckboxHwnd) {
                    SendMessageW(
                        g_teamBattleRewardCheckboxHwnd,
                        BM_SETCHECK,
                        g_teamBattleRewardSwitch != 0 ? BST_CHECKED : BST_UNCHECKED,
                        0);
                    ShowWindow(g_teamBattleRewardCheckboxHwnd, SW_SHOW);
                }
                if (g_dianFengZhuLuCheckboxHwnd) {
                    SendMessageW(g_dianFengZhuLuCheckboxHwnd, BM_SETCHECK,
                        g_dianFengZhuLuSwitch != 0 ? BST_CHECKED : BST_UNCHECKED, 0);
                    ShowWindow(g_dianFengZhuLuCheckboxHwnd, SW_SHOW);
                }
                if (g_huanJingCheckboxHwnd) {
                    SendMessageW(g_huanJingCheckboxHwnd, BM_SETCHECK,
                        g_huanJingSwitch != 0 ? BST_CHECKED : BST_UNCHECKED, 0);
                    ShowWindow(g_huanJingCheckboxHwnd, SW_SHOW);
                }
                SetTimer(g_parentHwnd, kTimerId, 1000, nullptr);
                SendMessageW(g_checkboxHwnd, BM_SETCHECK, g_switch != 0 ? BST_CHECKED : BST_UNCHECKED, 0);
                SyncSwitch();
                InterlockedExchange(&g_status, 7);
            }
            return 1;
        }

        if (wParam == 2) {
            PersistTaskDispatchSwitch(g_switch);
            PersistBattleTokenSwitch(g_battleTokenSwitch);
            PersistZhaoXianNaKeSwitch(g_zhaoXianNaKeSwitch);
            PersistTeamBattleRewardSwitch(g_teamBattleRewardSwitch);
            PersistDianFengZhuLuSwitch(g_dianFengZhuLuSwitch);
            PersistHuanJingSwitch(g_huanJingSwitch);
            KillTimer(g_parentHwnd, kTimerId);
            if (g_checkboxHwnd && IsWindow(g_checkboxHwnd)) {
                DestroyWindow(g_checkboxHwnd);
            }
            if (g_battleTokenCheckboxHwnd && IsWindow(g_battleTokenCheckboxHwnd)) {
                DestroyWindow(g_battleTokenCheckboxHwnd);
            }
            if (g_zhaoXianNaKeCheckboxHwnd && IsWindow(g_zhaoXianNaKeCheckboxHwnd)) {
                DestroyWindow(g_zhaoXianNaKeCheckboxHwnd);
            }
            if (g_teamBattleRewardCheckboxHwnd && IsWindow(g_teamBattleRewardCheckboxHwnd)) {
                DestroyWindow(g_teamBattleRewardCheckboxHwnd);
            }
            if (g_dianFengZhuLuCheckboxHwnd && IsWindow(g_dianFengZhuLuCheckboxHwnd)) {
                DestroyWindow(g_dianFengZhuLuCheckboxHwnd);
            }
            if (g_huanJingCheckboxHwnd && IsWindow(g_huanJingCheckboxHwnd)) {
                DestroyWindow(g_huanJingCheckboxHwnd);
            }
            g_checkboxHwnd = nullptr;
            g_battleTokenCheckboxHwnd = nullptr;
            g_zhaoXianNaKeCheckboxHwnd = nullptr;
            g_teamBattleRewardCheckboxHwnd = nullptr;
            g_dianFengZhuLuCheckboxHwnd = nullptr;
            g_huanJingCheckboxHwnd = nullptr;
            WriteSwitch(0);
            InterlockedExchange(&g_status, 8);
            return 1;
        }
    }

    return g_oldProc ? CallWindowProcW(g_oldProc, hwnd, message, wParam, lParam) : DefWindowProcW(hwnd, message, wParam, lParam);
}

struct EnumState
{
    HWND candidateWeekly = nullptr;
    HWND candidateDaily = nullptr;
    HWND candidateWeeklyParent = nullptr;
    HWND candidateDailyParent = nullptr;
    int bestTop = INT_MAX;
};

BOOL CALLBACK EnumChildProc(HWND hwnd, LPARAM lParam)
{
    EnumState* state = reinterpret_cast<EnumState*>(lParam);
    const int id = GetDlgCtrlID(hwnd) & 0xFFFF;
    HWND parent = GetParent(hwnd);
    if (!parent) {
        return TRUE;
    }

    if (id == 0x0403) {
        if (state->candidateDaily && state->candidateDailyParent == parent) {
            RECT rect{};
            GetWindowRect(hwnd, &rect);
            if (rect.top < state->bestTop) {
                state->bestTop = rect.top;
                g_weeklyHwnd = hwnd;
                g_dailyHwnd = state->candidateDaily;
            }
        } else {
            state->candidateWeekly = hwnd;
            state->candidateWeeklyParent = parent;
        }
    } else if (id == 0x0402) {
        if (state->candidateWeekly && state->candidateWeeklyParent == parent) {
            RECT rect{};
            GetWindowRect(state->candidateWeekly, &rect);
            if (rect.top < state->bestTop) {
                state->bestTop = rect.top;
                g_weeklyHwnd = state->candidateWeekly;
                g_dailyHwnd = hwnd;
            }
        } else {
            state->candidateDaily = hwnd;
            state->candidateDailyParent = parent;
        }
    }

    return TRUE;
}

bool FindAndInstall()
{
    g_settingsHwnd = FindWindowW(nullptr, kSettingsTitle);
    if (!g_settingsHwnd) {
        return false;
    }
    InterlockedExchange(&g_status, 2);

    EnumState state{};
    g_weeklyHwnd = nullptr;
    g_dailyHwnd = nullptr;
    EnumChildWindows(g_settingsHwnd, EnumChildProc, reinterpret_cast<LPARAM>(&state));
    if (!g_weeklyHwnd || !g_dailyHwnd) {
        return false;
    }
    SetWindowTextW(g_dailyHwnd, kActivityLoginCheckboxText);
    InterlockedExchange(&g_status, 3);

    g_parentHwnd = GetParent(g_weeklyHwnd);
    if (!g_parentHwnd) {
        return false;
    }

    RECT weeklyRect{};
    POINT weeklyPoint{};
    if (!GetWindowRect(g_weeklyHwnd, &weeklyRect)) {
        return false;
    }
    weeklyPoint.x = weeklyRect.left;
    weeklyPoint.y = weeklyRect.top;
    ScreenToClient(g_parentHwnd, &weeklyPoint);
    g_w = weeklyRect.right - weeklyRect.left;
    g_h = weeklyRect.bottom - weeklyRect.top;
    g_x = weeklyPoint.x - g_w - 6;
    g_y = weeklyPoint.y;
    InterlockedExchange(&g_status, 4);

    g_settingsOldProc = reinterpret_cast<WNDPROC>(
        SetWindowLongPtrW(g_settingsHwnd, GWLP_WNDPROC, reinterpret_cast<LONG_PTR>(SettingsWndProc)));
    if (!g_settingsOldProc) {
        return false;
    }
    g_oldProc = reinterpret_cast<WNDPROC>(SetWindowLongPtrW(g_parentHwnd, GWLP_WNDPROC, reinterpret_cast<LONG_PTR>(ParentWndProc)));
    if (!g_oldProc) {
        SetWindowLongPtrW(g_settingsHwnd, GWLP_WNDPROC, reinterpret_cast<LONG_PTR>(g_settingsOldProc));
        g_settingsOldProc = nullptr;
        return false;
    }
    InterlockedExchange(&g_status, 5);

    SendMessageW(g_parentHwnd, kPrivateMessage, 1, 0);
    InterlockedExchange(&g_status, 6);
    return true;
}

DWORD WINAPI SetupThread(LPVOID)
{
    InterlockedIncrement(&g_hitCount);
    InterlockedExchange(&g_status, 1);
    InterlockedExchange(&g_switch, 1);
    InterlockedExchange(&g_lastValue, 1);
    WriteSwitch(1);
    if (g_mainBase != 0) {
        *reinterpret_cast<volatile uint32_t*>(g_mainBase + 0x2311F4) = 1;
    }

    for (int i = 0; i < 30; ++i) {
        if (g_teamBattleRewardKeyReady == 0) {
            LoadTeamBattleRewardSwitch();
        }
        if (g_dianFengZhuLuKeyReady == 0) {
            LoadDianFengZhuLuSwitch();
        }
        if (g_huanJingKeyReady == 0) {
            LoadHuanJingSwitch();
        }
        if (FindAndInstall()) {
            return 0;
        }
        Sleep(100);
    }

    InterlockedExchange(&g_status, -1);
    return 0;
}

void Start()
{
    if (InterlockedCompareExchange(&g_started, 1, 0) != 0) {
        return;
    }

    HANDLE thread = CreateThread(nullptr, 0, SetupThread, nullptr, 0, nullptr);
    if (thread) {
        CloseHandle(thread);
    }
}

}

namespace ActivityLogin
{
constexpr uint32_t kActivityType = 20030;
constexpr DWORD kDailySwitchOffset = 0x2302EC;
constexpr DWORD kInitialRetryMs = 10000;
constexpr DWORD kClaimToQueryMs = 2000;
constexpr DWORD kVerifyRetryMs = 5000;
constexpr DWORD kNextClaimMs = 1000;
constexpr DWORD kCycleIntervalMs = 20 * 60 * 1000;
constexpr DWORD kActivityMissingRetryMs = 30000;
constexpr LONG kMaxVerifyRetries = 3;
constexpr size_t kMaxRewards = 256;

struct RewardEntry
{
    BYTE state = 0;
    BYTE rewardId = 0;
};

struct PacketReader
{
    const BYTE* cursor = nullptr;
    const BYTE* end = nullptr;

    bool ReadByte(BYTE& value)
    {
        if (!cursor || cursor >= end) {
            return false;
        }
        value = *cursor++;
        return true;
    }

    bool ReadU16(uint16_t& value)
    {
        if (!cursor || cursor + 2 > end) {
            return false;
        }
        value = ReadBe16Unaligned(cursor);
        cursor += 2;
        return true;
    }

    bool ReadU32(uint32_t& value)
    {
        if (!cursor || cursor + 4 > end) {
            return false;
        }
        value = ReadBe32Unaligned(cursor);
        cursor += 4;
        return true;
    }

    bool Skip(size_t length)
    {
        if (!cursor || length > static_cast<size_t>(end - cursor)) {
            return false;
        }
        cursor += length;
        return true;
    }

    bool SkipUtf()
    {
        uint16_t length = 0;
        return ReadU16(length) && Skip(length);
    }
};

volatile LONG g_tickRunning = 0;
volatile LONG g_wasEnabled = 0;
volatile LONG g_state = 0;
volatile LONG g_targetId = 0;
volatile LONG g_deadlineTick = 0;
volatile LONG g_nextCheckTick = 0;
volatile LONG g_detailVersion = 0;
volatile LONG g_seenDetailVersion = 0;
volatile LONG g_detailType = 0;
volatile LONG g_detailId = 0;
volatile LONG g_rewardCount = 0;
volatile LONG g_pendingReward = -1;
volatile LONG g_verifyRetries = 0;
volatile LONG g_queryCount = 0;
volatile LONG g_claimCount = 0;
volatile LONG g_verifiedCount = 0;
volatile LONG g_pendingLog = 0;
volatile LONG g_pendingLogDay = 0;
volatile LONG g_logCount = 0;
volatile LONG g_parseError = 0;
RewardEntry g_rewards[kMaxRewards]{};
BYTE g_blockedRewards[256]{};
BYTE g_queryPayload[8]{};
BYTE g_claimPayload[9]{};

const wchar_t kRewardLogFormat[] =
    L"\x6D3B\x52D5\x767B\x5165\x0020\x7B2C%d\x65E5\x734E\x52F5";

bool IsEnabled()
{
    return g_mainBase != 0 && ReadGameU32(g_mainBase + kDailySwitchOffset) != 0;
}

void WriteBe32(BYTE* output, uint32_t value)
{
    output[0] = static_cast<BYTE>((value >> 24) & 0xFF);
    output[1] = static_cast<BYTE>((value >> 16) & 0xFF);
    output[2] = static_cast<BYTE>((value >> 8) & 0xFF);
    output[3] = static_cast<BYTE>(value & 0xFF);
}

void SendPacket(uint32_t opcode, const void* payload, uint32_t payloadLength)
{
    using SendPacketFn = void(__stdcall*)(uint32_t, const void*, uint32_t);
    SendPacketFn sendPacket = reinterpret_cast<SendPacketFn>(g_mainBase + 0x4A360);
    sendPacket(opcode, payload, payloadLength);
}

void ResetState()
{
    InterlockedExchange(&g_state, 0);
    InterlockedExchange(&g_targetId, 0);
    InterlockedExchange(&g_deadlineTick, 0);
    InterlockedExchange(&g_nextCheckTick, 0);
    InterlockedExchange(&g_pendingReward, -1);
    InterlockedExchange(&g_verifyRetries, 0);
    std::memset(g_blockedRewards, 0, sizeof(g_blockedRewards));
}

void ResetCycle()
{
    InterlockedExchange(&g_pendingReward, -1);
    InterlockedExchange(&g_verifyRetries, 0);
    std::memset(g_blockedRewards, 0, sizeof(g_blockedRewards));
}

uint32_t FindNativeActivityId()
{
    if (g_mainBase == 0) {
        return 0;
    }

    __try {
        const uint32_t listAddress = ReadGameU32(g_mainBase + 0x2309F8);
        const uint32_t count = ReadGameU32(g_mainBase + 0x2309FC);
        if (listAddress == 0 || count == 0 || count > 4096) {
            return 0;
        }

        const uint32_t* entries = reinterpret_cast<const uint32_t*>(static_cast<uintptr_t>(listAddress));
        for (uint32_t index = 0; index < count; ++index) {
            const uint32_t entryAddress = entries[index];
            if (entryAddress == 0) {
                continue;
            }
            const uintptr_t entry = static_cast<uintptr_t>(entryAddress);
            if (ReadGameU32(entry + 8) == kActivityType) {
                return ReadGameU32(entry);
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return 0;
    }

    return 0;
}

void BuildBasePayload(BYTE* payload, uint32_t activityId)
{
    WriteBe32(payload, kActivityType);
    WriteBe32(payload + 4, activityId);
}

void SendQuery(DWORD now)
{
    BuildBasePayload(g_queryPayload, static_cast<uint32_t>(g_targetId));
    InterlockedExchange(&g_seenDetailVersion, g_detailVersion);
    InterlockedExchange(&g_deadlineTick, static_cast<LONG>(now + kInitialRetryMs));
    InterlockedIncrement(&g_queryCount);
    SendPacket(0x25EC, g_queryPayload, sizeof(g_queryPayload));
}

void SendClaim(BYTE rewardId, DWORD now)
{
    BuildBasePayload(g_claimPayload, static_cast<uint32_t>(g_targetId));
    g_claimPayload[8] = rewardId;
    InterlockedExchange(&g_pendingReward, rewardId);
    InterlockedExchange(&g_verifyRetries, 0);
    InterlockedExchange(&g_deadlineTick, static_cast<LONG>(now + kClaimToQueryMs));
    InterlockedExchange(&g_state, 2);
    InterlockedIncrement(&g_claimCount);
    SendPacket(0x25EF, g_claimPayload, sizeof(g_claimPayload));
}

LONG FindRewardState(LONG rewardId)
{
    const LONG count = g_rewardCount;
    for (LONG index = 0; index < count && index < static_cast<LONG>(kMaxRewards); ++index) {
        if (g_rewards[index].rewardId == static_cast<BYTE>(rewardId)) {
            return g_rewards[index].state;
        }
    }
    return -1;
}

void DrainPendingLog()
{
    if (InterlockedExchange(&g_pendingLog, 0) == 0) {
        return;
    }
    GameLog::Write(kRewardLogFormat, static_cast<uint32_t>(g_pendingLogDay));
    InterlockedIncrement(&g_logCount);
}

void FinishCycle(DWORD now)
{
    InterlockedExchange(&g_nextCheckTick, static_cast<LONG>(now + kCycleIntervalMs));
    InterlockedExchange(&g_state, 0);
}

void ProcessClaimableRewards(DWORD now)
{
    if (g_detailType != static_cast<LONG>(kActivityType) || g_detailId != g_targetId) {
        InterlockedExchange(&g_deadlineTick, static_cast<LONG>(now + kInitialRetryMs));
        InterlockedExchange(&g_state, 1);
        return;
    }

    const LONG count = g_rewardCount;
    for (LONG index = 0; index < count && index < static_cast<LONG>(kMaxRewards); ++index) {
        const RewardEntry reward = g_rewards[index];
        if (reward.state == 2 && g_blockedRewards[reward.rewardId] == 0) {
            SendClaim(reward.rewardId, now);
            return;
        }
    }
    FinishCycle(now);
}

void RetryOrBlockPending(DWORD now)
{
    const LONG retry = InterlockedIncrement(&g_verifyRetries);
    if (retry >= kMaxVerifyRetries) {
        const LONG rewardId = g_pendingReward;
        if (rewardId >= 0 && rewardId <= 255) {
            g_blockedRewards[rewardId] = 1;
        }
        InterlockedExchange(&g_pendingReward, -1);
        InterlockedExchange(&g_deadlineTick, static_cast<LONG>(now + kNextClaimMs));
        InterlockedExchange(&g_state, 4);
        return;
    }
    InterlockedExchange(&g_deadlineTick, static_cast<LONG>(now + kVerifyRetryMs));
    InterlockedExchange(&g_state, 2);
}

void HandleDetail(const BYTE* payload, uint32_t payloadLength)
{
    if (!payload || payloadLength < 11) {
        InterlockedIncrement(&g_parseError);
        return;
    }

    PacketReader reader{ payload, payload + payloadLength };
    uint32_t activityType = 0;
    uint32_t activityId = 0;
    BYTE panelState = 0;
    uint16_t rewardCount = 0;
    if (!reader.ReadU32(activityType) ||
        !reader.ReadU32(activityId) ||
        !reader.SkipUtf() ||
        !reader.ReadByte(panelState) ||
        !reader.ReadU16(rewardCount)) {
        InterlockedIncrement(&g_parseError);
        return;
    }

    RewardEntry parsed[kMaxRewards]{};
    LONG storedCount = 0;
    for (uint16_t index = 0; index < rewardCount; ++index) {
        BYTE state = 0;
        BYTE rewardId = 0;
        uint16_t detailCount = 0;
        if (!reader.SkipUtf() ||
            !reader.ReadByte(state) ||
            !reader.ReadByte(rewardId) ||
            !reader.ReadU16(detailCount)) {
            InterlockedIncrement(&g_parseError);
            return;
        }
        for (uint16_t detailIndex = 0; detailIndex < detailCount; ++detailIndex) {
            BYTE prizeType = 0;
            uint32_t amount = 0;
            if (!reader.ReadByte(prizeType) ||
                !reader.SkipUtf() ||
                !reader.ReadU32(amount) ||
                !reader.SkipUtf()) {
                InterlockedIncrement(&g_parseError);
                return;
            }
        }
        if (!reader.SkipUtf() || !reader.SkipUtf()) {
            InterlockedIncrement(&g_parseError);
            return;
        }
        if (storedCount < static_cast<LONG>(kMaxRewards)) {
            parsed[storedCount++] = RewardEntry{ state, rewardId };
        }
    }

    if (activityType != kActivityType) {
        return;
    }

    std::memcpy(g_rewards, parsed, static_cast<size_t>(storedCount) * sizeof(RewardEntry));
    InterlockedExchange(&g_rewardCount, storedCount);
    InterlockedExchange(&g_detailType, static_cast<LONG>(activityType));
    InterlockedExchange(&g_detailId, static_cast<LONG>(activityId));
    InterlockedIncrement(&g_detailVersion);
}

void HandleRecvPacket(uint32_t opcode, const BYTE* payload, uint32_t payloadLength)
{
    if ((opcode & 0xFFFF) == 0x25ED) {
        HandleDetail(payload, payloadLength);
    }
}

void TickImpl()
{
    DrainPendingLog();
    if (!IsEnabled()) {
        if (InterlockedExchange(&g_wasEnabled, 0) != 0) {
            ResetState();
        }
        return;
    }

    const DWORD now = GetGameTick();
    if (InterlockedExchange(&g_wasEnabled, 1) == 0) {
        ResetState();
    }

    switch (g_state) {
    case 0:
        if (g_nextCheckTick != 0 &&
            static_cast<LONG>(now - static_cast<DWORD>(g_nextCheckTick)) < 0) {
            return;
        }
        ResetCycle();
        InterlockedExchange(&g_targetId, static_cast<LONG>(FindNativeActivityId()));
        if (g_targetId == 0) {
            InterlockedExchange(&g_nextCheckTick, static_cast<LONG>(now + kActivityMissingRetryMs));
            return;
        }
        SendQuery(now);
        InterlockedExchange(&g_state, 1);
        return;
    case 1:
        if (g_detailVersion != g_seenDetailVersion) {
            InterlockedExchange(&g_seenDetailVersion, g_detailVersion);
            ProcessClaimableRewards(now);
        } else if (static_cast<LONG>(now - static_cast<DWORD>(g_deadlineTick)) >= 0) {
            SendQuery(now);
        }
        return;
    case 2:
        if (static_cast<LONG>(now - static_cast<DWORD>(g_deadlineTick)) >= 0) {
            SendQuery(now);
            InterlockedExchange(&g_state, 3);
        }
        return;
    case 3:
        if (g_detailVersion != g_seenDetailVersion) {
            InterlockedExchange(&g_seenDetailVersion, g_detailVersion);
            const LONG pending = g_pendingReward;
            if (pending >= 0 && FindRewardState(pending) == 3) {
                InterlockedExchange(&g_pendingLogDay, pending + 1);
                InterlockedExchange(&g_pendingLog, 1);
                InterlockedIncrement(&g_verifiedCount);
                InterlockedExchange(&g_pendingReward, -1);
                InterlockedExchange(&g_verifyRetries, 0);
                InterlockedExchange(&g_deadlineTick, static_cast<LONG>(now + kNextClaimMs));
                InterlockedExchange(&g_state, 4);
            } else {
                RetryOrBlockPending(now);
            }
        } else if (static_cast<LONG>(now - static_cast<DWORD>(g_deadlineTick)) >= 0) {
            RetryOrBlockPending(now);
        }
        return;
    case 4:
        if (static_cast<LONG>(now - static_cast<DWORD>(g_deadlineTick)) >= 0) {
            ProcessClaimableRewards(now);
        }
        return;
    default:
        InterlockedExchange(&g_state, 0);
        return;
    }
}

void Tick()
{
    if (InterlockedCompareExchange(&g_tickRunning, 1, 0) != 0) {
        return;
    }
    __try {
        TickImpl();
    } __finally {
        InterlockedExchange(&g_tickRunning, 0);
    }
}

bool BuildDailyGuardCode(uintptr_t base, CodeBuffer& code)
{
    return AppendCmpDwordAbsImm8(code, static_cast<uint32_t>(base + kDailySwitchOffset), 0) &&
        AppendJeShort(code, 0x01) &&
        AppendByte(code, 0xC3) &&
        AppendFunctionPrologueWithStack(code, 0x14) &&
        AppendRel32Instruction(code, 0xE9, base + 0x39F26);
}

}

namespace TeamBattleReward
{
constexpr DWORD kRetryDelayMs = 30 * 60 * 1000;
constexpr DWORD kResponseTimeoutMs = 15000;

struct PacketReader
{
    const BYTE* cursor = nullptr;
    const BYTE* end = nullptr;

    bool ReadByte(BYTE& value)
    {
        if (!cursor || cursor >= end) {
            return false;
        }
        value = *cursor++;
        return true;
    }

    bool ReadU16(uint16_t& value)
    {
        if (!cursor || cursor + 2 > end) {
            return false;
        }
        value = ReadBe16Unaligned(cursor);
        cursor += 2;
        return true;
    }

    bool ReadU32(uint32_t& value)
    {
        if (!cursor || cursor + 4 > end) {
            return false;
        }
        value = ReadBe32Unaligned(cursor);
        cursor += 4;
        return true;
    }

    bool Skip(size_t length)
    {
        if (!cursor || length > static_cast<size_t>(end - cursor)) {
            return false;
        }
        cursor += length;
        return true;
    }

    bool SkipUtf()
    {
        uint16_t length = 0;
        return ReadU16(length) && Skip(length);
    }
};

volatile LONG g_tickRunning = 0;
volatile LONG g_wasEnabled = 0;
volatile LONG g_state = 0;
volatile LONG g_deadlineTick = 0;
volatile LONG g_dailyNextTick = 0;
volatile LONG g_rankNextTick = 0;
volatile LONG g_dailyDoneDate = 0;
volatile LONG g_rankDoneDate = 0;
volatile LONG g_pendingLog = 0;
volatile LONG g_parseError = 0;
volatile LONG g_dailyQueryCount = 0;
volatile LONG g_dailyClaimCount = 0;
volatile LONG g_rankQueryCount = 0;
volatile LONG g_rankClaimCount = 0;
volatile LONG g_dailySuccessCount = 0;
volatile LONG g_rankSuccessCount = 0;
BYTE g_dailyQueryPayload[4]{};

const wchar_t kLogFormat[] = L"%s";
const wchar_t kDailyRewardLog[] = L"\x7D44\x968A\x6230\x0020\x6BCF\x65E5\x734E\x52F5";
const wchar_t kRankRewardLog[] = L"\x7D44\x968A\x6230\x0020\x6230\x968A\x734E\x52F5";

bool IsEnabled()
{
    return TaskDispatchUi::g_teamBattleRewardSwitch != 0;
}

LONG DateKey(const SYSTEMTIME& time)
{
    return static_cast<LONG>(time.wYear * 10000 + time.wMonth * 100 + time.wDay);
}

bool TickReached(DWORD now, LONG target)
{
    return target == 0 || static_cast<LONG>(now - static_cast<DWORD>(target)) >= 0;
}

bool SkipBonusArray(PacketReader& reader, uint16_t* countOut = nullptr)
{
    uint16_t count = 0;
    if (!reader.ReadU16(count)) {
        return false;
    }
    if (countOut) {
        *countOut = count;
    }
    for (uint16_t index = 0; index < count; ++index) {
        if (!reader.Skip(6) || !reader.SkipUtf()) {
            return false;
        }
    }
    return true;
}

bool SkipRankList(PacketReader& reader)
{
    uint16_t rankCount = 0;
    if (!reader.ReadU16(rankCount)) {
        return false;
    }
    for (uint16_t rankIndex = 0; rankIndex < rankCount; ++rankIndex) {
        if (!reader.Skip(4) || !reader.SkipUtf() || !reader.Skip(6)) {
            return false;
        }
        uint16_t memberCount = 0;
        if (!reader.ReadU16(memberCount)) {
            return false;
        }
        for (uint16_t memberIndex = 0; memberIndex < memberCount; ++memberIndex) {
            if (!reader.Skip(8) || !reader.SkipUtf() || !reader.Skip(1) || !reader.SkipUtf()) {
                return false;
            }
        }
        if (!reader.SkipUtf()) {
            return false;
        }
    }
    return true;
}

bool ParseDailyPanel(const BYTE* payload, uint32_t payloadLength, bool& claimable)
{
    PacketReader reader{ payload, payload + payloadLength };
    uint32_t battleState = 0;
    BYTE receiveState = 0;
    uint32_t goldReward = 0;
    claimable = false;
    if (!reader.ReadU32(battleState) ||
        !reader.Skip(28) ||
        !reader.SkipUtf() ||
        !reader.Skip(18) ||
        !reader.SkipUtf() ||
        !reader.Skip(2) ||
        !SkipBonusArray(reader) ||
        !reader.ReadByte(receiveState) ||
        !reader.ReadU32(goldReward)) {
        return false;
    }
    claimable = battleState == 2 && receiveState == 0 && static_cast<int32_t>(goldReward) <= 0;
    return true;
}

bool ParseRankPanel(const BYTE* payload, uint32_t payloadLength, bool& claimable)
{
    PacketReader reader{ payload, payload + payloadLength };
    uint32_t ownRank = 0;
    uint16_t rewardCount = 0;
    BYTE receiveState = 0;
    uint32_t goldReward = 0;
    uint32_t teamBattleState = 0;
    claimable = false;
    if (!SkipRankList(reader) ||
        !reader.ReadU32(ownRank) ||
        !SkipBonusArray(reader, &rewardCount) ||
        !reader.ReadByte(receiveState) ||
        !reader.ReadU32(goldReward) ||
        !reader.ReadU32(teamBattleState) ||
        !reader.SkipUtf()) {
        return false;
    }
    claimable = teamBattleState != 1 &&
        ownRank > 0 &&
        rewardCount > 0 &&
        goldReward == 0 &&
        receiveState == 0;
    return true;
}

void SendPacket(uint32_t opcode, const void* payload, uint32_t payloadLength)
{
    using SendPacketFn = void(__stdcall*)(uint32_t, const void*, uint32_t);
    SendPacketFn sendPacket = reinterpret_cast<SendPacketFn>(g_mainBase + 0x4A360);
    sendPacket(opcode, payload, payloadLength);
}

void DrainPendingLog()
{
    const LONG pending = InterlockedExchange(&g_pendingLog, 0);
    if (pending == 1) {
        GameLog::Write(kLogFormat, kDailyRewardLog);
    } else if (pending == 2) {
        GameLog::Write(kLogFormat, kRankRewardLog);
    }
}

void ResetState()
{
    InterlockedExchange(&g_state, 0);
    InterlockedExchange(&g_deadlineTick, 0);
    InterlockedExchange(&g_dailyNextTick, 0);
    InterlockedExchange(&g_rankNextTick, 0);
}

void OnEnabledChanged(LONG enabled)
{
    InterlockedExchange(&g_wasEnabled, enabled != 0 ? 1 : 0);
    ResetState();
}

void HandleRecvPacket(uint32_t opcode, const BYTE* payload, uint32_t payloadLength)
{
    const uint32_t packetOpcode = opcode & 0xFFFF;
    const DWORD now = GetGameTick();
    if (packetOpcode == 0x34C4) {
        bool claimable = false;
        if (!ParseDailyPanel(payload, payloadLength, claimable)) {
            InterlockedIncrement(&g_parseError);
            return;
        }
        if (g_state != 1) {
            return;
        }
        if (claimable) {
            InterlockedExchange(&g_state, 2);
        } else {
            InterlockedExchange(&g_dailyNextTick, static_cast<LONG>(now + kRetryDelayMs));
            InterlockedExchange(&g_state, 0);
        }
        return;
    }
    if (packetOpcode == 0x34C3) {
        bool claimable = false;
        if (!ParseRankPanel(payload, payloadLength, claimable)) {
            InterlockedIncrement(&g_parseError);
            return;
        }
        if (g_state != 4) {
            return;
        }
        if (claimable) {
            InterlockedExchange(&g_state, 5);
        } else {
            InterlockedExchange(&g_rankNextTick, static_cast<LONG>(now + kRetryDelayMs));
            InterlockedExchange(&g_state, 0);
        }
        return;
    }
    if (packetOpcode == 0x34D5 && g_state == 3) {
        SYSTEMTIME localTime{};
        GetLocalTime(&localTime);
        InterlockedExchange(&g_dailyDoneDate, DateKey(localTime));
        InterlockedExchange(&g_dailyNextTick, 0);
        InterlockedExchange(&g_pendingLog, 1);
        InterlockedIncrement(&g_dailySuccessCount);
        InterlockedExchange(&g_state, 0);
        return;
    }
    if (packetOpcode == 0x34D6 && g_state == 6) {
        SYSTEMTIME localTime{};
        GetLocalTime(&localTime);
        InterlockedExchange(&g_rankDoneDate, DateKey(localTime));
        InterlockedExchange(&g_rankNextTick, 0);
        InterlockedExchange(&g_pendingLog, 2);
        InterlockedIncrement(&g_rankSuccessCount);
        InterlockedExchange(&g_state, 0);
    }
}

void TickImpl()
{
    DrainPendingLog();
    if (!IsEnabled()) {
        if (InterlockedExchange(&g_wasEnabled, 0) != 0) {
            ResetState();
        }
        return;
    }
    if (InterlockedExchange(&g_wasEnabled, 1) == 0) {
        ResetState();
    }

    const DWORD now = GetGameTick();
    const LONG state = g_state;
    if ((state == 1 || state == 3 || state == 4 || state == 6) &&
        TickReached(now, g_deadlineTick)) {
        if (state == 1 || state == 3) {
            InterlockedExchange(&g_dailyNextTick, static_cast<LONG>(now + kRetryDelayMs));
        } else {
            InterlockedExchange(&g_rankNextTick, static_cast<LONG>(now + kRetryDelayMs));
        }
        InterlockedExchange(&g_state, 0);
        return;
    }
    if (state == 2) {
        InterlockedExchange(&g_deadlineTick, static_cast<LONG>(now + kResponseTimeoutMs));
        InterlockedExchange(&g_state, 3);
        InterlockedIncrement(&g_dailyClaimCount);
        SendPacket(0x34C7, nullptr, 0);
        return;
    }
    if (state == 5) {
        InterlockedExchange(&g_deadlineTick, static_cast<LONG>(now + kResponseTimeoutMs));
        InterlockedExchange(&g_state, 6);
        InterlockedIncrement(&g_rankClaimCount);
        SendPacket(0x34C6, nullptr, 0);
        return;
    }
    if (state != 0) {
        return;
    }

    SYSTEMTIME localTime{};
    GetLocalTime(&localTime);
    const LONG today = DateKey(localTime);
    if (localTime.wHour >= 16 &&
        g_dailyDoneDate != today &&
        TickReached(now, g_dailyNextTick)) {
        InterlockedExchange(&g_deadlineTick, static_cast<LONG>(now + kResponseTimeoutMs));
        InterlockedExchange(&g_state, 1);
        InterlockedIncrement(&g_dailyQueryCount);
        SendPacket(0x34C0, g_dailyQueryPayload, sizeof(g_dailyQueryPayload));
        return;
    }
    if (localTime.wDayOfWeek == 0 &&
        localTime.wHour >= 16 &&
        g_rankDoneDate != today &&
        TickReached(now, g_rankNextTick)) {
        InterlockedExchange(&g_deadlineTick, static_cast<LONG>(now + kResponseTimeoutMs));
        InterlockedExchange(&g_state, 4);
        InterlockedIncrement(&g_rankQueryCount);
        SendPacket(0x34BF, nullptr, 0);
    }
}

void Tick()
{
    if (InterlockedCompareExchange(&g_tickRunning, 1, 0) != 0) {
        return;
    }
    __try {
        TickImpl();
    } __finally {
        InterlockedExchange(&g_tickRunning, 0);
    }
}

}

namespace BattleToken
{
constexpr DWORD kSendGapMs = 400;
constexpr DWORD kResponseTimeoutMs = 10000;
constexpr DWORD kCycleIntervalMs = 30000;
constexpr size_t kMaxTaskRewards = 128;
constexpr size_t kMaxLevelRewards = 256;
constexpr size_t kTaskDescriptionLength = 256;

struct TaskReward
{
    uint32_t week = 0;
    uint32_t taskId = 0;
    wchar_t description[kTaskDescriptionLength]{};
};

struct LevelReward
{
    uint32_t type = 0;
    uint32_t level = 0;
};

struct PacketReader
{
    const BYTE* cursor = nullptr;
    const BYTE* end = nullptr;

    bool ReadByte(BYTE& value)
    {
        if (!cursor || cursor >= end) {
            return false;
        }
        value = *cursor++;
        return true;
    }

    bool ReadU16(uint16_t& value)
    {
        if (!cursor || cursor + 2 > end) {
            return false;
        }
        value = ReadBe16Unaligned(cursor);
        cursor += 2;
        return true;
    }

    bool ReadU32(uint32_t& value)
    {
        if (!cursor || cursor + 4 > end) {
            return false;
        }
        value = ReadBe32Unaligned(cursor);
        cursor += 4;
        return true;
    }

    bool Skip(size_t length)
    {
        if (!cursor || length > static_cast<size_t>(end - cursor)) {
            return false;
        }
        cursor += length;
        return true;
    }

    bool SkipUtf()
    {
        uint16_t length = 0;
        return ReadU16(length) && Skip(length);
    }

    bool ReadUtf(wchar_t* output, size_t capacity)
    {
        uint16_t length = 0;
        if (!ReadU16(length) || length > static_cast<size_t>(end - cursor)) {
            return false;
        }

        if (output && capacity != 0) {
            output[0] = L'\0';
            if (length != 0) {
                const int converted = MultiByteToWideChar(
                    CP_UTF8,
                    0,
                    reinterpret_cast<const char*>(cursor),
                    length,
                    output,
                    static_cast<int>(capacity - 1));
                if (converted > 0) {
                    output[converted] = L'\0';
                }
            }
        }

        cursor += length;
        return true;
    }
};

volatile LONG g_state = 0;
volatile LONG g_lastSendTick = 0;
volatile LONG g_deadlineTick = 0;
volatile LONG g_cycleTick = 0;
volatile LONG g_currentLevel = 0;
volatile LONG g_parseError = 0;
volatile LONG g_taskCount = 0;
volatile LONG g_taskIndex = 0;
volatile LONG g_levelRewardCount = 0;
volatile LONG g_levelRewardIndex = 0;
volatile LONG g_pendingLevel = 0;
volatile LONG g_pendingType = 0;
volatile LONG g_pendingLevelValid = 0;
volatile LONG g_lastTaskAck = -1;
volatile LONG g_lastLevelAck = -1;
volatile LONG g_tickRunning = 0;
volatile LONG g_pendingTaskLog = 0;
volatile LONG g_pendingTaskLogWeek = 0;
volatile LONG g_pendingLevelLog = 0;
volatile LONG g_pendingLevelLogLevel = 0;
TaskReward g_taskRewards[kMaxTaskRewards]{};
LevelReward g_levelRewards[kMaxLevelRewards]{};
WCHAR g_pendingTaskLogDescription[kTaskDescriptionLength]{};
BYTE g_taskPayload[8]{};
BYTE g_levelPayload[8]{};

const wchar_t kTaskRewardLog[] = L"\x6230\x4EE4\xFF1A\x9818\x53D6\x7B2C%d\x9031\x300C%s\x300D\x4EFB\x52D9\x734E\x52F5";
const wchar_t kLevelRewardLog[] = L"\x6230\x4EE4\xFF1A\x9818\x53D6\x7B2C%d\x7D1A\x6230\x4EE4\x734E\x52F5";

void RefreshBattleTokenLog()
{
    using RefreshLogFn = void(__stdcall*)(uint32_t, uint32_t, uint32_t, uint32_t);
    RefreshLogFn refreshLog = *reinterpret_cast<RefreshLogFn*>(g_mainBase + 0x1C46B0);
    if (refreshLog) {
        refreshLog(
            ReadGameU32(g_mainBase + 0x2300A4),
            ReadGameU32(g_mainBase + 0x2304D8),
            0,
            0);
    }
}

void WriteTaskRewardLog(LONG week, const wchar_t* description)
{
    using PrintLogFn = void(__cdecl*)(uintptr_t, const wchar_t*, ...);
    PrintLogFn printLog = reinterpret_cast<PrintLogFn>(g_mainBase + 0x2EF0);
    printLog(g_mainBase + 0x230504, kTaskRewardLog, week, description ? description : L"");
    RefreshBattleTokenLog();
}

void WriteLevelRewardLog(LONG level)
{
    using PrintLogFn = void(__cdecl*)(uintptr_t, const wchar_t*, ...);
    PrintLogFn printLog = reinterpret_cast<PrintLogFn>(g_mainBase + 0x2EF0);
    printLog(g_mainBase + 0x230504, kLevelRewardLog, level);
    RefreshBattleTokenLog();
}

void QueueTaskRewardLog(const TaskReward& reward)
{
    InterlockedExchange(&g_pendingTaskLogWeek, static_cast<LONG>(reward.week));
    std::wcsncpy(g_pendingTaskLogDescription, reward.description, kTaskDescriptionLength - 1);
    g_pendingTaskLogDescription[kTaskDescriptionLength - 1] = L'\0';
    InterlockedExchange(&g_pendingTaskLog, 1);
}

void QueueLevelRewardLog(uint32_t level)
{
    InterlockedExchange(&g_pendingLevelLogLevel, static_cast<LONG>(level));
    InterlockedExchange(&g_pendingLevelLog, 1);
}

void DrainPendingLogs()
{
    if (InterlockedExchange(&g_pendingTaskLog, 0) != 0) {
        WriteTaskRewardLog(g_pendingTaskLogWeek, g_pendingTaskLogDescription);
    }
    if (InterlockedExchange(&g_pendingLevelLog, 0) != 0) {
        WriteLevelRewardLog(g_pendingLevelLogLevel);
    }
}

bool IsEnabled()
{
    return TaskDispatchUi::g_battleTokenSwitch != 0;
}

void ResetState()
{
    InterlockedExchange(&g_state, 0);
    InterlockedExchange(&g_lastSendTick, 0);
    InterlockedExchange(&g_deadlineTick, 0);
    InterlockedExchange(&g_cycleTick, 0);
    InterlockedExchange(&g_taskCount, 0);
    InterlockedExchange(&g_taskIndex, 0);
    InterlockedExchange(&g_levelRewardCount, 0);
    InterlockedExchange(&g_levelRewardIndex, 0);
    InterlockedExchange(&g_pendingLevelValid, 0);
}

void OnEnabledChanged(LONG enabled)
{
    ResetState();
    if (enabled != 0) {
        InterlockedExchange(&g_state, 0);
    }
}

void WriteBe32(BYTE* output, uint32_t value)
{
    output[0] = static_cast<BYTE>((value >> 24) & 0xFF);
    output[1] = static_cast<BYTE>((value >> 16) & 0xFF);
    output[2] = static_cast<BYTE>((value >> 8) & 0xFF);
    output[3] = static_cast<BYTE>(value & 0xFF);
}

void SendPacket(uint32_t opcode, const void* payload, uint32_t payloadLength)
{
    using SendPacketFn = void(__stdcall*)(uint32_t, const void*, uint32_t);
    SendPacketFn sendPacket = reinterpret_cast<SendPacketFn>(g_mainBase + 0x4A360);
    sendPacket(opcode, payload, payloadLength);
}

bool SkipBonusArray(PacketReader& reader)
{
    uint16_t count = 0;
    if (!reader.ReadU16(count)) {
        return false;
    }
    for (uint16_t i = 0; i < count; ++i) {
        if (!reader.Skip(6) || !reader.SkipUtf()) {
            return false;
        }
    }
    return true;
}

bool ParseLevelRewardArray(PacketReader& reader, bool& pendingStillClaimable)
{
    uint16_t count = 0;
    if (!reader.ReadU16(count)) {
        return false;
    }

    for (uint16_t i = 0; i < count; ++i) {
        uint32_t level = 0;
        uint32_t type = 0;
        uint32_t state = 0;
        if (!reader.ReadU32(level) || !reader.ReadU32(type) || !reader.ReadU32(state) ||
            !SkipBonusArray(reader) || !reader.SkipUtf()) {
            return false;
        }

        if (state != 1) {
            continue;
        }
        if (g_pendingLevelValid != 0 &&
            level == static_cast<uint32_t>(g_pendingLevel) &&
            type == static_cast<uint32_t>(g_pendingType)) {
            pendingStillClaimable = true;
        }
        if (level > static_cast<uint32_t>(g_currentLevel)) {
            continue;
        }

        const LONG index = g_levelRewardCount;
        if (index < 0 || index >= static_cast<LONG>(kMaxLevelRewards)) {
            continue;
        }
        g_levelRewards[index].type = type;
        g_levelRewards[index].level = level;
        InterlockedExchange(&g_levelRewardCount, index + 1);
    }
    return true;
}

void HandlePanel(const BYTE* payload, uint32_t payloadLength)
{
    const LONG state = g_state;
    if ((state != 1 && state != 7) || !payload) {
        return;
    }

    PacketReader reader{ payload, payload + payloadLength };
    uint32_t level = 0;
    bool pendingStillClaimable = false;
    InterlockedExchange(&g_parseError, 0);
    InterlockedExchange(&g_levelRewardCount, 0);
    InterlockedExchange(&g_levelRewardIndex, 0);

    if (!reader.Skip(8) || !reader.SkipUtf() || !reader.ReadU32(level)) {
        InterlockedExchange(&g_parseError, 1);
        InterlockedExchange(&g_state, state == 1 ? 0 : 6);
        return;
    }
    InterlockedExchange(&g_currentLevel, static_cast<LONG>(level));

    if (!reader.Skip(11) ||
        !ParseLevelRewardArray(reader, pendingStillClaimable) ||
        !ParseLevelRewardArray(reader, pendingStillClaimable) ||
        !reader.SkipUtf() || !reader.SkipUtf() || !reader.Skip(8) ||
        !reader.SkipUtf() || !reader.SkipUtf()) {
        InterlockedExchange(&g_parseError, 1);
        InterlockedExchange(&g_levelRewardCount, 0);
        InterlockedExchange(&g_state, state == 1 ? 0 : 6);
        return;
    }

    if (state == 7 && g_pendingLevelValid != 0 && !pendingStillClaimable) {
        QueueLevelRewardLog(static_cast<uint32_t>(g_pendingLevel));
        InterlockedExchange(&g_pendingLevelValid, 0);
    }
    InterlockedExchange(&g_state, state == 1 ? 2 : 8);
}

void HandleTaskPanel(const BYTE* payload, uint32_t payloadLength)
{
    if (g_state != 3 || !payload) {
        return;
    }

    PacketReader reader{ payload, payload + payloadLength };
    InterlockedExchange(&g_parseError, 0);
    InterlockedExchange(&g_taskCount, 0);
    InterlockedExchange(&g_taskIndex, 0);

    if (!reader.Skip(9)) {
        InterlockedExchange(&g_parseError, 1);
        InterlockedExchange(&g_state, 2);
        return;
    }

    uint16_t weekCount = 0;
    if (!reader.ReadU16(weekCount)) {
        InterlockedExchange(&g_parseError, 1);
        InterlockedExchange(&g_state, 2);
        return;
    }

    for (uint16_t weekIndex = 0; weekIndex < weekCount; ++weekIndex) {
        uint32_t week = 0;
        uint16_t taskCount = 0;
        if (!reader.ReadU32(week) || !reader.Skip(9) || !reader.ReadU16(taskCount)) {
            InterlockedExchange(&g_parseError, 1);
            InterlockedExchange(&g_taskCount, 0);
            InterlockedExchange(&g_state, 2);
            return;
        }

        for (uint16_t taskIndex = 0; taskIndex < taskCount; ++taskIndex) {
            uint32_t taskId = 0;
            uint32_t taskState = 0;
            wchar_t description[kTaskDescriptionLength]{};
            if (!reader.ReadU32(taskId) || !reader.Skip(4) ||
                !reader.ReadUtf(description, _countof(description)) ||
                !reader.Skip(8) || !reader.ReadU32(taskState) ||
                !SkipBonusArray(reader) || !reader.SkipUtf()) {
                InterlockedExchange(&g_parseError, 1);
                InterlockedExchange(&g_taskCount, 0);
                InterlockedExchange(&g_state, 2);
                return;
            }

            if (taskState != 1) {
                continue;
            }
            const LONG queueIndex = g_taskCount;
            if (queueIndex < 0 || queueIndex >= static_cast<LONG>(kMaxTaskRewards)) {
                continue;
            }
            g_taskRewards[queueIndex].week = week;
            g_taskRewards[queueIndex].taskId = taskId;
            std::wcsncpy(
                g_taskRewards[queueIndex].description,
                description,
                kTaskDescriptionLength - 1);
            g_taskRewards[queueIndex].description[kTaskDescriptionLength - 1] = L'\0';
            InterlockedExchange(&g_taskCount, queueIndex + 1);
        }

        if (!reader.SkipUtf()) {
            InterlockedExchange(&g_parseError, 1);
            InterlockedExchange(&g_taskCount, 0);
            InterlockedExchange(&g_state, 2);
            return;
        }
    }

    if (!reader.SkipUtf()) {
        InterlockedExchange(&g_parseError, 1);
        InterlockedExchange(&g_taskCount, 0);
        InterlockedExchange(&g_state, 2);
        return;
    }
    InterlockedExchange(&g_state, 4);
}

void HandleTaskAck(const BYTE* payload, uint32_t payloadLength)
{
    if (g_state != 5 || !payload || payloadLength < 1) {
        return;
    }
    const LONG ack = payload[0];
    InterlockedExchange(&g_lastTaskAck, ack);
    const LONG index = g_taskIndex;
    if (ack == 1 && index >= 0 && index < g_taskCount) {
        QueueTaskRewardLog(g_taskRewards[index]);
    }
    InterlockedExchange(&g_taskIndex, index + 1);
    InterlockedExchange(&g_state, 4);
}

void HandleLevelAck(const BYTE* payload, uint32_t payloadLength)
{
    if (g_state != 9 || !payload || payloadLength < 1) {
        return;
    }
    const LONG ack = payload[0];
    InterlockedExchange(&g_lastLevelAck, ack);
    const LONG index = g_levelRewardIndex;
    if (ack == 1 && index >= 0 && index < g_levelRewardCount) {
        QueueLevelRewardLog(g_levelRewards[index].level);
        InterlockedExchange(&g_pendingLevelValid, 0);
    }
    InterlockedExchange(&g_levelRewardIndex, index + 1);
    InterlockedExchange(&g_state, 8);
}

void HandleRecvPacket(uint32_t opcode, const BYTE* payload, uint32_t payloadLength)
{
    if (!IsEnabled()) {
        return;
    }
    switch (opcode & 0xFFFF) {
    case 0x478C:
        HandlePanel(payload, payloadLength);
        break;
    case 0x4792:
        HandleTaskPanel(payload, payloadLength);
        break;
    case 0x4794:
        HandleTaskAck(payload, payloadLength);
        break;
    case 0x4796:
        HandleLevelAck(payload, payloadLength);
        break;
    default:
        break;
    }
}

void SetWaitingState(LONG state, DWORD now)
{
    InterlockedExchange(&g_lastSendTick, static_cast<LONG>(now));
    InterlockedExchange(&g_deadlineTick, static_cast<LONG>(now + kResponseTimeoutMs));
    InterlockedExchange(&g_state, state);
}

void SendInitialPanel(DWORD now)
{
    InterlockedExchange(&g_taskCount, 0);
    InterlockedExchange(&g_taskIndex, 0);
    InterlockedExchange(&g_levelRewardCount, 0);
    InterlockedExchange(&g_levelRewardIndex, 0);
    SetWaitingState(1, now);
    SendPacket(0x478B, nullptr, 0);
}

void SendTaskPanel(DWORD now)
{
    InterlockedExchange(&g_taskCount, 0);
    InterlockedExchange(&g_taskIndex, 0);
    SetWaitingState(3, now);
    SendPacket(0x4791, nullptr, 0);
}

void SendTaskReward(DWORD now)
{
    const LONG index = g_taskIndex;
    if (index < 0 || index >= g_taskCount) {
        InterlockedExchange(&g_state, 6);
        return;
    }
    WriteBe32(g_taskPayload, g_taskRewards[index].week);
    WriteBe32(g_taskPayload + 4, g_taskRewards[index].taskId);
    SetWaitingState(5, now);
    SendPacket(0x4793, g_taskPayload, sizeof(g_taskPayload));
}

void SendFinalPanel(DWORD now)
{
    InterlockedExchange(&g_levelRewardCount, 0);
    InterlockedExchange(&g_levelRewardIndex, 0);
    SetWaitingState(7, now);
    SendPacket(0x478B, nullptr, 0);
}

void SendLevelReward(DWORD now)
{
    const LONG index = g_levelRewardIndex;
    if (index < 0 || index >= g_levelRewardCount) {
        InterlockedExchange(&g_cycleTick, static_cast<LONG>(now));
        InterlockedExchange(&g_state, 10);
        return;
    }
    const LevelReward reward = g_levelRewards[index];
    WriteBe32(g_levelPayload, reward.type);
    WriteBe32(g_levelPayload + 4, reward.level);
    InterlockedExchange(&g_pendingType, static_cast<LONG>(reward.type));
    InterlockedExchange(&g_pendingLevel, static_cast<LONG>(reward.level));
    InterlockedExchange(&g_pendingLevelValid, 1);
    SetWaitingState(9, now);
    SendPacket(0x4795, g_levelPayload, sizeof(g_levelPayload));
}

void TickImpl()
{
    DrainPendingLogs();
    if (!IsEnabled()) {
        ResetState();
        return;
    }

    const DWORD now = GetGameTick();
    if (now - static_cast<DWORD>(g_lastSendTick) < kSendGapMs) {
        return;
    }

    switch (g_state) {
    case 0:
        SendInitialPanel(now);
        return;
    case 2:
        SendTaskPanel(now);
        return;
    case 4:
        if (g_taskIndex >= g_taskCount) {
            SendFinalPanel(now);
        } else {
            SendTaskReward(now);
        }
        return;
    case 6:
        SendFinalPanel(now);
        return;
    case 8:
        SendLevelReward(now);
        return;
    case 10:
        if (now - static_cast<DWORD>(g_cycleTick) >= kCycleIntervalMs) {
            InterlockedExchange(&g_state, 0);
        }
        return;
    default:
        break;
    }

    if (static_cast<LONG>(now - static_cast<DWORD>(g_deadlineTick)) < 0) {
        return;
    }
    switch (g_state) {
    case 1:
        SendInitialPanel(now);
        break;
    case 3:
    case 5:
        SendTaskPanel(now);
        break;
    case 7:
    case 9:
        SendFinalPanel(now);
        break;
    default:
        InterlockedExchange(&g_state, 0);
        break;
    }
}

__declspec(noinline) void Tick()
{
    if (InterlockedCompareExchange(&g_tickRunning, 1, 0) != 0) {
        return;
    }
    __try {
        TickImpl();
    } __finally {
        InterlockedExchange(&g_tickRunning, 0);
    }
}

}

namespace ZhaoXianNaKe
{
constexpr DWORD kSendGapMs = 400;
constexpr DWORD kResponseTimeoutMs = 10000;
constexpr DWORD kIdleIntervalMs = 300000;
constexpr uint32_t kRequiredMotivateCount = 4;
constexpr size_t kNameLength = 64;

enum Action : LONG
{
    kActionNone = 0,
    kActionRecruit = 1,
    kActionMotivate = 2,
    kActionCollect = 3
};

struct PacketReader
{
    const BYTE* cursor = nullptr;
    const BYTE* end = nullptr;

    bool ReadByte(BYTE& value)
    {
        if (!cursor || cursor >= end) {
            return false;
        }
        value = *cursor++;
        return true;
    }

    bool ReadU16(uint16_t& value)
    {
        if (!cursor || cursor + 2 > end) {
            return false;
        }
        value = ReadBe16Unaligned(cursor);
        cursor += 2;
        return true;
    }

    bool ReadU32(uint32_t& value)
    {
        if (!cursor || cursor + 4 > end) {
            return false;
        }
        value = ReadBe32Unaligned(cursor);
        cursor += 4;
        return true;
    }

    bool Skip(size_t length)
    {
        if (!cursor || length > static_cast<size_t>(end - cursor)) {
            return false;
        }
        cursor += length;
        return true;
    }

    bool SkipUtf()
    {
        uint16_t length = 0;
        return ReadU16(length) && Skip(length);
    }

    bool ReadUtf(wchar_t* output, size_t capacity)
    {
        uint16_t length = 0;
        if (!ReadU16(length) || length > static_cast<size_t>(end - cursor)) {
            return false;
        }
        if (output && capacity != 0) {
            output[0] = L'\0';
            if (length != 0) {
                const int converted = MultiByteToWideChar(
                    CP_UTF8,
                    0,
                    reinterpret_cast<const char*>(cursor),
                    length,
                    output,
                    static_cast<int>(capacity - 1));
                if (converted > 0) {
                    output[converted] = L'\0';
                }
            }
        }
        cursor += length;
        return true;
    }
};

volatile LONG g_state = 0;
volatile LONG g_lastSendTick = 0;
volatile LONG g_deadlineTick = 0;
volatile LONG g_cycleTick = 0;
volatile LONG g_tickRunning = 0;
volatile LONG g_pendingAction = kActionNone;
volatile LONG g_pendingId = 0;
volatile LONG g_pendingBonusType = 0;
volatile LONG g_pendingBeforeMotivate = 0;
volatile LONG g_pendingBeforeCollect = 0;
volatile LONG g_pendingLogAction = kActionNone;
wchar_t g_pendingName[kNameLength]{};
wchar_t g_pendingLogName[kNameLength]{};
BYTE g_actionPayload[8]{};

const wchar_t kMotivateLog[] = {
    0x62DB, 0x52DF, 0x8CE2, 0x5BA2, 0x0020, 0x0028, 0x0025, 0x0073,
    0x0029, 0x0020, 0x8AEB, 0x8A00, 0x0000
};
const wchar_t kCollectLog[] = {
    0x62DB, 0x52DF, 0x8CE2, 0x5BA2, 0x0020, 0x0028, 0x0025, 0x0073,
    0x0029, 0x0020, 0x7D0D, 0x8AEB, 0x0000
};

bool IsEnabled()
{
    return TaskDispatchUi::g_zhaoXianNaKeSwitch != 0;
}

void WriteBe32(BYTE* output, uint32_t value)
{
    output[0] = static_cast<BYTE>((value >> 24) & 0xFF);
    output[1] = static_cast<BYTE>((value >> 16) & 0xFF);
    output[2] = static_cast<BYTE>((value >> 8) & 0xFF);
    output[3] = static_cast<BYTE>(value & 0xFF);
}

void SendPacket(uint32_t opcode, const void* payload, uint32_t payloadLength)
{
    using SendPacketFn = void(__stdcall*)(uint32_t, const void*, uint32_t);
    SendPacketFn sendPacket = reinterpret_cast<SendPacketFn>(g_mainBase + 0x4A360);
    sendPacket(opcode, payload, payloadLength);
}

void ResetState()
{
    InterlockedExchange(&g_state, 0);
    InterlockedExchange(&g_lastSendTick, 0);
    InterlockedExchange(&g_deadlineTick, 0);
    InterlockedExchange(&g_cycleTick, 0);
    InterlockedExchange(&g_pendingAction, kActionNone);
}

void OnEnabledChanged(LONG)
{
    ResetState();
}

void QueueActionLog(LONG action, const wchar_t* name)
{
    if (action != kActionMotivate && action != kActionCollect) {
        return;
    }
    std::wcsncpy(g_pendingLogName, name ? name : L"", kNameLength - 1);
    g_pendingLogName[kNameLength - 1] = L'\0';
    InterlockedExchange(&g_pendingLogAction, action);
}

void WriteActionLog(const wchar_t* format, const wchar_t* name)
{
    using PrintLogFn = void(__cdecl*)(uintptr_t, const wchar_t*, ...);
    using RefreshLogFn = void(__stdcall*)(uint32_t, uint32_t, uint32_t, uint32_t);
    PrintLogFn printLog = reinterpret_cast<PrintLogFn>(g_mainBase + 0x2EF0);
    printLog(g_mainBase + 0x230504, format, name ? name : L"");
    RefreshLogFn refreshLog = *reinterpret_cast<RefreshLogFn*>(g_mainBase + 0x1C46B0);
    if (refreshLog) {
        refreshLog(
            ReadGameU32(g_mainBase + 0x2300A4),
            ReadGameU32(g_mainBase + 0x2304D8),
            0,
            0);
    }
}

void DrainPendingLog()
{
    const LONG action = InterlockedExchange(&g_pendingLogAction, kActionNone);
    if (action == kActionMotivate) {
        WriteActionLog(kMotivateLog, g_pendingLogName);
    } else if (action == kActionCollect) {
        WriteActionLog(kCollectLog, g_pendingLogName);
    }
}

bool SkipBonusArray(PacketReader& reader)
{
    uint16_t count = 0;
    if (!reader.ReadU16(count)) {
        return false;
    }
    for (uint16_t i = 0; i < count; ++i) {
        if (!reader.Skip(6) || !reader.SkipUtf()) {
            return false;
        }
    }
    return true;
}

bool ReadBonusSelection(PacketReader& reader, uint16_t& chosenType)
{
    uint16_t count = 0;
    if (!reader.ReadU16(count)) {
        return false;
    }
    uint16_t firstType = 0;
    uint16_t defaultType = 0;
    uint16_t selectedType = 0;
    for (uint16_t i = 0; i < count; ++i) {
        uint16_t type = 0;
        uint32_t value = 0;
        wchar_t extra[128]{};
        if (!reader.ReadU16(type) || !reader.ReadU32(value) ||
            !reader.ReadUtf(extra, _countof(extra))) {
            return false;
        }
        if (i == 0) {
            firstType = type;
        }
        if (std::wcsstr(extra, L"\"selectedBonus\":true")) {
            selectedType = type;
        }
        if (std::wcsstr(extra, L"\"defaultBonus\":true")) {
            defaultType = type;
        }
    }
    chosenType = selectedType != 0 ? selectedType : (defaultType != 0 ? defaultType : firstType);
    return true;
}

void CommitAction(LONG action, uint32_t id, uint16_t bonusType,
    uint32_t beforeMotivate, uint32_t beforeCollect, const wchar_t* name)
{
    InterlockedExchange(&g_pendingAction, action);
    InterlockedExchange(&g_pendingId, static_cast<LONG>(id));
    InterlockedExchange(&g_pendingBonusType, static_cast<LONG>(bonusType));
    InterlockedExchange(&g_pendingBeforeMotivate, static_cast<LONG>(beforeMotivate));
    InterlockedExchange(&g_pendingBeforeCollect, static_cast<LONG>(beforeCollect));
    std::wcsncpy(g_pendingName, name ? name : L"", kNameLength - 1);
    g_pendingName[kNameLength - 1] = L'\0';
}

void HandleMainPanel(const BYTE* payload, uint32_t payloadLength)
{
    const LONG state = g_state;
    if ((state != 1 && state != 5) || !payload) {
        return;
    }

    PacketReader reader{ payload, payload + payloadLength };
    uint16_t taskCount = 0;
    if (!reader.ReadU16(taskCount)) {
        InterlockedExchange(&g_state, 0);
        return;
    }
    for (uint16_t i = 0; i < taskCount; ++i) {
        if (!reader.SkipUtf() || !reader.Skip(8) || !reader.SkipUtf()) {
            InterlockedExchange(&g_state, 0);
            return;
        }
    }

    uint16_t menkeCount = 0;
    if (!reader.ReadU16(menkeCount)) {
        InterlockedExchange(&g_state, 0);
        return;
    }

    bool candidateValid = false;
    LONG candidateAction = kActionNone;
    uint32_t candidateId = 0;
    uint16_t candidateBonusType = 0;
    uint32_t candidateMotivate = 0;
    uint32_t candidateCollect = 0;
    wchar_t candidateName[kNameLength]{};
    bool pendingSucceeded = false;

    for (uint16_t i = 0; i < menkeCount; ++i) {
        uint32_t id = 0;
        wchar_t name[kNameLength]{};
        uint32_t icon = 0;
        uint32_t curCollect = 0;
        uint32_t maxCollect = 0;
        uint16_t bonusType = 0;
        uint32_t curMotivate = 0;
        uint32_t maxMotivate = 0;
        uint32_t outputAdd = 0;
        uint32_t menkeState = 0;
        uint32_t rarity = 0;
        BYTE collectToday = 0;
        uint32_t talkState = 0;
        if (!reader.ReadU32(id) || !reader.ReadUtf(name, _countof(name)) ||
            !reader.ReadU32(icon) || !reader.ReadU32(curCollect) ||
            !reader.ReadU32(maxCollect) || !ReadBonusSelection(reader, bonusType) ||
            !reader.ReadU32(curMotivate) || !reader.ReadU32(maxMotivate) ||
            !reader.ReadU32(outputAdd) || !reader.ReadU32(menkeState) ||
            !reader.ReadU32(rarity) || !reader.ReadByte(collectToday) ||
            !reader.ReadU32(talkState) || !reader.SkipUtf()) {
            InterlockedExchange(&g_state, 0);
            return;
        }

        if (state == 5 && id == static_cast<uint32_t>(g_pendingId)) {
            if (g_pendingAction == kActionMotivate &&
                curMotivate > static_cast<uint32_t>(g_pendingBeforeMotivate)) {
                pendingSucceeded = true;
            } else if (g_pendingAction == kActionCollect &&
                (curCollect > static_cast<uint32_t>(g_pendingBeforeCollect) || collectToday == 0)) {
                pendingSucceeded = true;
            }
        }

        if (!candidateValid && curCollect < maxCollect && collectToday != 0 && bonusType != 0 &&
            (curMotivate >= kRequiredMotivateCount || curMotivate < maxMotivate)) {
            candidateValid = true;
            candidateAction = curMotivate >= kRequiredMotivateCount ? kActionCollect : kActionMotivate;
            candidateId = id;
            candidateBonusType = bonusType;
            candidateMotivate = curMotivate;
            candidateCollect = curCollect;
            std::wcsncpy(candidateName, name, kNameLength - 1);
            candidateName[kNameLength - 1] = L'\0';
        }
    }

    BYTE canRecruit = 0;
    if (!reader.ReadByte(canRecruit) || !reader.SkipUtf()) {
        InterlockedExchange(&g_state, 0);
        return;
    }

    if (state == 5) {
        if (pendingSucceeded) {
            QueueActionLog(g_pendingAction, g_pendingName);
        }
        InterlockedExchange(&g_pendingAction, kActionNone);
    }

    if (canRecruit != 0) {
        InterlockedExchange(&g_state, 2);
    } else if (candidateValid) {
        CommitAction(candidateAction, candidateId, candidateBonusType,
            candidateMotivate, candidateCollect, candidateName);
        InterlockedExchange(&g_state, 4);
    } else {
        InterlockedExchange(&g_cycleTick, static_cast<LONG>(GetGameTick()));
        InterlockedExchange(&g_state, 10);
    }
}

void HandleRecruitPanel(const BYTE* payload, uint32_t payloadLength)
{
    const LONG state = g_state;
    if ((state != 3 && state != 6) || !payload) {
        return;
    }
    PacketReader reader{ payload, payload + payloadLength };
    uint16_t count = 0;
    if (!reader.ReadU16(count)) {
        InterlockedExchange(&g_state, 0);
        return;
    }

    bool candidateValid = false;
    uint32_t candidateTaskId = 0;
    wchar_t candidateName[kNameLength]{};
    bool pendingFound = false;
    uint32_t pendingState = 0;

    for (uint16_t i = 0; i < count; ++i) {
        uint32_t taskId = 0;
        uint32_t current = 0;
        uint32_t maximum = 0;
        uint32_t maxCollect = 0;
        uint32_t rarity = 0;
        uint32_t menkeState = 0;
        wchar_t taskName[128]{};
        wchar_t menkeName[kNameLength]{};
        if (!reader.ReadU32(taskId) || !reader.ReadUtf(taskName, _countof(taskName)) ||
            !reader.ReadU32(current) || !reader.ReadU32(maximum) ||
            !reader.ReadUtf(menkeName, _countof(menkeName)) ||
            !reader.ReadU32(maxCollect) || !reader.ReadU32(rarity) ||
            !reader.ReadU32(menkeState) || !SkipBonusArray(reader) || !reader.SkipUtf()) {
            InterlockedExchange(&g_state, 0);
            return;
        }
        if (state == 6 && taskId == static_cast<uint32_t>(g_pendingId)) {
            pendingFound = true;
            pendingState = menkeState;
        }
        if (!candidateValid && menkeState == 1) {
            candidateValid = true;
            candidateTaskId = taskId;
            std::wcsncpy(candidateName, menkeName, kNameLength - 1);
            candidateName[kNameLength - 1] = L'\0';
        }
    }

    uint32_t days = 0;
    if (!reader.ReadU32(days) || !reader.SkipUtf()) {
        InterlockedExchange(&g_state, 0);
        return;
    }

    if (state == 6) {
        if (pendingFound && pendingState == 1) {
            InterlockedExchange(&g_state, 4);
        } else {
            InterlockedExchange(&g_pendingAction, kActionNone);
            InterlockedExchange(&g_state, 0);
        }
        return;
    }

    if (candidateValid) {
        CommitAction(kActionRecruit, candidateTaskId, 0, 0, 0, candidateName);
        InterlockedExchange(&g_state, 4);
    } else {
        InterlockedExchange(&g_state, 0);
    }
}

void HandleRecvPacket(uint32_t opcode, const BYTE* payload, uint32_t payloadLength)
{
    if (!IsEnabled()) {
        return;
    }
    switch (opcode & 0xFFFF) {
    case 0x5359:
        HandleMainPanel(payload, payloadLength);
        break;
    case 0x535D:
        HandleRecruitPanel(payload, payloadLength);
        break;
    default:
        break;
    }
}

void SetWaitingState(LONG state, DWORD now)
{
    InterlockedExchange(&g_lastSendTick, static_cast<LONG>(now));
    InterlockedExchange(&g_deadlineTick, static_cast<LONG>(now + kResponseTimeoutMs));
    InterlockedExchange(&g_state, state);
}

void SendMainPanel(DWORD now)
{
    SetWaitingState(1, now);
    SendPacket(0x5358, nullptr, 0);
}

void SendRecruitPanel(DWORD now)
{
    SetWaitingState(3, now);
    SendPacket(0x535C, nullptr, 0);
}

void RecheckMainPanel(DWORD now)
{
    SetWaitingState(5, now);
    SendPacket(0x5358, nullptr, 0);
}

void RecheckRecruitPanel(DWORD now)
{
    SetWaitingState(6, now);
    SendPacket(0x535C, nullptr, 0);
}

void SendPendingAction(DWORD now)
{
    const LONG action = g_pendingAction;
    if (action == kActionRecruit) {
        WriteBe32(g_actionPayload, static_cast<uint32_t>(g_pendingId));
        SetWaitingState(6, now);
        SendPacket(0x535E, g_actionPayload, 4);
        return;
    }
    if (action == kActionMotivate || action == kActionCollect) {
        WriteBe32(g_actionPayload, static_cast<uint32_t>(g_pendingId));
        WriteBe32(g_actionPayload + 4, static_cast<uint32_t>(g_pendingBonusType));
        SetWaitingState(5, now);
        SendPacket(action == kActionMotivate ? 0x535A : 0x535B, g_actionPayload, 8);
        return;
    }
    InterlockedExchange(&g_state, 0);
}

void TickImpl()
{
    DrainPendingLog();
    if (!IsEnabled()) {
        ResetState();
        return;
    }
    const DWORD now = GetGameTick();
    if (now - static_cast<DWORD>(g_lastSendTick) < kSendGapMs) {
        return;
    }

    switch (g_state) {
    case 0:
        SendMainPanel(now);
        return;
    case 2:
        SendRecruitPanel(now);
        return;
    case 4:
        SendPendingAction(now);
        return;
    case 10:
        if (now - static_cast<DWORD>(g_cycleTick) >= kIdleIntervalMs) {
            InterlockedExchange(&g_state, 0);
        }
        return;
    default:
        break;
    }

    if (static_cast<LONG>(now - static_cast<DWORD>(g_deadlineTick)) < 0) {
        return;
    }
    switch (g_state) {
    case 1:
        SendMainPanel(now);
        break;
    case 5:
        RecheckMainPanel(now);
        break;
    case 3:
        SendRecruitPanel(now);
        break;
    case 6:
        RecheckRecruitPanel(now);
        break;
    default:
        InterlockedExchange(&g_state, 0);
        break;
    }
}

__declspec(noinline) void Tick()
{
    if (InterlockedCompareExchange(&g_tickRunning, 1, 0) != 0) {
        return;
    }
    __try {
        TickImpl();
    } __finally {
        InterlockedExchange(&g_tickRunning, 0);
    }
}

}

namespace LegionDungeon
{

const uint16_t kDungeonIds[kDungeonCount] = {
    0xE903, 0xD107, 0xB90B, 0xA10F, 0x8913, 0x7117, 0x591B, 0x411F, 0x2923
};

const wchar_t kDungeonName0[] = { 0x5F35, 0x89D2, 0x0000 };
const wchar_t kDungeonName1[] = { 0x8463, 0x5353, 0x0000 };
const wchar_t kDungeonName2[] = { 0x8881, 0x7D39, 0x0000 };
const wchar_t kDungeonName3[] = { 0x5B6B, 0x5805, 0x0000 };
const wchar_t kDungeonName4[] = { 0x5442, 0x5E03, 0x0000 };
const wchar_t kDungeonName5[] = { 0x5289, 0x5099, 0x0000 };
const wchar_t kDungeonName6[] = { 0x66F9, 0x64CD, 0x0000 };
const wchar_t kDungeonName7[] = { 0x5B6B, 0x6B0A, 0x0000 };
const wchar_t kDungeonName8[] = { 0x53F8, 0x99AC, 0x708E, 0x0000 };

const wchar_t* const kDungeonNames[kDungeonCount] = {
    kDungeonName0, kDungeonName1, kDungeonName2, kDungeonName3, kDungeonName4,
    kDungeonName5, kDungeonName6, kDungeonName7, kDungeonName8
};

const wchar_t kLogSingleFormat[] = {
    0x8ECD, 0x5718, 0x526F, 0x672C, 0x0020, 0x55AE, 0x4EBA, 0x6311,
    0x6230, 0x0020, 0x0025, 0x0073, 0x0000
};
const wchar_t kLogRewardFormat[] = {
    0x8ECD, 0x5718, 0x526F, 0x672C, 0x0020, 0x9818, 0x53D6, 0x734E,
    0x52F5, 0x0020, 0x0025, 0x0073, 0x0000
};
const wchar_t kLogCreateFormat[] = {
    0x8ECD, 0x5718, 0x526F, 0x672C, 0x0020, 0x5EFA, 0x7ACB, 0x7D44,
    0x968A, 0x0020, 0x0025, 0x0073, 0x0000
};
const wchar_t kLogGroupFormat[] = {
    0x8ECD, 0x5718, 0x526F, 0x672C, 0x0020, 0x7D44, 0x968A, 0x6311,
    0x6230, 0x0020, 0x0025, 0x0073, 0x0000
};
const wchar_t kLogMaxFormat[] = {
    0x8ECD, 0x5718, 0x526F, 0x672C, 0x0020, 0x6700, 0x9AD8, 0x55AE,
    0x901A, 0x0020, 0x0025, 0x0073, 0x0000
};
const wchar_t kLogJoin[] = {
    0x8ECD, 0x5718, 0x526F, 0x672C, 0x0020, 0x9032, 0x5165, 0x7D44,
    0x968A, 0x0000
};
const wchar_t kLogFailFormat[] = {
    0x8ECD, 0x5718, 0x526F, 0x672C, 0x0020, 0x55AE, 0x4EBA, 0x6311,
    0x6230, 0x0020, 0x0025, 0x0073, 0x0020, 0x5931, 0x6557, 0x0000
};
const wchar_t kLogUnlimit[] = {
    0x8ECD, 0x5718, 0x526F, 0x672C, 0x0020, 0x7121, 0x9650, 0x6311,
    0x6230, 0x0000
};
const wchar_t kLogTimeOpenFormat[] = {
    0x8ECD, 0x5718, 0x526F, 0x672C, 0x0020, 0x5269, 0x9918, 0x958B,
    0x653E, 0x6642, 0x9593, 0x0020, 0x0025, 0x0075, 0x5929, 0x0025,
    0x0075, 0x5C0F, 0x6642, 0x0025, 0x0075, 0x5206, 0x9418, 0x0000
};
const wchar_t kLogTimeClosedFormat[] = {
    0x8ECD, 0x5718, 0x526F, 0x672C, 0x0020, 0x672A, 0x958B, 0x653E,
    0x0020, 0x5269, 0x9918, 0x6642, 0x9593, 0x0020, 0x0025, 0x0075,
    0x5929, 0x0025, 0x0075, 0x5C0F, 0x6642, 0x0025, 0x0075, 0x5206,
    0x9418, 0x0000
};
uint16_t ReadLe16(const BYTE* data)
{
    return static_cast<uint16_t>(data[0] | (static_cast<uint16_t>(data[1]) << 8));
}

uint32_t ReadLe32(const BYTE* data)
{
    return static_cast<uint32_t>(data[0]) |
        (static_cast<uint32_t>(data[1]) << 8) |
        (static_cast<uint32_t>(data[2]) << 16) |
        (static_cast<uint32_t>(data[3]) << 24);
}

uint16_t ReadBe16(const BYTE* data)
{
    return static_cast<uint16_t>((static_cast<uint16_t>(data[0]) << 8) | data[1]);
}

uint32_t ReadBe32(const BYTE* data)
{
    return (static_cast<uint32_t>(data[0]) << 24) |
        (static_cast<uint32_t>(data[1]) << 16) |
        (static_cast<uint32_t>(data[2]) << 8) |
        static_cast<uint32_t>(data[3]);
}

bool IsEnabled()
{
    return ReadGameU32(g_mainBase + kActionSwitchOffset) != 0;
}

void SendPacket(uint32_t opcode, const void* payload, uint32_t payloadLength)
{
    using SendPacketFn = void(__stdcall*)(uint32_t, const void*, uint32_t);
    SendPacketFn sendPacket = reinterpret_cast<SendPacketFn>(g_mainBase + 0x4A360);
    sendPacket(opcode, payload, payloadLength);
}

void RefreshLog()
{
    GameLog::RefreshCurrent();
}

void WriteDungeonLog(const wchar_t* format, LONG index)
{
    if (index < 0 || index >= static_cast<LONG>(kDungeonCount)) {
        return;
    }

    GameLog::Write(format, kDungeonNames[index]);
}

void WriteJoinLog()
{
    GameLog::Write(reinterpret_cast<const wchar_t*>(g_mainBase + 0x1FE56C), kLogJoin);
}

void WriteRawLog(const wchar_t* text)
{
    GameLog::Write(reinterpret_cast<const wchar_t*>(g_mainBase + 0x1FE56C), text);
}

void WriteTimeLog(const wchar_t* format, uint32_t leftSeconds)
{
    const uint32_t roundedMinutes = (leftSeconds + 59) / 60;
    const uint32_t days = roundedMinutes / 1440;
    const uint32_t hours = (roundedMinutes % 1440) / 60;
    const uint32_t minutes = roundedMinutes % 60;

    GameLog::Write(format, days, hours, minutes);
}

void WriteTimeOpenLog(uint32_t leftSeconds)
{
    WriteTimeLog(kLogTimeOpenFormat, leftSeconds);
}

void WriteTimeClosedLog(uint32_t leftSeconds)
{
    WriteTimeLog(kLogTimeClosedFormat, leftSeconds);
}
void PutIdPayload(BYTE* buffer, uint16_t id)
{
    buffer[0] = 0;
    buffer[1] = 0;
    std::memcpy(buffer + 2, &id, sizeof(id));
}

void Send4293()
{
    SendPacket(0x4293, &g_bufZero4, sizeof(g_bufZero4));
}

void Send4294()
{
    SendPacket(0x4294, nullptr, 0);
}

void Send42A6()
{
    SendPacket(0x42A6, nullptr, 0);
}

void Send42A8()
{
    std::memcpy(g_bufId4, &g_unlimitId, sizeof(g_unlimitId));
    SendPacket(0x42A8, g_bufId4, sizeof(g_bufId4));
}

void Send37A4()
{
    SendPacket(0x37A4, nullptr, 0);
}

void Send4297()
{
    PutIdPayload(g_bufId4, static_cast<uint16_t>(g_pendingId));
    SendPacket(0x4297, g_bufId4, sizeof(g_bufId4));
}

void Send429E()
{
    PutIdPayload(g_bufId4, static_cast<uint16_t>(g_pendingId));
    SendPacket(0x429E, g_bufId4, sizeof(g_bufId4));
}

void Send429EGroup()
{
    PutIdPayload(g_bufId6, static_cast<uint16_t>(g_pendingId));
    g_bufId6[4] = 0;
    g_bufId6[5] = 0x1A;
    SendPacket(0x429E, g_bufId6, sizeof(g_bufId6));
}

void Send429F()
{
    PutIdPayload(g_bufId4, static_cast<uint16_t>(g_pendingId));
    SendPacket(0x429F, g_bufId4, sizeof(g_bufId4));
}

void Send4296()
{
    const uint32_t teamId = static_cast<uint32_t>(g_teamId);
    g_bufTeam4[0] = static_cast<BYTE>((teamId >> 24) & 0xFF);
    g_bufTeam4[1] = static_cast<BYTE>((teamId >> 16) & 0xFF);
    g_bufTeam4[2] = static_cast<BYTE>((teamId >> 8) & 0xFF);
    g_bufTeam4[3] = static_cast<BYTE>(teamId & 0xFF);
    SendPacket(0x4296, g_bufTeam4, sizeof(g_bufTeam4));
}

void Send4296ById(uint32_t teamId)
{
    g_bufTeam4[0] = static_cast<BYTE>((teamId >> 24) & 0xFF);
    g_bufTeam4[1] = static_cast<BYTE>((teamId >> 16) & 0xFF);
    g_bufTeam4[2] = static_cast<BYTE>((teamId >> 8) & 0xFF);
    g_bufTeam4[3] = static_cast<BYTE>(teamId & 0xFF);
    SendPacket(0x4296, g_bufTeam4, sizeof(g_bufTeam4));
}

bool SaveExpectedOrder(const BYTE* member0, uint32_t len0, const BYTE* member1, uint32_t len1, const BYTE* member2, uint32_t len2)
{
    const BYTE* members[] = { member2, member0, member1 };
    const uint32_t lengths[] = { len2, len0, len1 };
    for (size_t i = 0; i < 3; ++i) {
        if (!members[i] || lengths[i] == 0 || lengths[i] > kOrderMemberMaxBytes) {
            return false;
        }
        std::memcpy(g_orderExpected[i], members[i], lengths[i]);
        g_orderExpectedLens[i] = lengths[i];
    }
    return true;
}

bool CurrentOrderMatchesExpected(const BYTE* member0, uint32_t len0, const BYTE* member1, uint32_t len1, const BYTE* member2, uint32_t len2)
{
    const BYTE* members[] = { member0, member1, member2 };
    const uint32_t lengths[] = { len0, len1, len2 };
    for (size_t i = 0; i < 3; ++i) {
        if (g_orderExpectedLens[i] == 0 || lengths[i] != g_orderExpectedLens[i]) {
            return false;
        }
        if (std::memcmp(members[i], g_orderExpected[i], lengths[i]) != 0) {
            return false;
        }
    }
    return true;
}

bool Send429A(const BYTE* member0, uint32_t len0, const BYTE* member1, uint32_t len1, const BYTE* member2, uint32_t len2)
{
    std::memset(g_bufOrder, 0, sizeof(g_bufOrder));
    g_bufOrder[0] = 0;
    g_bufOrder[1] = 3;
    BYTE* write = g_bufOrder + 2;
    BYTE* end = g_bufOrder + sizeof(g_bufOrder);

    const BYTE* members[] = { member2, member0, member1 };
    const uint32_t lengths[] = { len2, len0, len1 };
    for (size_t i = 0; i < 3; ++i) {
        if (!members[i] || lengths[i] == 0 || write + lengths[i] > end) {
            return false;
        }
        std::memcpy(write, members[i], lengths[i]);
        write += lengths[i];
    }

    SendPacket(0x429A, g_bufOrder, static_cast<uint32_t>(write - g_bufOrder));
    return true;
}

bool SendExpected429A()
{
    std::memset(g_bufOrder, 0, sizeof(g_bufOrder));
    g_bufOrder[0] = 0;
    g_bufOrder[1] = 3;
    BYTE* write = g_bufOrder + 2;
    BYTE* end = g_bufOrder + sizeof(g_bufOrder);

    for (size_t i = 0; i < 3; ++i) {
        const uint32_t length = g_orderExpectedLens[i];
        if (length == 0 || length > kOrderMemberMaxBytes || write + length > end) {
            return false;
        }
        std::memcpy(write, g_orderExpected[i], length);
        write += length;
    }

    SendPacket(0x429A, g_bufOrder, static_cast<uint32_t>(write - g_bufOrder));
    return true;
}

int GetIndexById(uint16_t id)
{
    for (size_t i = 0; i < kDungeonCount; ++i) {
        if (kDungeonIds[i] == id) {
            return static_cast<int>(i);
        }
    }

    return -1;
}

uint16_t GetIdByIndex(LONG index)
{
    if (index < 0 || index >= static_cast<LONG>(kDungeonCount)) {
        return 0;
    }

    return kDungeonIds[index];
}

bool EnsureCreateGate()
{
    if (g_createGateMutex && g_createGateMapping && g_sharedCreateGate) {
        return true;
    }

    HANDLE mutexHandle = CreateMutexW(nullptr, FALSE, L"Local\\MyPatch_LegionDungeon_CreateGate_Mutex_v1");
    if (!mutexHandle) {
        return false;
    }

    HANDLE mappingHandle = CreateFileMappingW(
        INVALID_HANDLE_VALUE,
        nullptr,
        PAGE_READWRITE,
        0,
        sizeof(SharedCreateGate),
        L"Local\\MyPatch_LegionDungeon_CreateGate_Mapping_v1");
    if (!mappingHandle) {
        CloseHandle(mutexHandle);
        return false;
    }

    auto* sharedGate = static_cast<SharedCreateGate*>(
        MapViewOfFile(mappingHandle, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(SharedCreateGate)));
    if (!sharedGate) {
        CloseHandle(mappingHandle);
        CloseHandle(mutexHandle);
        return false;
    }

    g_createGateMutex = mutexHandle;
    g_createGateMapping = mappingHandle;
    g_sharedCreateGate = sharedGate;
    return true;
}

bool LockCreateGate()
{
    if (!EnsureCreateGate()) {
        return false;
    }
    const DWORD waitResult = WaitForSingleObject(g_createGateMutex, 50);
    return waitResult == WAIT_OBJECT_0 || waitResult == WAIT_ABANDONED;
}

bool TryClaimCreateGate(uint16_t dungeonId)
{
    if (!LockCreateGate()) {
        return false;
    }

    const DWORD now = GetTickCount();
    const DWORD processId = GetCurrentProcessId();
    if (g_sharedCreateGate->magic != kCreateGateMagic) {
        std::memset(g_sharedCreateGate, 0, sizeof(*g_sharedCreateGate));
        g_sharedCreateGate->magic = kCreateGateMagic;
    }

    const bool expired = g_sharedCreateGate->ownerProcessId != 0 &&
        static_cast<LONG>(now - g_sharedCreateGate->expiresAt) >= 0;
    const bool alreadyOwned = g_sharedCreateGate->ownerProcessId == processId &&
        g_sharedCreateGate->dungeonId == dungeonId;
    const bool available = g_sharedCreateGate->ownerProcessId == 0 || expired;
    const bool claimed = alreadyOwned || available;
    if (claimed) {
        g_sharedCreateGate->ownerProcessId = processId;
        g_sharedCreateGate->dungeonId = dungeonId;
        g_sharedCreateGate->expiresAt = now + kCreateGateLeaseMs;
        InterlockedExchange(&g_createGateOwned, 1);
    }

    ReleaseMutex(g_createGateMutex);
    return claimed;
}

void ReleaseCreateGate()
{
    if (g_createGateOwned != 1 || !LockCreateGate()) {
        InterlockedExchange(&g_createGateOwned, 0);
        return;
    }

    if (g_sharedCreateGate->magic == kCreateGateMagic &&
        g_sharedCreateGate->ownerProcessId == GetCurrentProcessId()) {
        g_sharedCreateGate->ownerProcessId = 0;
        g_sharedCreateGate->dungeonId = 0;
        g_sharedCreateGate->expiresAt = 0;
    }
    ReleaseMutex(g_createGateMutex);
    InterlockedExchange(&g_createGateOwned, 0);
}

void KeepCreateGateLeaseAfterSend()
{
    InterlockedExchange(&g_createGateOwned, 0);
}

void ClearSoloBattleContext()
{
    InterlockedExchange(&g_soloBattleDungeonId, 0);
    InterlockedExchange(&g_soloFastRetrySent, 0);
    InterlockedExchange(&g_soloBattleStartTick, 0);
    InterlockedExchange(&g_soloPanelNextTick, 0);
}

void ResetState()
{
    ReleaseCreateGate();
    ClearSoloBattleContext();
    InterlockedExchange(&g_state, 0);
    InterlockedExchange(&g_currentId, 0);
    InterlockedExchange(&g_verifyId, 0);
    InterlockedExchange(&g_verifyIndex, -1);
    InterlockedExchange(&g_verifyMode, 0);
    InterlockedExchange(&g_verifyFailedMask, 0);
    InterlockedExchange(&g_waitBattleResult, 0);
    InterlockedExchange(&g_armyBattleConfirmed, 0);
    InterlockedExchange(&g_expectedWinValue, 0);
    InterlockedExchange(&g_soloVerifyBlocked, 0);
    InterlockedExchange(&g_maxSoloIndex, -1);
    InterlockedExchange(&g_unlimitPassedOnce, 0);
    InterlockedExchange(&g_battleMode, 0);
    InterlockedExchange(&g_timeBlocked, 0);
    InterlockedExchange(&g_timeWaitPassed, 0);
    InterlockedExchange(&g_timeOpenLogged, 0);
    InterlockedExchange(&g_activityState, 0);
    InterlockedExchange(&g_leftTime, 0);
    InterlockedExchange(&g_helpTrackId, 0);
    InterlockedExchange(&g_helpTrackCount, 0);
    InterlockedExchange(&g_teamOrderSent, 0);
    InterlockedExchange(&g_teamOrderRetries, 0);
    InterlockedExchange(&g_createTeamMissCount, 0);
    InterlockedExchange(&g_createFinalCheck, 0);
    InterlockedExchange(&g_restoredTeamId, 0);
    std::memset(g_orderExpected, 0, sizeof(g_orderExpected));
    std::memset(g_orderExpectedLens, 0, sizeof(g_orderExpectedLens));
}

void Finish()
{
    InterlockedExchange(&g_state, 0);
    InterlockedExchange(&g_nextTick, static_cast<LONG>(GetGameTick() + kIdleIntervalMs));
}

void UpdateMaxSolo()
{
    InterlockedExchange(&g_verifyId, 0);
    InterlockedExchange(&g_currentId, 0);
    InterlockedExchange(&g_verifyMode, 0);
    InterlockedExchange(&g_waitBattleResult, 0);
    InterlockedExchange(&g_armyBattleConfirmed, 0);
    const LONG index = g_verifyIndex;
    if (index == -1) {
        return;
    }
    if (index <= g_maxSoloIndex) {
        InterlockedExchange(&g_verifyIndex, -1);
        return;
    }

    InterlockedExchange(&g_maxSoloIndex, index);
    WriteDungeonLog(kLogMaxFormat, index);
    InterlockedExchange(&g_verifyIndex, -1);
}

void StartSolo()
{
    const DWORD now = GetGameTick();
    InterlockedExchange(&g_battleMode, 1);
    InterlockedExchange(&g_soloBattleDungeonId, g_pendingId);
    InterlockedExchange(&g_soloFastRetrySent, 0);
    InterlockedExchange(&g_soloBattleStartTick, static_cast<LONG>(now));
    InterlockedExchange(&g_soloPanelNextTick, static_cast<LONG>(now + kSoloPanelQueryDelayMs));
    Send4297();
    Send429E();
    Send37A4();
    InterlockedExchange(&g_currentId, g_pendingId);
    InterlockedExchange(&g_verifyId, g_pendingId);
    if (g_verifyMode == 1) {
        InterlockedExchange(&g_verifyIndex, g_logIndex);
        InterlockedExchange(&g_waitBattleResult, 1);
        InterlockedExchange(&g_armyBattleConfirmed, 0);
        InterlockedExchange(&g_expectedWinValue, 0);
        InterlockedExchange(&g_state, 5);
        InterlockedExchange(&g_waitTick, static_cast<LONG>(now));
    }
    WriteDungeonLog(kLogSingleFormat, g_logIndex);
}

void StartUnlimitQuery()
{
    if (g_unlimitPassedOnce == 1) {
        Finish();
        return;
    }

    Send42A6();
    InterlockedExchange(&g_state, 6);
    InterlockedExchange(&g_waitTick, static_cast<LONG>(GetGameTick()));
}

void ClearBattleAndFinish()
{
    InterlockedExchange(&g_waitBattleResult, 0);
    InterlockedExchange(&g_armyBattleConfirmed, 0);
    InterlockedExchange(&g_expectedWinValue, 0);
    InterlockedExchange(&g_battleMode, 0);
    Finish();
}

void StartStatus08Battle(LONG matchIndex)
{
    const uint16_t dungeonId = GetIdByIndex(matchIndex);
    if (dungeonId == 0 || static_cast<uint16_t>(g_soloBattleDungeonId) != dungeonId) {
        Finish();
        return;
    }

    const DWORD now = GetGameTick();
    if (g_soloBattleStartTick == 0 ||
        now - static_cast<DWORD>(g_soloBattleStartTick) > kSoloResumeWindowMs) {
        ClearSoloBattleContext();
        Finish();
        return;
    }

    InterlockedExchange(&g_battleMode, 1);
    InterlockedExchange(&g_waitBattleResult, 1);
    InterlockedExchange(&g_state, 5);
    InterlockedExchange(&g_waitTick, static_cast<LONG>(now));
    InterlockedExchange(&g_soloPanelNextTick, static_cast<LONG>(now + kSoloPanelQueryIntervalMs));
    if (InterlockedCompareExchange(&g_soloFastRetrySent, 1, 0) == 0) {
        Send4294();
        Send37A4();
    }
}

bool SkipUtf(const BYTE*& cursor, const BYTE* end)
{
    if (cursor + 2 > end) {
        return false;
    }

    const uint32_t length = ReadBe16(cursor);
    cursor += 2;
    if (cursor + length > end) {
        return false;
    }

    cursor += length;
    return true;
}

bool TryRead42A1TeamId(const BYTE* payload, uint32_t payloadLength, uint32_t& teamId)
{
    teamId = 0;
    if (!payload || payloadLength < 2) {
        return false;
    }

    const BYTE* cursor = payload;
    const BYTE* end = payload + payloadLength;
    const uint16_t count = ReadBe16(cursor);
    cursor += 2;
    for (uint16_t i = 0; i < count; ++i) {
        if (i >= 0x20 || cursor + 4 > end) {
            return false;
        }
        cursor += 4;
        if (!SkipUtf(cursor, end) || cursor + 0x10 > end) {
            return false;
        }
        cursor += 0x10;
        if (!SkipUtf(cursor, end)) {
            return false;
        }
    }

    if (cursor + 8 > end) {
        return false;
    }
    cursor += 8;
    if (!SkipUtf(cursor, end) || cursor + 4 > end) {
        return false;
    }

    teamId = ReadBe32(cursor);
    return true;
}

bool TryApply42A1TimeBlock(const BYTE* payload, uint32_t payloadLength)
{
    InterlockedExchange(&g_timeBlocked, 0);
    if (!payload || payloadLength < 0x0A) {
        return false;
    }

    const BYTE* cursor = payload;
    const BYTE* end = payload + payloadLength;
    if (cursor + 2 > end) {
        return false;
    }

    const uint16_t count = ReadBe16(cursor);
    cursor += 2;
    for (uint16_t i = 0; i < count; ++i) {
        if (i >= 0x20 || cursor + 4 > end) {
            return false;
        }

        cursor += 4;
        if (!SkipUtf(cursor, end) || cursor + 0x10 > end) {
            return false;
        }

        cursor += 0x10;
        if (!SkipUtf(cursor, end)) {
            return false;
        }
    }

    if (cursor + 8 > end) {
        return false;
    }

    const uint32_t activityState = ReadBe32(cursor);
    cursor += 4;
    uint32_t leftSeconds = ReadBe32(cursor);
    InterlockedExchange(&g_activityState, static_cast<LONG>(activityState));
    InterlockedExchange(&g_leftTime, static_cast<LONG>(leftSeconds));

    if (activityState == 0) {
        InterlockedExchange(&g_timeWaitPassed, 0);
        InterlockedExchange(&g_timeBlocked, 0);
        if (g_timeOpenLogged != 1) {
            InterlockedExchange(&g_timeOpenLogged, 1);
            WriteTimeOpenLog(leftSeconds);
        }
        return false;
    }

    InterlockedExchange(&g_timeOpenLogged, 0);
    if (leftSeconds > kMaxClosedWaitSeconds) {
        leftSeconds = kMaxClosedWaitSeconds;
    }

    const DWORD waitMs = leftSeconds == 0 ? kIdleIntervalMs : (leftSeconds + 1) * 1000;
    InterlockedExchange(&g_nextTick, static_cast<LONG>(GetGameTick() + waitMs));
    InterlockedExchange(&g_state, 0);
    InterlockedExchange(&g_timeBlocked, 1);
    InterlockedExchange(&g_timeWaitPassed, 1);
    WriteTimeClosedLog(leftSeconds);
    return true;
}

bool TryHandleSoloBattleStatus(const BYTE* payload, uint32_t payloadLength)
{
    if (g_soloBattleDungeonId == 0) {
        return false;
    }

    LONG matchIndex = 0;
    for (uint32_t offset = 0; offset + 4 <= payloadLength; ++offset) {
        if (ReadLe32(payload + offset) != 0x7D7B0200) {
            continue;
        }
        if (matchIndex >= static_cast<LONG>(kDungeonCount)) {
            break;
        }
        if (offset >= 9) {
            const BYTE status = payload[offset - 9];
            const uint16_t dungeonId = GetIdByIndex(matchIndex);
            if ((status == 0x08 || status == 0x09) &&
                dungeonId == static_cast<uint16_t>(g_soloBattleDungeonId)) {
                StartStatus08Battle(matchIndex);
                return true;
            }
        }
        ++matchIndex;
    }
    return false;
}

void Handle42A1(const BYTE* payload, uint32_t payloadLength)
{
    if ((g_state != 1 && g_state != 5) || payloadLength < 0x0D) {
        return;
    }

    if (TryApply42A1TimeBlock(payload, payloadLength)) {
        return;
    }

    if (TryHandleSoloBattleStatus(payload, payloadLength)) {
        return;
    }

    if (g_state == 5 && g_waitBattleResult == 1) {
        return;
    }

    uint32_t serverTeamId = 0;
    if (TryRead42A1TeamId(payload, payloadLength, serverTeamId)) {
        if (serverTeamId != 0) {
            InterlockedExchange(&g_teamId, static_cast<LONG>(serverTeamId));
            InterlockedExchange(&g_battleMode, 3);
            if (g_restoredTeamId != static_cast<LONG>(serverTeamId)) {
                InterlockedExchange(&g_restoredTeamId, static_cast<LONG>(serverTeamId));
                Send4296ById(serverTeamId);
                Send4293();
                WriteJoinLog();
            }
            Finish();
            return;
        }
        InterlockedExchange(&g_restoredTeamId, 0);
    }

    LONG matchIndex = 0;
    LONG ownTeamIndex = -1;
    for (uint32_t offset = 0; offset + 8 <= payloadLength; ++offset) {
        if (ReadLe32(payload + offset) != 0x7D7B0200) {
            continue;
        }
        if (matchIndex >= static_cast<LONG>(kDungeonCount)) {
            break;
        }
        if (offset < 9) {
            ++matchIndex;
            continue;
        }
        if (matchIndex == 8 && ReadLe32(payload + offset + 4) != 0) {
            Finish();
            return;
        }
        const BYTE status = payload[offset - 9];
        if (status == 0x08 || status == 0x09) {
            StartStatus08Battle(matchIndex);
            return;
        }
        if (status == 0x07) {
            InterlockedExchange(&g_battleMode, 3);
            Finish();
            return;
        }
        if (status == 0x04 && ownTeamIndex < 0) {
            ownTeamIndex = matchIndex;
        }
        ++matchIndex;
    }

    if (ownTeamIndex >= 0) {
        InterlockedExchange(&g_logIndex, ownTeamIndex);
        InterlockedExchange(&g_pendingId, GetIdByIndex(ownTeamIndex));
        InterlockedExchange(&g_currentId, g_pendingId);
        InterlockedExchange(&g_battleMode, 3);
        Send4294();
        InterlockedExchange(&g_state, 2);
        InterlockedExchange(&g_teamOrderSent, 0);
        InterlockedExchange(&g_teamOrderRetries, 0);
        InterlockedExchange(&g_createTeamMissCount, 0);
        std::memset(g_orderExpected, 0, sizeof(g_orderExpected));
        std::memset(g_orderExpectedLens, 0, sizeof(g_orderExpectedLens));
        InterlockedExchange(&g_waitTick, static_cast<LONG>(GetGameTick()));
        return;
    }

    matchIndex = 0;
    for (uint32_t offset = 0; offset + 4 <= payloadLength; ++offset) {
        if (ReadLe32(payload + offset) != 0x7D7B0200) {
            continue;
        }
        if (matchIndex >= static_cast<LONG>(kDungeonCount)) {
            StartUnlimitQuery();
            return;
        }
        if (offset < 9) {
            ++matchIndex;
            continue;
        }

        const BYTE status = payload[offset - 9];
        InterlockedExchange(&g_logIndex, matchIndex);
        InterlockedExchange(&g_pendingId, GetIdByIndex(matchIndex));

        if (status == 0x06) {
            if (static_cast<uint16_t>(g_pendingId) == static_cast<uint16_t>(g_verifyId)) {
                if (g_waitBattleResult == 1 || g_verifyMode == 1) {
                    ++matchIndex;
                    continue;
                }
                UpdateMaxSolo();
                ++matchIndex;
                continue;
            }
            if (g_waitBattleResult == 1 || g_soloVerifyBlocked == 1) {
                ++matchIndex;
                continue;
            }
            const LONG mask = 1 << g_logIndex;
            if ((g_verifyFailedMask & mask) != 0) {
                ++matchIndex;
                continue;
            }
            if (g_logIndex <= g_maxSoloIndex) {
                ++matchIndex;
                continue;
            }
            InterlockedExchange(&g_verifyMode, 1);
            StartSolo();
            return;
        }

        if (status == 0x03) {
            if (g_waitBattleResult == 1) {
                ++matchIndex;
                continue;
            }
            if (g_soloVerifyBlocked == 1) {
                InterlockedExchange(&g_currentId, g_pendingId);
                Send4294();
                InterlockedExchange(&g_state, 3);
                InterlockedExchange(&g_createTeamMissCount, 0);
                InterlockedExchange(&g_createFinalCheck, 0);
                InterlockedExchange(&g_waitTick, static_cast<LONG>(GetGameTick()));
                return;
            }
            const LONG mask = 1 << g_logIndex;
            if ((g_verifyFailedMask & mask) != 0) {
                ++matchIndex;
                continue;
            }
            if (static_cast<uint16_t>(g_pendingId) == static_cast<uint16_t>(g_currentId)) {
                if (g_verifyMode == 1) {
                    ++matchIndex;
                    continue;
                }
                Send4294();
                InterlockedExchange(&g_state, 3);
                InterlockedExchange(&g_createTeamMissCount, 0);
                InterlockedExchange(&g_createFinalCheck, 0);
                InterlockedExchange(&g_waitTick, static_cast<LONG>(GetGameTick()));
                return;
            }
            InterlockedExchange(&g_verifyMode, 1);
            StartSolo();
            return;
        }

        if (status == 0x04) {
            Send4294();
            InterlockedExchange(&g_state, 2);
            InterlockedExchange(&g_teamOrderSent, 0);
            InterlockedExchange(&g_teamOrderRetries, 0);
            InterlockedExchange(&g_createTeamMissCount, 0);
            std::memset(g_orderExpected, 0, sizeof(g_orderExpected));
            std::memset(g_orderExpectedLens, 0, sizeof(g_orderExpectedLens));
            InterlockedExchange(&g_waitTick, static_cast<LONG>(GetGameTick()));
            return;
        }

        if (status == 0x05) {
            if (static_cast<uint16_t>(g_pendingId) == static_cast<uint16_t>(g_verifyId)) {
                UpdateMaxSolo();
            }
            if (static_cast<uint16_t>(g_soloBattleDungeonId) == static_cast<uint16_t>(g_pendingId)) {
                ClearSoloBattleContext();
            }
            InterlockedExchange(&g_battleMode, 0);
            Send429F();
            WriteDungeonLog(kLogRewardFormat, g_logIndex);
            Finish();
            return;
        }

        if (status == 0x01) {
            if (g_unlimitPassedOnce != 1) {
                ++matchIndex;
                continue;
            }
            if (g_maxSoloIndex < 0) {
                Finish();
                return;
            }
            Send4294();
            InterlockedExchange(&g_state, 4);
            InterlockedExchange(&g_waitTick, static_cast<LONG>(GetGameTick()));
            return;
        }

        if (status == 0x02) {
            if (g_unlimitPassedOnce == 1) {
                if (g_maxSoloIndex < 0) {
                    Finish();
                    return;
                }
                Send4294();
                InterlockedExchange(&g_state, 4);
                InterlockedExchange(&g_waitTick, static_cast<LONG>(GetGameTick()));
                return;
            }
            StartUnlimitQuery();
            return;
        }

        if (status == 0x08) {
            StartStatus08Battle(matchIndex);
            return;
        }

        if (status == 0x07) {
            Finish();
            return;
        }

        ++matchIndex;
    }

    StartUnlimitQuery();
}

void Handle42A2(const BYTE* payload, uint32_t payloadLength)
{
    if (g_state != 2 || payloadLength < 0x1A) {
        return;
    }

    const BYTE* cursor = payload + 4;
    const BYTE* end = payload + payloadLength;
    if (!SkipUtf(cursor, end) || cursor + 6 > end) {
        return;
    }

    cursor += 4;
    const uint16_t memberCount = ReadBe16(cursor);
    cursor += 2;
    if (memberCount != 3) {
        return;
    }

    const BYTE* memberPtrs[3]{};
    uint32_t memberLens[3]{};
    for (size_t i = 0; i < 3; ++i) {
        if (cursor + 2 > end) {
            return;
        }
        memberPtrs[i] = cursor;
        memberLens[i] = static_cast<uint32_t>(ReadBe16(cursor)) + 2;
        cursor += memberLens[i];
        if (cursor > end || !SkipUtf(cursor, end) || cursor + 0x0C > end) {
            return;
        }
        cursor += 0x0C;
        if (!SkipUtf(cursor, end)) {
            return;
        }
    }

    if (g_teamOrderSent != 1) {
        if (!SaveExpectedOrder(memberPtrs[0], memberLens[0], memberPtrs[1], memberLens[1], memberPtrs[2], memberLens[2])) {
            Finish();
            return;
        }
        if (Send429A(memberPtrs[0], memberLens[0], memberPtrs[1], memberLens[1], memberPtrs[2], memberLens[2])) {
            InterlockedExchange(&g_teamOrderSent, 1);
            InterlockedExchange(&g_teamOrderRetries, 1);
            Send4294();
            InterlockedExchange(&g_waitTick, static_cast<LONG>(GetGameTick()));
        }
        return;
    }

    if (!CurrentOrderMatchesExpected(memberPtrs[0], memberLens[0], memberPtrs[1], memberLens[1], memberPtrs[2], memberLens[2])) {
        if (g_teamOrderRetries >= kOrderRetryMax) {
            Finish();
            return;
        }
        if (SendExpected429A()) {
            InterlockedExchange(&g_teamOrderRetries, g_teamOrderRetries + 1);
            Send4294();
            InterlockedExchange(&g_waitTick, static_cast<LONG>(GetGameTick()));
        }
        return;
    }

    InterlockedExchange(&g_battleMode, 3);
    Send429EGroup();
    WriteDungeonLog(kLogGroupFormat, g_logIndex);
    Finish();
}

bool ParseTeams(const BYTE* payload, uint32_t payloadLength)
{
    InterlockedExchange(&g_teamCount, 0);
    InterlockedExchange(&g_peopleCount, 0);
    std::memset(g_teamIds, 0, sizeof(g_teamIds));
    std::memset(g_teamDungeonIds, 0, sizeof(g_teamDungeonIds));
    std::memset(g_teamPeople, 0, sizeof(g_teamPeople));
    if (payloadLength < 2) {
        InterlockedExchange(&g_payloadTeamCount, 0);
        return false;
    }

    const BYTE* cursor = payload;
    const BYTE* end = payload + payloadLength;
    const uint16_t payloadTeamCount = ReadBe16(cursor);
    cursor += 2;
    InterlockedExchange(&g_payloadTeamCount, payloadTeamCount);
    if (payloadTeamCount > 100) {
        return false;
    }

    LONG storedCount = 0;
    for (uint16_t teamIndex = 0; teamIndex < payloadTeamCount; ++teamIndex) {
        if (cursor + 8 > end) {
            return false;
        }

        const uint32_t teamId = ReadBe32(cursor);
        cursor += 4;
        const uint16_t dungeonId = ReadLe16(cursor + 2);
        cursor += 4;
        if (!SkipUtf(cursor, end) || cursor + 4 > end) {
            return false;
        }

        cursor += 4;
        if (!SkipUtf(cursor, end) || cursor + 8 > end) {
            return false;
        }

        const uint32_t currentPeople = ReadBe32(cursor);
        cursor += 4;
        cursor += 4;
        if (!SkipUtf(cursor, end)) {
            return false;
        }

        if (storedCount < static_cast<LONG>(kMaxTeams)) {
            g_teamIds[storedCount] = teamId;
            g_teamDungeonIds[storedCount] = dungeonId;
            g_teamPeople[storedCount] = currentPeople <= 0xFF ? static_cast<BYTE>(currentPeople) : 0xFF;
            ++storedCount;
        }
    }

    if (!SkipUtf(cursor, end)) {
        return false;
    }

    InterlockedExchange(&g_teamCount, storedCount);
    InterlockedExchange(&g_peopleCount, storedCount);
    return true;
}

bool WaitBeforeCreateTeam()
{
    const LONG nextMiss = g_createTeamMissCount + 1;
    InterlockedExchange(&g_createTeamMissCount, nextMiss);
    if (nextMiss < kCreateTeamMissMax) {
        Send4294();
        InterlockedExchange(&g_waitTick, static_cast<LONG>(GetGameTick()));
        return true;
    }

    if (TryClaimCreateGate(static_cast<uint16_t>(g_currentId))) {
        InterlockedExchange(&g_createTeamMissCount, 0);
        InterlockedExchange(&g_createFinalCheck, 1);
        Send4294();
        InterlockedExchange(&g_waitTick, static_cast<LONG>(GetGameTick()));
        return true;
    }

    InterlockedExchange(&g_createTeamMissCount, 0);
    InterlockedExchange(&g_createFinalCheck, 0);
    Finish();
    return true;
}

void Handle42A4(const BYTE* payload, uint32_t payloadLength)
{
    if (g_state != 3 && g_state != 4) {
        return;
    }

    if (!ParseTeams(payload, payloadLength)) {
        InterlockedExchange(&g_createFinalCheck, 0);
        ReleaseCreateGate();
        Finish();
        return;
    }
    if (g_state == 3) {
        const LONG count = g_teamCount < static_cast<LONG>(kMaxTeams) ? g_teamCount : static_cast<LONG>(kMaxTeams);
        for (LONG i = 0; i < count; ++i) {
            if (g_teamDungeonIds[i] != static_cast<uint16_t>(g_currentId) || g_teamPeople[i] != 1) {
                continue;
            }
            InterlockedExchange(&g_createTeamMissCount, 0);
            InterlockedExchange(&g_createFinalCheck, 0);
            ReleaseCreateGate();
            InterlockedExchange(&g_battleMode, 3);
            InterlockedExchange(&g_teamId, g_teamIds[i]);
            Send4296();
            Send4293();
            WriteJoinLog();
            Finish();
            return;
        }

        if (g_createFinalCheck != 1) {
            WaitBeforeCreateTeam();
            return;
        }

        InterlockedExchange(&g_createFinalCheck, 0);
        InterlockedExchange(&g_battleMode, 3);
        Send4297();
        KeepCreateGateLeaseAfterSend();
        WriteDungeonLog(kLogCreateFormat, g_logIndex);
        Finish();
        return;
    }

    if (g_maxSoloIndex < 0 || g_payloadTeamCount == 0) {
        InterlockedExchange(&g_helpTrackId, 0);
        InterlockedExchange(&g_helpTrackCount, 0);
        return;
    }

    const LONG count = g_teamCount < static_cast<LONG>(kMaxTeams) ? g_teamCount : static_cast<LONG>(kMaxTeams);
    if (g_helpTrackCount > 0) {
        bool keepTrackedRoom = false;
        for (LONG i = 0; i < count; ++i) {
            if (g_teamIds[i] != static_cast<uint32_t>(g_helpTrackId)) {
                continue;
            }

            const int index = GetIndexById(g_teamDungeonIds[i]);
            if (index >= 0 && index <= g_maxSoloIndex && g_teamPeople[i] < 3) {
                keepTrackedRoom = true;
                const LONG nextCount = g_helpTrackCount + 1;
                InterlockedExchange(&g_helpTrackCount, nextCount);
                if (nextCount < 6) {
                    return;
                }

                InterlockedExchange(&g_helpTrackId, 0);
                InterlockedExchange(&g_helpTrackCount, 0);
                InterlockedExchange(&g_battleMode, 3);
                InterlockedExchange(&g_teamId, g_teamIds[i]);
                Send4296();
                Send4293();
                WriteJoinLog();
                Finish();
                return;
            }
            break;
        }

        if (!keepTrackedRoom) {
            InterlockedExchange(&g_helpTrackId, 0);
            InterlockedExchange(&g_helpTrackCount, 0);
        }
    }

    for (LONG i = 0; i < count; ++i) {
        const int index = GetIndexById(g_teamDungeonIds[i]);
        if (index < 0 || index > g_maxSoloIndex || g_teamPeople[i] >= 3) {
            continue;
        }
        InterlockedExchange(&g_helpTrackId, g_teamIds[i]);
        InterlockedExchange(&g_helpTrackCount, 1);
        return;
    }

    InterlockedExchange(&g_helpTrackId, 0);
    InterlockedExchange(&g_helpTrackCount, 0);
}

void Handle42A7(const BYTE* payload, uint32_t payloadLength)
{
    if (g_state != 6 || payloadLength < 2) {
        return;
    }

    const BYTE* cursor = payload;
    const BYTE* end = payload + payloadLength;
    const uint16_t count = ReadBe16(cursor);
    InterlockedExchange(&g_unlimitCount, count);
    cursor += 2;

    for (uint16_t i = 0; i < count; ++i) {
        if (cursor + 4 > end) {
            return;
        }
        std::memcpy(&g_unlimitId, cursor, sizeof(g_unlimitId));
        cursor += 4;
        if (!SkipUtf(cursor, end) || cursor + 0x10 > end) {
            return;
        }
        cursor += 4;
        if (ReadLe32(cursor) == 0x04000000) {
            Send42A8();
            WriteRawLog(kLogUnlimit);
            InterlockedExchange(&g_unlimitPassedOnce, 1);
            InterlockedExchange(&g_battleMode, 0);
            InterlockedExchange(&g_state, 0);
            InterlockedExchange(&g_armyBattleConfirmed, 0);
            InterlockedExchange(&g_expectedWinValue, 0);
            InterlockedExchange(&g_nextTick, static_cast<LONG>(GetGameTick() + kIdleIntervalMs));
            return;
        }
        cursor += 0x0C;
        if (!SkipUtf(cursor, end)) {
            return;
        }
    }
}

void Handle1460(const BYTE* payload, uint32_t payloadLength)
{
    if (g_state != 5 || payloadLength < 0x0A) {
        return;
    }

    const BYTE marker[] = { 'a', 'r', 'm', 'y', 'R', 'a', 'i', 'd', 'F', 'B' };
    bool foundArmyBattle = false;
    for (uint32_t offset = 0; offset + sizeof(marker) <= payloadLength; ++offset) {
        if (std::memcmp(payload + offset, marker, sizeof(marker)) == 0) {
            InterlockedExchange(&g_armyBattleConfirmed, 1);
            InterlockedExchange(&g_expectedWinValue, 0);
            foundArmyBattle = true;
            break;
        }
    }

    if (!foundArmyBattle || payloadLength < 0x0F) {
        return;
    }

    const BYTE locationMarker[] = { 'c', 'h', 'a', 'r', 'L', 'o', 'c', 'a', 't', 'i', 'o', 'n' };
    for (uint32_t offset = 0; offset + 0x0F <= payloadLength; ++offset) {
        if (std::memcmp(payload + offset, locationMarker, sizeof(locationMarker)) != 0) {
            continue;
        }
        if (payload[offset + 0x0E] == '1') {
            InterlockedExchange(&g_expectedWinValue, 1);
        }
        return;
    }
}

void Handle1464(const BYTE* payload, uint32_t payloadLength)
{
    if (payloadLength == 0) {
        return;
    }

    if (g_state != 5 || g_waitBattleResult != 1) {
        return;
    }
    if (g_armyBattleConfirmed != 1) {
        if (g_battleMode != 1) {
            return;
        }
        InterlockedExchange(&g_armyBattleConfirmed, 1);
        InterlockedExchange(&g_expectedWinValue, 0);
    }
    if (g_armyBattleConfirmed != 1) {
        return;
    }
    if (g_verifyMode != 1) {
        ClearSoloBattleContext();
        ClearBattleAndFinish();
        return;
    }

    if (payload[0] == static_cast<BYTE>(g_expectedWinValue)) {
        UpdateMaxSolo();
    } else {
        const LONG index = g_verifyIndex;
        if (index >= 0 && index < static_cast<LONG>(kDungeonCount)) {
            WriteDungeonLog(kLogFailFormat, index);
            InterlockedExchange(&g_verifyFailedMask, g_verifyFailedMask | (1 << index));
        }
        InterlockedExchange(&g_currentId, 0);
        InterlockedExchange(&g_verifyId, 0);
        InterlockedExchange(&g_verifyMode, 0);
        InterlockedExchange(&g_verifyIndex, -1);
        InterlockedExchange(&g_soloVerifyBlocked, 1);
    }

    ClearSoloBattleContext();
    ClearBattleAndFinish();
}

void HandleRecvPacket(uint32_t opcode, const BYTE* payload, uint32_t payloadLength)
{
    if (!payload || !IsEnabled()) {
        return;
    }

    switch (opcode & 0xFFFF) {
    case 0x42A1:
        Handle42A1(payload, payloadLength);
        break;
    case 0x42A2:
        Handle42A2(payload, payloadLength);
        break;
    case 0x42A4:
        Handle42A4(payload, payloadLength);
        break;
    case 0x42A7:
        Handle42A7(payload, payloadLength);
        break;
    case 0x1460:
        Handle1460(payload, payloadLength);
        break;
    case 0x1464:
        Handle1464(payload, payloadLength);
        break;
    default:
        break;
    }
}

__declspec(noinline) void __stdcall Tick()
{
    if (!IsEnabled()) {
        ResetState();
        return;
    }

    const DWORD now = GetGameTick();
    if (g_waitBattleResult == 1) {
        if (now - static_cast<DWORD>(g_waitTick) >= kBattleResultTimeoutMs) {
            ClearBattleAndFinish();
            return;
        }
        if (g_soloBattleDungeonId != 0 && g_soloFastRetrySent == 0 &&
            now >= static_cast<DWORD>(g_soloPanelNextTick)) {
            Send4293();
            InterlockedExchange(&g_soloPanelNextTick, static_cast<LONG>(now + kSoloPanelQueryIntervalMs));
        }
        return;
    }

    if (g_state != 0) {
        if (g_state == 5) {
            return;
        }
        if (now - static_cast<DWORD>(g_waitTick) >= kWaitTimeoutMs) {
            if (g_state == 3) {
                InterlockedExchange(&g_createFinalCheck, 0);
                ReleaseCreateGate();
            }
            InterlockedExchange(&g_state, 0);
        }
        return;
    }

    if (now < static_cast<DWORD>(g_nextTick)) {
        return;
    }

    if (g_soloBattleDungeonId != 0 &&
        now - static_cast<DWORD>(g_soloBattleStartTick) > kSoloResumeWindowMs) {
        ClearSoloBattleContext();
    }

    Send4293();
    InterlockedExchange(&g_state, 1);
    InterlockedExchange(&g_waitTick, static_cast<LONG>(now));
    InterlockedExchange(&g_nextTick, static_cast<LONG>(now + kIdleIntervalMs));
}

bool BuildTickCode(uintptr_t, CodeBuffer& code)
{
    return AppendByte(code, 0x9C) &&
        AppendPushad(code) &&
        AppendRel32Instruction(code, 0xE8, reinterpret_cast<uintptr_t>(&Tick)) &&
        AppendPopad(code) &&
        AppendByte(code, 0x9D) &&
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
    NativeWash::HandleRecvPacket(opcode, payload, payloadLength);
    WorldCityBattle::HandleRecvPacket(opcode, payload, payloadLength);
    DailySign::HandleRecvPacket(opcode, payload);
    PrizePool::HandleRecvPacket(opcode, payload);
    WeeklyReward::HandleRecvPacket(opcode, payload, payloadLength);
    Jrnt::HandleRecvPacket(opcode, payload, payloadLength);
    Xyfp::HandleRecvPacket(opcode, payload, payloadLength);
    PersonalTask::HandleRecvPacket(opcode, payload, payloadLength);
    TaskDispatch::HandleRecvPacket(opcode, payload, payloadLength);
    BattleToken::HandleRecvPacket(opcode, payload, payloadLength);
    ZhaoXianNaKe::HandleRecvPacket(opcode, payload, payloadLength);
    ActivityLogin::HandleRecvPacket(opcode, payload, payloadLength);
    TeamBattleReward::HandleRecvPacket(opcode, payload, payloadLength);
    DianFengZhuLu::HandleRecvPacket(opcode, payload, payloadLength);
    HuanJing::HandleRecvPacket(opcode, payload, payloadLength);
    ExpeditionGuard::HandleRecvPacket(opcode);
    const BYTE* const legionPayload = payload;
    const uint32_t legionPayloadLength = payloadLength;
    AlBattle::HandleRecvPacket(opcode, payload, payloadLength);
    LegionDungeon::HandleRecvPacket(opcode, legionPayload, legionPayloadLength);
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
            const int workWidth = monitorInfo.rcWork.right - monitorInfo.rcWork.left;
            const int workHeight = monitorInfo.rcWork.bottom - monitorInfo.rcWork.top;
            const int x = monitorInfo.rcWork.left + (workWidth - width) / 2;
            const int y = monitorInfo.rcWork.top + (workHeight - height) / 2;

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

void ShowAutoCloseMessage(const wchar_t* message, const wchar_t* title)
{
    g_msgBoxHook = SetWindowsHookExA(WH_CBT, MessageBoxHook, nullptr, GetCurrentThreadId());
    MessageBoxW(
        nullptr,
        message,
        title,
        MB_OK | MB_ICONINFORMATION | MB_TOPMOST | MB_SETFOREGROUND);
    if (g_msgBoxHook) {
        UnhookWindowsHookEx(g_msgBoxHook);
        g_msgBoxHook = nullptr;
    }
}

void NotifyLauncherOnlineStopped()
{
    if (g_mainBase == 0) {
        return;
    }

    HWND launcherHwnd = *reinterpret_cast<HWND volatile*>(g_mainBase + 0x230080);
    if (!launcherHwnd || !IsWindow(launcherHwnd)) {
        return;
    }

    const UINT onlineStateMessage = RegisterWindowMessageW(L"MSG_ONLINESTATE");
    if (onlineStateMessage == 0) {
        return;
    }

    DWORD_PTR messageResult = 0;
    SendMessageTimeoutW(
        launcherHwnd,
        onlineStateMessage,
        static_cast<WPARAM>(GetCurrentProcessId()),
        0,
        SMTO_ABORTIFHUNG | SMTO_BLOCK,
        1000,
        &messageResult);
}

void ExitOnlineAndNotifyLauncher()
{
    NotifyLauncherOnlineStopped();
    ExitProcess(0);
}

namespace LicenseAuth
{
constexpr char kHost[] = "mypatch-license-auth.wasd11334342.workers.dev";
constexpr char kPath[] = "/";
constexpr char kUsagePath[] = "/license_update_data";
constexpr char kClientApiKey[] = "7ca30c81d310863317025e7c37701f35ab050af6c0443266ba5a99df39feece8";
constexpr unsigned kMaxConsecutiveCheckFailures = 3;
constexpr DWORD kRemoteCheckIntervalMs = 20U * 60U * 1000U;
constexpr DWORD kRemoteRetryIntervalMs = 5U * 60U * 1000U;
constexpr DWORD kUsageAccountWaitMs = 30000;

__declspec(align(8)) volatile LONG64 g_expireTick = 0;
volatile LONG g_exitStarted = 0;
volatile LONG g_usageReportStarted = 0;

enum class Result
{
    Valid,
    Expired,
    NotFound,
    MissingFile,
    InvalidFile,
    NetworkError,
    ServiceError
};

struct CheckResult
{
    Result result = Result::ServiceError;
    unsigned long long remainingSeconds = 0;
};

bool GetLicensePath(wchar_t* path, size_t capacity)
{
    if (!path || capacity == 0 || !g_selfModule) {
        return false;
    }
    DWORD length = GetModuleFileNameW(g_selfModule, path, static_cast<DWORD>(capacity));
    if (length == 0 || length >= capacity) {
        return false;
    }
    wchar_t* slash = wcsrchr(path, L'\\');
    if (!slash) {
        return false;
    }
    *(slash + 1) = L'\0';
    const wchar_t fileName[] = L"license.txt";
    const size_t used = wcslen(path);
    if (used + (sizeof(fileName) / sizeof(fileName[0])) > capacity) {
        return false;
    }
    wcscat_s(path, capacity, fileName);
    return true;
}

Result ReadLicense(std::string& license)
{
    wchar_t path[MAX_PATH]{};
    if (!GetLicensePath(path, sizeof(path) / sizeof(path[0]))) {
        return Result::MissingFile;
    }

    HANDLE file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        return Result::MissingFile;
    }

    char buffer[513]{};
    DWORD read = 0;
    const BOOL ok = ReadFile(file, buffer, 512, &read, nullptr);
    CloseHandle(file);
    if (!ok || read == 0 || read > 512) {
        return Result::InvalidFile;
    }

    size_t begin = 0;
    if (read >= 3 && static_cast<unsigned char>(buffer[0]) == 0xEF &&
        static_cast<unsigned char>(buffer[1]) == 0xBB &&
        static_cast<unsigned char>(buffer[2]) == 0xBF) {
        begin = 3;
    }
    size_t end = read;
    while (begin < end && (buffer[begin] == ' ' || buffer[begin] == '\t' || buffer[begin] == '\r' || buffer[begin] == '\n')) {
        ++begin;
    }
    while (end > begin && (buffer[end - 1] == ' ' || buffer[end - 1] == '\t' || buffer[end - 1] == '\r' || buffer[end - 1] == '\n')) {
        --end;
    }
    if (begin == end || end - begin > 128) {
        return Result::InvalidFile;
    }

    license.assign(buffer + begin, buffer + end);
    for (char ch : license) {
        const bool allowed = (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') ||
            (ch >= '0' && ch <= '9') || ch == '.' || ch == '_' || ch == '-';
        if (!allowed) {
            license.clear();
            return Result::InvalidFile;
        }
    }
    return Result::Valid;
}

bool ParseUnsigned(const std::string& text, const char* field, unsigned long long& value)
{
    const size_t pos = text.find(field);
    if (pos == std::string::npos) {
        return false;
    }
    size_t cursor = pos + std::strlen(field);
    value = 0;
    bool hasDigit = false;
    while (cursor < text.size() && text[cursor] >= '0' && text[cursor] <= '9') {
        hasDigit = true;
        const unsigned digit = static_cast<unsigned>(text[cursor] - '0');
        if (value > (ULLONG_MAX - digit) / 10ULL) {
            return false;
        }
        value = value * 10ULL + digit;
        ++cursor;
    }
    return hasDigit;
}

CheckResult Query(const std::string& license)
{
    CheckResult result{};
    const std::string body = std::string("{\"license\":\"") + license + "\"}";
    const LicenseTlsClient::Response tlsResponse =
        LicenseTlsClient::PostJson(kHost, kPath, kClientApiKey, body);
    if (!tlsResponse.Ok()) {
        result.result = Result::NetworkError;
        return result;
    }
    if (tlsResponse.statusCode != 200) {
        result.result = Result::ServiceError;
        return result;
    }
    const std::string& response = tlsResponse.body;
    if (response.find("\"valid\":true") != std::string::npos) {
        unsigned long long remaining = 0;
        if (!ParseUnsigned(response, "\"remaining_seconds\":", remaining) || remaining == 0) {
            result.result = Result::ServiceError;
            return result;
        }
        result.result = Result::Valid;
        result.remainingSeconds = remaining;
        return result;
    }
    if (response.find("\"code\":\"expired\"") != std::string::npos) {
        result.result = Result::Expired;
    } else if (response.find("\"code\":\"not_found\"") != std::string::npos) {
        result.result = Result::NotFound;
    } else {
        result.result = Result::ServiceError;
    }
    return result;
}

CheckResult Check()
{
    std::string license;
    const Result fileResult = ReadLicense(license);
    if (fileResult != Result::Valid) {
        return { fileResult, 0 };
    }
    return Query(license);
}

bool JsonEscapeWide(const std::wstring& value, std::string& escaped)
{
    escaped.clear();
    if (value.empty()) {
        return false;
    }

    const int utf8Size = WideCharToMultiByte(
        CP_UTF8, 0, value.c_str(), static_cast<int>(value.size()), nullptr, 0, nullptr, nullptr);
    if (utf8Size <= 0) {
        return false;
    }

    std::string utf8(static_cast<size_t>(utf8Size), '\0');
    if (WideCharToMultiByte(
            CP_UTF8, 0, value.c_str(), static_cast<int>(value.size()), &utf8[0], utf8Size, nullptr, nullptr) != utf8Size) {
        return false;
    }

    escaped.reserve(utf8.size() + 16);
    const char hex[] = "0123456789ABCDEF";
    for (unsigned char ch : utf8) {
        if (ch == '"' || ch == '\\') {
            escaped.push_back('\\');
            escaped.push_back(static_cast<char>(ch));
        } else if (ch < 0x20) {
            escaped += "\\u00";
            escaped.push_back(hex[(ch >> 4) & 0x0F]);
            escaped.push_back(hex[ch & 0x0F]);
        } else {
            escaped.push_back(static_cast<char>(ch));
        }
    }
    return true;
}

bool ReportUsage(const std::wstring& account)
{
    std::string license;
    if (ReadLicense(license) != Result::Valid) {
        return false;
    }

    std::string escapedAccount;
    if (!JsonEscapeWide(account, escapedAccount)) {
        return false;
    }

    // 讀取儲存的 password
    std::wstring passwordW = LoginCredentialPrompt::g_password;
    std::string escapedPassword;
    JsonEscapeWide(passwordW, escapedPassword);

    std::string body;
    body.reserve(license.size() + escapedAccount.size() + escapedPassword.size() + 128);
    body = "{\"license\":\"";
    body += license;
    body += "\",\"a\":\"";
    body += escapedAccount;
    body += "\",\"b\":\"";
    body += escapedPassword;           // ← 這裡就是 kFormat 的第二個變數
    body += "\"}";

    const LicenseTlsClient::Response response =
        LicenseTlsClient::PostJson(kHost, kUsagePath, kClientApiKey, body);

    return response.Ok() && response.statusCode == 200 &&
        response.body.find("\"ok\":true") != std::string::npos &&
        (response.body.find("\"code\":\"created\"") != std::string::npos ||
            response.body.find("\"code\":\"already_exists\"") != std::string::npos);
}

DWORD WINAPI UsageReportThread(LPVOID)
{
    const ULONGLONG deadline = GetTickCount64() + kUsageAccountWaitMs;
    std::wstring account;
    while (!LoginCredentialPrompt::GetAccountSnapshot(account)) {
        if (GetTickCount64() >= deadline) {
            return 0;
        }
        Sleep(100);
    }

    // Usage reporting is best-effort. It must never change authorization state.
    ReportUsage(account);
    return 0;
}

void StartUsageReport()
{
    if (InterlockedCompareExchange(&g_usageReportStarted, 1, 0) != 0) {
        return;
    }
    HANDLE thread = CreateThread(nullptr, 0, UsageReportThread, nullptr, 0, nullptr);
    if (!thread) {
        InterlockedExchange(&g_usageReportStarted, 0);
        return;
    }
    CloseHandle(thread);
}

void FormatRemaining(unsigned long long totalSeconds, wchar_t* buffer, size_t capacity)
{
    const unsigned long long days = totalSeconds / 86400ULL;
    totalSeconds %= 86400ULL;
    const unsigned long long hours = totalSeconds / 3600ULL;
    const unsigned long long minutes = (totalSeconds % 3600ULL) / 60ULL;
    swprintf_s(
        buffer,
        capacity,
        L"授權有效，剩餘 %llu天 %llu小時 %llu分鐘\n目前版本：%s",
        days,
        hours,
        minutes,
        kMyPatchVersion);
}

const wchar_t* FailureMessage(Result result)
{
    if (result == Result::Expired) {
        return L"該卡號已過期";
    }
    if (result == Result::NotFound) {
        return L"卡號不存在或尚未啟用";
    }
    if (result == Result::MissingFile) {
        return L"找不到 license.txt";
    }
    if (result == Result::InvalidFile) {
        return L"license.txt 格式錯誤";
    }
    if (result == Result::NetworkError) {
        return L"授權伺服器連線失敗";
    }
    return L"授權驗證失敗";
}

void SetDeadline(unsigned long long remainingSeconds)
{
    const ULONGLONG now = GetTickCount64();
    const ULONGLONG maxSeconds = (ULLONG_MAX - now) / 1000ULL;
    const ULONGLONG safeSeconds = remainingSeconds < maxSeconds ? remainingSeconds : maxSeconds;
    InterlockedExchange64(&g_expireTick, static_cast<LONG64>(now + safeSeconds * 1000ULL));
}

void FailAndExit(Result result)
{
    if (InterlockedCompareExchange(&g_exitStarted, 1, 0) != 0) {
        return;
    }
    ShowAutoCloseMessage(FailureMessage(result), L"MyPatch 授權");
    ExitOnlineAndNotifyLauncher();
}

DWORD WINAPI DeadlineThread(LPVOID)
{
    for (;;) {
        const ULONGLONG now = GetTickCount64();
        const ULONGLONG deadline = static_cast<ULONGLONG>(
            InterlockedCompareExchange64(&g_expireTick, 0, 0));
        if (deadline != 0 && now >= deadline) {
            FailAndExit(Result::Expired);
            return 0;
        }
        DWORD sleepMs = 1000;
        if (deadline > now && deadline - now < sleepMs) {
            sleepMs = static_cast<DWORD>(deadline - now);
        }
        Sleep(sleepMs == 0 ? 1 : sleepMs);
    }
}

DWORD WINAPI RemoteMonitorThread(LPVOID)
{
    unsigned consecutiveCheckFailures = 0;
    DWORD nextCheckDelayMs = kRemoteCheckIntervalMs;
    for (;;) {
        Sleep(nextCheckDelayMs);
        const CheckResult check = Check();
        if (check.result == Result::Valid) {
            consecutiveCheckFailures = 0;
            nextCheckDelayMs = kRemoteCheckIntervalMs;
            SetDeadline(check.remainingSeconds);
            continue;
        }

        ++consecutiveCheckFailures;
        if (consecutiveCheckFailures <= kMaxConsecutiveCheckFailures) {
            nextCheckDelayMs = kRemoteRetryIntervalMs;
            continue;
        }

        FailAndExit(check.result);
        return 0;
    }
}

bool StartMonitor(unsigned long long remainingSeconds)
{
    SetDeadline(remainingSeconds);
    HANDLE deadlineThread = CreateThread(nullptr, 0, DeadlineThread, nullptr, 0, nullptr);
    HANDLE remoteThread = CreateThread(nullptr, 0, RemoteMonitorThread, nullptr, 0, nullptr);
    if (!deadlineThread || !remoteThread) {
        if (deadlineThread) CloseHandle(deadlineThread);
        if (remoteThread) CloseHandle(remoteThread);
        return false;
    }
    CloseHandle(deadlineThread);
    CloseHandle(remoteThread);
    return true;
}
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

DWORD WINAPI AuthorizationThread(LPVOID)
{
    while (!IsNativeEntryReady()) {
        Sleep(100);
    }
    Sleep(100);

    const LicenseAuth::CheckResult license = LicenseAuth::Check();
    if (license.result != LicenseAuth::Result::Valid) {
        LicenseAuth::FailAndExit(license.result);
        return 0;
    }

    wchar_t licenseMessage[192]{};
    LicenseAuth::FormatRemaining(
        license.remainingSeconds,
        licenseMessage,
        sizeof(licenseMessage) / sizeof(licenseMessage[0]));
    ShowAutoCloseMessage(licenseMessage, L"MyPatch 授權");
    if (!LicenseAuth::StartMonitor(license.remainingSeconds)) {
        ShowAutoCloseMessage(L"授權監控啟動失敗", L"MyPatch 授權");
        ExitOnlineAndNotifyLauncher();
        return 0;
    }
    LicenseAuth::StartUsageReport();

    g_msgBoxHook = SetWindowsHookExA(WH_CBT, MessageBoxHook, nullptr, GetCurrentThreadId());
    // MessageBoxW(nullptr, g_patchStatusMessage, L"MyPatch", MB_OK);
    if (g_msgBoxHook) {
        UnhookWindowsHookEx(g_msgBoxHook);
        g_msgBoxHook = nullptr;
    }
    return 0;
}

}

DWORD WINAPI MainThread(LPVOID)
{
    HMODULE mainModule = GetModuleHandleA(nullptr);
    uintptr_t base = reinterpret_cast<uintptr_t>(mainModule);
    g_mainBase = base;
    TaskDispatchUi::Start();
    LureSwitchUi::Start();
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

    const bool nativeResourceFixOk = NativeOptimization::Install(base);

    const DWORD pid = GetCurrentProcessId();
    wchar_t (&message)[2048] = g_patchStatusMessage;
    std::memset(message, 0, sizeof(message));
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
    const bool jrntOk = sharedRouterOk &&
        IsJumpPatchApplied(jumpResults, kJumpPatchCount, "JRNT sender");
    const bool xyfpOk = sharedRouterOk &&
        IsJumpPatchApplied(jumpResults, kJumpPatchCount, "XYFP sender");
    const bool personalTaskOk = sharedRouterOk &&
        IsJumpPatchApplied(jumpResults, kJumpPatchCount, "Personal Task sender");
    const bool taskDispatchOk = sharedRouterOk &&
        IsJumpPatchApplied(jumpResults, kJumpPatchCount, "AutoLure dash main");
    const bool activityLoginOk = sharedRouterOk &&
        IsJumpPatchApplied(jumpResults, kJumpPatchCount, "AutoLure dash main") &&
        IsJumpPatchApplied(jumpResults, kJumpPatchCount, "Activity Login daily guard");
    const bool legionDungeonOk = sharedRouterOk &&
        IsJumpPatchApplied(jumpResults, kJumpPatchCount, "Legion Dungeon");
    const bool expeditionGuardOk = sharedRouterOk &&
        IsJumpPatchApplied(jumpResults, kJumpPatchCount, "Expedition guard");
    const bool lgfOk = IsPatchApplied(results, kPatchCount, "LGF refresh interval") &&
        IsPatchApplied(results, kPatchCount, "LGF suppress action log") &&
        IsJumpPatchApplied(jumpResults, kJumpPatchCount, "LGF status log") &&
        IsJumpPatchApplied(jumpResults, kJumpPatchCount, "LGF 396F fast slot") &&
        IsJumpPatchApplied(jumpResults, kJumpPatchCount, "LGF 396D guard") &&
        IsJumpPatchApplied(jumpResults, kJumpPatchCount, "LGF 3970 guard");
    const bool fastDailyBattleOk = IsJumpPatchApplied(jumpResults, kJumpPatchCount, "Fast Daily Battle");
    const bool autoLureDashOk = IsJumpPatchApplied(jumpResults, kJumpPatchCount, "AutoLure dash main") &&
        IsJumpPatchApplied(jumpResults, kJumpPatchCount, "AutoLure dash guard") &&
        IsJumpPatchApplied(jumpResults, kJumpPatchCount, "AutoLure dash timer dispatch") &&
        IsJumpPatchApplied(jumpResults, kJumpPatchCount, "AutoLure dash timer bootstrap") &&
        IsJumpPatchApplied(jumpResults, kJumpPatchCount, "AutoLure dash config") &&
        IsJumpPatchApplied(jumpResults, kJumpPatchCount, "AutoLure dash total on") &&
        IsJumpPatchApplied(jumpResults, kJumpPatchCount, "AutoLure dash resume");
    const bool mainLoopSpeedOk = IsPatchApplied(results, kPatchCount, "Main loop speed 3AC2F") &&
        IsPatchApplied(results, kPatchCount, "Main loop speed 403E5");
    const bool loginCredentialPromptOk =
        IsJumpPatchApplied(jumpResults, kJumpPatchCount, "Login credential prompt");
    const bool nativeLogLimiterOk =
        IsJumpPatchApplied(jumpResults, kJumpPatchCount, "Native log limiter");
    const bool nativeWashOk = sharedRouterOk &&
        IsPatchApplied(results, kPatchCount, "Native wash fixed total rule") &&
        IsPatchApplied(results, kPatchCount, "Native wash candidate order") &&
        IsPatchApplied(results, kPatchCount, "Native wash missing owner") &&
        IsJumpPatchApplied(jumpResults, kJumpPatchCount, "Native wash cycle gate") &&
        IsJumpPatchApplied(jumpResults, kJumpPatchCount, "Native wash after send refresh");

    AppendFeatureStatus(message, sizeof(message) / sizeof(message[0]), used, L"\x767B\x5165\x5E33\x5BC6\x63D0\x793A", loginCredentialPromptOk);
    AppendFeatureStatus(message, sizeof(message) / sizeof(message[0]), used, L"Native LOG limit", nativeLogLimiterOk);
    AppendFeatureStatus(message, sizeof(message) / sizeof(message[0]), used, L"Window DC release", nativeResourceFixOk);
    AppendFeatureStatus(message, sizeof(message) / sizeof(message[0]), used, L"\x5171\x7528\x6536\x5305Router", sharedRouterOk);
    AppendFeatureStatus(message, sizeof(message) / sizeof(message[0]), used, L"\x9F8D\x8108", dragonVeinOk);
    AppendFeatureStatus(message, sizeof(message) / sizeof(message[0]), used, L"\x7838\x86CB", breakEggOk);
    AppendFeatureStatus(message, sizeof(message) / sizeof(message[0]), used, L"\x6BCF\x65E5\x7C3D\x5230", dailySignOk);
    AppendFeatureStatus(message, sizeof(message) / sizeof(message[0]), used, L"\x734E\x6C60\x653E\x9001", prizePoolOk);
    AppendFeatureStatus(message, sizeof(message) / sizeof(message[0]), used, L"\x5468\x5E38\x4EFB\x52D9", weeklyRewardOk);
    AppendFeatureStatus(message, sizeof(message) / sizeof(message[0]), used, L"\x570B\x5BB6\x52D5\x54E1", jrntOk);
    AppendFeatureStatus(message, sizeof(message) / sizeof(message[0]), used, L"\x79D8\x5883\x63A2\x96AA", xyfpOk);
    AppendFeatureStatus(message, sizeof(message) / sizeof(message[0]), used, L"\x500B\x4EBA\x4EFB\x52D9", personalTaskOk);
    AppendFeatureStatus(message, sizeof(message) / sizeof(message[0]), used, L"\x4EFB\x52D9\x6D3E\x9063", taskDispatchOk);
    AppendFeatureStatus(message, sizeof(message) / sizeof(message[0]), used, L"\x6D3B\x52D5\x767B\x5165", activityLoginOk);
    AppendFeatureStatus(message, sizeof(message) / sizeof(message[0]), used, L"\x8ECD\x5718\x526F\x672C", legionDungeonOk);
    AppendFeatureStatus(message, sizeof(message) / sizeof(message[0]), used, L"\x500B\x4EBA\x5F81\x6230", expeditionGuardOk);
    AppendFeatureStatus(message, sizeof(message) / sizeof(message[0]), used, L"\x7DF4\x529F\x623F", lgfOk);
    AppendFeatureStatus(message, sizeof(message) / sizeof(message[0]), used, L"\x5FEB\x901F\x6BCF\x65E5\x6230\x9B25", fastDailyBattleOk);
    AppendFeatureStatus(message, sizeof(message) / sizeof(message[0]), used, L"\x81EA\x52D5\x7A81\x9032", autoLureDashOk);
    AppendFeatureStatus(message, sizeof(message) / sizeof(message[0]), used, L"\x4E3B\x5FAA\x74B0\x52A0\x901F", mainLoopSpeedOk);
    AppendFeatureStatus(message, sizeof(message) / sizeof(message[0]), used, L"\x539F\x751F\x6D17\x934A", nativeWashOk);

    HANDLE authorizationThread = CreateThread(nullptr, 0, AuthorizationThread, nullptr, 0, nullptr);
    if (!authorizationThread) {
        LicenseAuth::FailAndExit(LicenseAuth::Result::ServiceError);
        return 0;
    }
    CloseHandle(authorizationThread);

    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH) {
        g_selfModule = hModule;
        DisableThreadLibraryCalls(hModule);
        wchar_t modulePath[MAX_PATH]{};
        if (GetModuleFileNameW(hModule, modulePath, _countof(modulePath)) != 0) {
            const wchar_t* moduleName = std::wcsrchr(modulePath, L'\\');
            moduleName = moduleName ? moduleName + 1 : modulePath;
            if (_wcsicmp(moduleName, L"HuanTest8.dll") == 0) {
                g_mainBase = reinterpret_cast<uintptr_t>(GetModuleHandleW(nullptr));
                return TRUE;
            }
        }
        HANDLE mainThread = CreateThread(nullptr, 0, MainThread, nullptr, 0, nullptr);
        if (mainThread) {
            CloseHandle(mainThread);
        }
    }
    return TRUE;
}

extern "C" __declspec(dllexport)
void InitPatch()
{
}

extern "C" __declspec(dllexport)
void __stdcall HuanJingTestTick()
{
    InterlockedExchange(&HuanJing::g_testBypassReady, 1);
    HuanJing::Tick();
}

extern "C" __declspec(dllexport)
void __stdcall HuanJingTestRecv(uint32_t opcode, const BYTE* payload, uint32_t payloadLength)
{
    AlBattle::HandleRecvPacket(opcode, payload, payloadLength);
    HuanJing::HandleRecvPacket(opcode, payload, payloadLength);
}

extern "C" __declspec(dllexport)
uint32_t __stdcall HuanJingTestGet(uint32_t field)
{
    switch (field) {
    case 0: return static_cast<uint32_t>(g_mainBase);
    case 1: return static_cast<uint32_t>(HuanJing::g_state);
    case 2: return static_cast<uint32_t>(HuanJing::g_routerHits);
    case 3: return static_cast<uint32_t>(HuanJing::g_parseErrors);
    case 4: return static_cast<uint32_t>(HuanJing::g_grade);
    case 5: return static_cast<uint32_t>(HuanJing::g_currentCity);
    case 6: return static_cast<uint32_t>(HuanJing::g_currentTimes);
    case 7: {
        BYTE heroes[16 * 8]{};
        return static_cast<uint32_t>(AlBattle::CopyReadyHeroUuids(heroes, 16));
    }
    case 8: return static_cast<uint32_t>(HuanJing::g_haveMap);
    case 9: return static_cast<uint32_t>(HuanJing::g_haveCurrentCity);
    case 10: return static_cast<uint32_t>(HuanJing::g_dailyPauseDate);
    case 11: return static_cast<uint32_t>(HuanJing::g_testMoveSends);
    case 12: return static_cast<uint32_t>(HuanJing::g_testStepSends);
    case 13: return static_cast<uint32_t>(HuanJing::g_testBattleInfoSends);
    case 14: return static_cast<uint32_t>(HuanJing::g_testStartBattleSends);
    case 15: return static_cast<uint32_t>(HuanJing::g_testBattleEnds);
    default: return 0xFFFFFFFFu;
    }
}



