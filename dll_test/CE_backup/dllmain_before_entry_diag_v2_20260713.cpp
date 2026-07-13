#include <windows.h>
#include <winhttp.h>
#include <climits>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cwchar>
#include <string>
#include <vector>

namespace
{
HHOOK g_msgBoxHook = nullptr;
HHOOK g_diagCallHook = nullptr;
HHOOK g_diagCallRetHook = nullptr;
HMODULE g_selfModule = nullptr;
wchar_t g_patchStatusMessage[2048]{};
constexpr DWORD kMessageBoxAutoCloseMs = 3000;
UINT g_diagUpdateNameMsg = 0;
volatile LONG g_diagLogLock = 0;
uintptr_t g_mainBase = 0;

void DiagLog(const char* text)
{
    if (!text || !g_selfModule) {
        return;
    }
    while (InterlockedCompareExchange(&g_diagLogLock, 1, 0) != 0) {
        Sleep(0);
    }
    wchar_t path[MAX_PATH]{};
    const DWORD length = GetModuleFileNameW(g_selfModule, path, MAX_PATH);
    if (length > 0 && length < MAX_PATH) {
        wchar_t* slash = wcsrchr(path, L'\\');
        if (slash) {
            wcscpy_s(slash + 1, MAX_PATH - static_cast<size_t>(slash + 1 - path), L"mypatch_entry_diag.log");
            HANDLE file = CreateFileW(path, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE,
                nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
            if (file != INVALID_HANDLE_VALUE) {
                char line[256]{};
                const int count = std::snprintf(line, sizeof(line), "tick=%llu tid=%lu %s\r\n",
                    static_cast<unsigned long long>(GetTickCount64()), GetCurrentThreadId(), text);
                if (count > 0) {
                    DWORD written = 0;
                    WriteFile(file, line, static_cast<DWORD>(count), &written, nullptr);
                }
                CloseHandle(file);
            }
        }
    }
    InterlockedExchange(&g_diagLogLock, 0);
}

LRESULT CALLBACK DiagCallWndProc(int code, WPARAM wParam, LPARAM lParam)
{
    if (code >= 0 && lParam) {
        const CWPSTRUCT* info = reinterpret_cast<const CWPSTRUCT*>(lParam);
        if (info->message == g_diagUpdateNameMsg) {
            DiagLog("MSG_UPDATE_GETNAME dispatch begin");
        }
    }
    return CallNextHookEx(g_diagCallHook, code, wParam, lParam);
}

LRESULT CALLBACK DiagCallWndRetProc(int code, WPARAM wParam, LPARAM lParam)
{
    if (code >= 0 && lParam) {
        const CWPRETSTRUCT* info = reinterpret_cast<const CWPRETSTRUCT*>(lParam);
        if (info->message == g_diagUpdateNameMsg) {
            DiagLog("MSG_UPDATE_GETNAME dispatch returned");
        }
    }
    return CallNextHookEx(g_diagCallRetHook, code, wParam, lParam);
}

DWORD WINAPI DiagUiHookThread(LPVOID)
{
    DiagLog("UI message observer waiting");
    HWND mainHwnd = nullptr;
    for (DWORD i = 0; i < 1200 && !mainHwnd; ++i) {
        if (g_mainBase != 0) {
            mainHwnd = *reinterpret_cast<HWND volatile*>(g_mainBase + 0x2300A4);
        }
        if (!mainHwnd) Sleep(100);
    }
    if (!mainHwnd) {
        DiagLog("UI message observer: main HWND missing");
        return 0;
    }
    g_diagUpdateNameMsg = RegisterWindowMessageW(L"MSG_UPDATE_GETNAME");
    const DWORD uiThread = GetWindowThreadProcessId(mainHwnd, nullptr);
    g_diagCallHook = SetWindowsHookExW(WH_CALLWNDPROC, DiagCallWndProc, g_selfModule, uiThread);
    g_diagCallRetHook = SetWindowsHookExW(WH_CALLWNDPROCRET, DiagCallWndRetProc, g_selfModule, uiThread);
    DiagLog((g_diagCallHook && g_diagCallRetHook) ? "UI message observer installed" : "UI message observer install FAILED");
    return 0;
}

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
uint32_t g_ids[4] = { 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0 };
BYTE g_claimPending[4]{};
BYTE g_payloadZero = 0;
BYTE g_payload4F37 = 0;
uint32_t g_payload4F36 = 0;

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

namespace TaskDispatchUi
{
constexpr UINT kCheckboxId = 0x0439;
constexpr UINT kPrivateMessage = 0x8439;
constexpr UINT kTimerId = 0x843A;

volatile LONG g_started = 0;
volatile LONG g_switch = 0;
volatile LONG g_lastValue = 0;
volatile LONG g_hitCount = 0;
volatile LONG g_status = 0;
HWND g_settingsHwnd = nullptr;
HWND g_parentHwnd = nullptr;
HWND g_checkboxHwnd = nullptr;
HWND g_weeklyHwnd = nullptr;
HWND g_dailyHwnd = nullptr;
WNDPROC g_oldProc = nullptr;
int g_x = 0;
int g_y = 0;
int g_w = 0;
int g_h = 0;

const wchar_t kSettingsTitle[] = L"\x8A2D\x7F6E";
const wchar_t kCheckboxText[] = L"\x4EFB\x52D9\x6D3E\x9063";

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
volatile LONG g_restoredTeamId = 0;
volatile LONG g_unlimitPassedOnce = 0;
volatile LONG g_battleMode = 0;
volatile LONG g_unlimitCount = 0;
uint32_t g_unlimitId = 0;
uint16_t g_teamIds[kMaxTeams]{};
uint16_t g_teamDungeonIds[kMaxTeams]{};
uint32_t g_teamOffsets[kMaxTeams]{};
BYTE g_teamPeople[kMaxTeams]{};
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

namespace AutoLureDash
{
constexpr bool kEnableDashDiagLog = false;
constexpr DWORD kPhaseGapMs = 100;
constexpr DWORD kFallbackCheckMs = 500;
constexpr DWORD kIdleScanMs = 1000;
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
volatile LONG g_showFlag = 0;
volatile LONG g_configReadHits = 0;
volatile LONG g_configLastStrike = 0;
volatile LONG g_configLastLure = 0;
volatile LONG g_configLastFallback = 0;

const wchar_t kConfigSection[] = L"WorldWar";
const wchar_t kLureKey[] = L"bLure";
const wchar_t kFallbackKey[] = L"bFallback";
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

const MemoryPatch kPatches[] = {
    { "Dragon vein fix", 0x4AA10, kDragonVeinPatchBytes, sizeof(kDragonVeinPatchBytes) },
    { "Break egg fix", 0x36B60, kBreakEggPatchBytes, sizeof(kBreakEggPatchBytes) },
    { "LGF refresh interval", 0x3719C, kLgfRefreshIntervalBytes, sizeof(kLgfRefreshIntervalBytes) },
    { "LGF suppress action log", 0x37385, kLgfSuppressActionLogBytes, sizeof(kLgfSuppressActionLogBytes) },
    { "Main loop speed 3AC2F", 0x3AC2F, kMainLoopSpeed1000MsBytes, sizeof(kMainLoopSpeed1000MsBytes) },
    { "Main loop speed 403E5", 0x403E5, kMainLoopSpeed1000MsBytes, sizeof(kMainLoopSpeed1000MsBytes) },
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

const JumpPatch kJumpPatches[] = {
    { "Fast Daily Battle", 0x4A785, 11, 128, FastDailyBattle::BuildSend37A4Code },
    { "Shared recv router", 0x42AD0, 5, 128, SharedRecvRouter::BuildCode },
    { "Daily Sign send tick", 0x38F90, 5, 128, DailySign::BuildSendCode },
    { "Prize Pool sender", 0x364C0, 5, 128, PrizePool::BuildSendCode },
    { "Weekly Reward sender", 0x35CE0, 5, 128, WeeklyReward::BuildSendCode },
    { "JRNT sender", 0x36A90, 11, 128, Jrnt::BuildSendCode },
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
    { "AutoLure dash timer", 0x403A3, 12, 128, AutoLureDash::BuildTimerCode },
    { "AutoLure dash config", 0x4B79B, 7, 160, AutoLureDash::BuildConfigCode },
    { "AutoLure dash total on", 0x401E0, 5, 64, AutoLureDash::BuildTotalOnCode },
    { "AutoLure dash resume", 0x412F0, 5, 64, AutoLureDash::BuildResumeCode },
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

void Send1483(BYTE* group)
{
    RefreshMarchFreeLogState();
    if (IsMarchFreeExhausted()) {
        WriteNoMarchFreeLogOnce();
        FinishAll();
        return;
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

__declspec(noinline) void __stdcall DashTick()
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
            if (g_waitingNoRush == 1 || g_hasWaiting == 1) {
                WriteDashDiag(kDiagAllowOriginalWaiting, 0, 0);
                ResetDashState();
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

bool BuildMainCode(uintptr_t base, CodeBuffer& code)
{
    const uint32_t action = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(&g_action));
    return AppendByte(code, 0x9C) &&
        AppendPushad(code) &&
        AppendRel32Instruction(code, 0xE8, reinterpret_cast<uintptr_t>(&TaskDispatch::SendTick)) &&
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

bool BuildConfigCode(uintptr_t base, CodeBuffer& code)
{
    const uint32_t readHits = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(&g_configReadHits));
    const uint32_t lastStrike = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(&g_configLastStrike));
    const uint32_t lureSwitch = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(&g_lureSwitch));
    const uint32_t lastLure = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(&g_configLastLure));
    const uint32_t fallbackSwitch = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(&g_fallbackSwitch));
    const uint32_t lastFallback = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(&g_configLastFallback));

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

void HandleRecvPacket(uint32_t opcode, const BYTE* payload, uint32_t payloadLength)
{
    if ((opcode & 0xFFFF) != 0x4F35 || !payload || payloadLength < 4) {
        return;
    }

    InterlockedExchange(&g_pendingOpen, 0);
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
    for (uint16_t task = 0; task < taskCount; ++task) {
        if (cursor + 4 > end) {
            return;
        }
        const uint32_t taskId = ReadBe32(cursor);
        cursor += 4;

        if (!SkipUtf(cursor, end) ||
            !SkipUtf(cursor, end) ||
            !SkipUtf(cursor, end) ||
            !SkipUtf(cursor, end) ||
            cursor + 8 > end) {
            return;
        }

        cursor += 4; // rewardBox
        const uint32_t taskState = ReadBe32(cursor);
        cursor += 4;
        if (!SkipUtf(cursor, end)) {
            return;
        }

        if (taskState == 1 && pendingIndex < 3) {
            g_ids[pendingIndex] = taskId;
            g_claimPending[pendingIndex] = 1;
            ++pendingIndex;
        }
    }
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

LRESULT CALLBACK ParentWndProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam)
{
    if (message == WM_COMMAND && (LOWORD(wParam) == kCheckboxId)) {
        SyncSwitch();
        return g_oldProc ? CallWindowProcW(g_oldProc, hwnd, message, wParam, lParam) : DefWindowProcW(hwnd, message, wParam, lParam);
    }

    if (message == WM_TIMER && wParam == kTimerId) {
        SyncSwitch();
        return 1;
    }

    if (message == kPrivateMessage) {
        if (wParam == 1) {
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

            if (g_checkboxHwnd) {
                HFONT font = reinterpret_cast<HFONT>(SendMessageW(g_weeklyHwnd, WM_GETFONT, 0, 0));
                if (font) {
                    SendMessageW(g_checkboxHwnd, WM_SETFONT, reinterpret_cast<WPARAM>(font), TRUE);
                }
                ShowWindow(g_checkboxHwnd, SW_SHOW);
                SetTimer(g_parentHwnd, kTimerId, 1000, nullptr);
                SendMessageW(g_checkboxHwnd, BM_SETCHECK, g_switch != 0 ? BST_CHECKED : BST_UNCHECKED, 0);
                SyncSwitch();
                InterlockedExchange(&g_status, 7);
            }
            return 1;
        }

        if (wParam == 2) {
            KillTimer(g_parentHwnd, kTimerId);
            if (g_checkboxHwnd && IsWindow(g_checkboxHwnd)) {
                DestroyWindow(g_checkboxHwnd);
            }
            g_checkboxHwnd = nullptr;
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

    g_oldProc = reinterpret_cast<WNDPROC>(SetWindowLongPtrW(g_parentHwnd, GWLP_WNDPROC, reinterpret_cast<LONG_PTR>(ParentWndProc)));
    if (!g_oldProc) {
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
    PutIdPayload(g_bufTeam4, static_cast<uint16_t>(g_teamId));
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

void ResetState()
{
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
    InterlockedExchange(&g_battleMode, 1);
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
        InterlockedExchange(&g_waitTick, static_cast<LONG>(GetGameTick()));
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
    (void)matchIndex;
    Finish();
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
void Handle42A1(const BYTE* payload, uint32_t payloadLength)
{
    if (g_state != 1 || payloadLength < 0x0D) {
        return;
    }

    if (TryApply42A1TimeBlock(payload, payloadLength)) {
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

void ParseTeams(const BYTE* payload, uint32_t payloadLength)
{
    InterlockedExchange(&g_teamCount, 0);
    InterlockedExchange(&g_peopleCount, 0);
    std::memset(g_teamIds, 0, sizeof(g_teamIds));
    std::memset(g_teamDungeonIds, 0, sizeof(g_teamDungeonIds));
    std::memset(g_teamOffsets, 0, sizeof(g_teamOffsets));
    std::memset(g_teamPeople, 0, sizeof(g_teamPeople));
    if (payloadLength < 2) {
        InterlockedExchange(&g_payloadTeamCount, 0);
        return;
    }

    InterlockedExchange(&g_payloadTeamCount, payload[1]);
    if (g_payloadTeamCount == 0 || payloadLength < 8) {
        return;
    }

    for (uint32_t offset = 0; offset + 2 <= payloadLength; ++offset) {
        if (ReadLe16(payload + offset) != 0x0C00 || offset < 6 || g_teamCount >= static_cast<LONG>(kMaxTeams)) {
            continue;
        }
        const LONG index = g_teamCount;
        g_teamIds[index] = ReadLe16(payload + offset - 6);
        g_teamDungeonIds[index] = ReadLe16(payload + offset - 2);
        g_teamOffsets[index] = offset;
        InterlockedExchange(&g_teamCount, index + 1);
    }

    for (uint32_t offset = 0; offset + 4 <= payloadLength; ++offset) {
        if (ReadLe32(payload + offset) != 0x7D7B0200 || offset < 5 || g_peopleCount >= static_cast<LONG>(kMaxTeams)) {
            continue;
        }
        const LONG index = g_peopleCount;
        g_teamPeople[index] = payload[offset - 5];
        InterlockedExchange(&g_peopleCount, index + 1);
    }
}

BYTE FindPeopleNearTeam(const BYTE* payload, uint32_t payloadLength, LONG teamIndex)
{
    if (!payload || teamIndex < 0 || teamIndex >= static_cast<LONG>(kMaxTeams)) {
        return 0;
    }

    uint32_t offset = g_teamOffsets[teamIndex];
    if (offset >= payloadLength || offset + 4 > payloadLength) {
        return 0;
    }

    uint32_t end = offset + 0x80;
    if (end + 4 > payloadLength) {
        end = payloadLength >= 4 ? payloadLength - 4 : 0;
    }

    for (uint32_t cursor = offset; cursor <= end; ++cursor) {
        if (cursor != offset && cursor + 2 <= payloadLength && ReadLe16(payload + cursor) == 0x0C00) {
            break;
        }
        if (cursor >= 5 && cursor + 4 <= payloadLength && ReadLe32(payload + cursor) == 0x7D7B0200) {
            g_teamPeople[teamIndex] = payload[cursor - 5];
            return g_teamPeople[teamIndex];
        }
    }

    return 0;
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

    InterlockedExchange(&g_createTeamMissCount, 0);
    return false;
}

void Handle42A4(const BYTE* payload, uint32_t payloadLength)
{
    if (g_state != 3 && g_state != 4) {
        return;
    }

    ParseTeams(payload, payloadLength);
    if (g_state == 3) {
        if (g_payloadTeamCount == 0) {
            if (WaitBeforeCreateTeam()) {
                return;
            }
            InterlockedExchange(&g_battleMode, 3);
            Send4297();
            WriteDungeonLog(kLogCreateFormat, g_logIndex);
            Finish();
            return;
        }

        const LONG count = g_teamCount < static_cast<LONG>(kMaxTeams) ? g_teamCount : static_cast<LONG>(kMaxTeams);
        for (LONG i = 0; i < count; ++i) {
            const BYTE people = g_teamPeople[i] == 1 ? 1 : FindPeopleNearTeam(payload, payloadLength, i);
            if (g_teamDungeonIds[i] != static_cast<uint16_t>(g_currentId) || people != 1) {
                continue;
            }
            InterlockedExchange(&g_createTeamMissCount, 0);
            InterlockedExchange(&g_battleMode, 3);
            InterlockedExchange(&g_teamId, g_teamIds[i]);
            Send4296();
            Send4293();
            WriteJoinLog();
            Finish();
            return;
        }

        if (WaitBeforeCreateTeam()) {
            return;
        }
        InterlockedExchange(&g_battleMode, 3);
        Send4297();
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
            if (g_teamIds[i] != static_cast<uint16_t>(g_helpTrackId)) {
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
        }
        return;
    }

    if (g_state != 0) {
        if (g_state == 5) {
            return;
        }
        if (now - static_cast<DWORD>(g_waitTick) >= kWaitTimeoutMs) {
            InterlockedExchange(&g_state, 0);
        }
        return;
    }

    if (now < static_cast<DWORD>(g_nextTick)) {
        return;
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
    if (opcode == 0x04B9) {
        DiagLog("shared router received opcode 04B9");
    }
    InterlockedExchange(&g_clearStackArg, 0);
    DailySign::HandleRecvPacket(opcode, payload);
    PrizePool::HandleRecvPacket(opcode, payload);
    WeeklyReward::HandleRecvPacket(opcode, payload, payloadLength);
    Jrnt::HandleRecvPacket(opcode, payload, payloadLength);
    Xyfp::HandleRecvPacket(opcode, payload, payloadLength);
    PersonalTask::HandleRecvPacket(opcode, payload, payloadLength);
    TaskDispatch::HandleRecvPacket(opcode, payload, payloadLength);
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
    MessageBoxW(nullptr, message, title, MB_OK | MB_ICONINFORMATION);
    if (g_msgBoxHook) {
        UnhookWindowsHookEx(g_msgBoxHook);
        g_msgBoxHook = nullptr;
    }
}

namespace LicenseAuth
{
constexpr wchar_t kHost[] = L"mypatch-license-auth.wasd11334342.workers.dev";
constexpr wchar_t kPath[] = L"/";
constexpr char kClientApiKey[] = "7ca30c81d310863317025e7c37701f35ab050af6c0443266ba5a99df39feece8";

__declspec(align(8)) volatile LONG64 g_expireTick = 0;
volatile LONG g_exitStarted = 0;

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

bool ReadResponse(HINTERNET request, std::string& response)
{
    response.clear();
    for (;;) {
        DWORD available = 0;
        if (!WinHttpQueryDataAvailable(request, &available)) {
            return false;
        }
        if (available == 0) {
            return true;
        }
        if (response.size() + available > 16384) {
            return false;
        }
        const size_t oldSize = response.size();
        response.resize(oldSize + available);
        DWORD read = 0;
        if (!WinHttpReadData(request, &response[oldSize], available, &read)) {
            return false;
        }
        response.resize(oldSize + read);
    }
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
    HINTERNET session = WinHttpOpen(L"MyPatch-License/1.0", WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
        WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!session) {
        result.result = Result::NetworkError;
        return result;
    }
    WinHttpSetTimeouts(session, 5000, 5000, 7000, 7000);

    HINTERNET connection = WinHttpConnect(session, kHost, INTERNET_DEFAULT_HTTPS_PORT, 0);
    HINTERNET request = connection ? WinHttpOpenRequest(connection, L"POST", kPath, nullptr,
        WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE) : nullptr;
    if (!request) {
        if (connection) WinHttpCloseHandle(connection);
        WinHttpCloseHandle(session);
        result.result = Result::NetworkError;
        return result;
    }

    std::wstring headers = L"Content-Type: application/json\r\nx-api-key: ";
    for (const char* p = kClientApiKey; *p; ++p) {
        headers.push_back(static_cast<wchar_t>(*p));
    }
    const std::string body = std::string("{\"license\":\"") + license + "\"}";
    const BOOL sent = WinHttpSendRequest(request, headers.c_str(), static_cast<DWORD>(-1L),
        const_cast<char*>(body.data()), static_cast<DWORD>(body.size()), static_cast<DWORD>(body.size()), 0);
    const BOOL received = sent ? WinHttpReceiveResponse(request, nullptr) : FALSE;

    DWORD status = 0;
    DWORD statusSize = sizeof(status);
    std::string response;
    const bool readOk = received && WinHttpQueryHeaders(request,
        WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_HEADER_NAME_BY_INDEX,
        &status, &statusSize, WINHTTP_NO_HEADER_INDEX) && ReadResponse(request, response);

    WinHttpCloseHandle(request);
    WinHttpCloseHandle(connection);
    WinHttpCloseHandle(session);

    if (!readOk) {
        result.result = Result::NetworkError;
        return result;
    }
    if (status != 200) {
        result.result = Result::ServiceError;
        return result;
    }
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

void FormatRemaining(unsigned long long totalSeconds, wchar_t* buffer, size_t capacity)
{
    const unsigned long long days = totalSeconds / 86400ULL;
    totalSeconds %= 86400ULL;
    const unsigned long long hours = totalSeconds / 3600ULL;
    const unsigned long long minutes = (totalSeconds % 3600ULL) / 60ULL;
    swprintf_s(buffer, capacity, L"授權有效，剩餘 %llu天 %llu小時 %llu分鐘", days, hours, minutes);
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
    ExitProcess(0);
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
    for (;;) {
        Sleep(60000);
        const CheckResult check = Check();
        if (check.result == Result::Valid) {
            SetDeadline(check.remainingSeconds);
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
    DiagLog("authorization thread begin");
    const LicenseAuth::CheckResult license = LicenseAuth::Check();
    DiagLog(license.result == LicenseAuth::Result::Valid ? "authorization check valid" : "authorization check FAILED");
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
        ExitProcess(0);
        return 0;
    }

    g_msgBoxHook = SetWindowsHookExA(WH_CBT, MessageBoxHook, nullptr, GetCurrentThreadId());
    MessageBoxW(nullptr, g_patchStatusMessage, L"MyPatch", MB_OK);
    if (g_msgBoxHook) {
        UnhookWindowsHookEx(g_msgBoxHook);
        g_msgBoxHook = nullptr;
    }
    return 0;
}

}

DWORD WINAPI MainThread(LPVOID)
{
    DiagLog("main thread begin");
    HMODULE mainModule = GetModuleHandleA(nullptr);
    uintptr_t base = reinterpret_cast<uintptr_t>(mainModule);
    g_mainBase = base;
    TaskDispatchUi::Start();
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
    DiagLog("all patch attempts completed");

    HANDLE diagThread = CreateThread(nullptr, 0, DiagUiHookThread, nullptr, 0, nullptr);
    if (diagThread) {
        CloseHandle(diagThread);
    } else {
        DiagLog("diagnostic UI thread create FAILED");
    }

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
        IsJumpPatchApplied(jumpResults, kJumpPatchCount, "AutoLure dash timer") &&
        IsJumpPatchApplied(jumpResults, kJumpPatchCount, "AutoLure dash config") &&
        IsJumpPatchApplied(jumpResults, kJumpPatchCount, "AutoLure dash total on") &&
        IsJumpPatchApplied(jumpResults, kJumpPatchCount, "AutoLure dash resume");
    const bool mainLoopSpeedOk = IsPatchApplied(results, kPatchCount, "Main loop speed 3AC2F") &&
        IsPatchApplied(results, kPatchCount, "Main loop speed 403E5");

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
    AppendFeatureStatus(message, sizeof(message) / sizeof(message[0]), used, L"\x8ECD\x5718\x526F\x672C", legionDungeonOk);
    AppendFeatureStatus(message, sizeof(message) / sizeof(message[0]), used, L"\x500B\x4EBA\x5F81\x6230", expeditionGuardOk);
    AppendFeatureStatus(message, sizeof(message) / sizeof(message[0]), used, L"\x7DF4\x529F\x623F", lgfOk);
    AppendFeatureStatus(message, sizeof(message) / sizeof(message[0]), used, L"\x5FEB\x901F\x6BCF\x65E5\x6230\x9B25", fastDailyBattleOk);
    AppendFeatureStatus(message, sizeof(message) / sizeof(message[0]), used, L"\x81EA\x52D5\x7A81\x9032", autoLureDashOk);
    AppendFeatureStatus(message, sizeof(message) / sizeof(message[0]), used, L"\x4E3B\x5FAA\x74B0\x52A0\x901F", mainLoopSpeedOk);

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
        CreateThread(nullptr, 0, MainThread, nullptr, 0, nullptr);
    }
    return TRUE;
}

extern "C" __declspec(dllexport)
void InitPatch()
{
}




