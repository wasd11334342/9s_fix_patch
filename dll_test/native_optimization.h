#pragma once

#include <windows.h>
#include <cstddef>
#include <cstdint>

struct NativeOptimizationSnapshot
{
    uint32_t structSize;
    uint32_t version;
    uint64_t privateBytes;
    uint64_t workingSetBytes;
    uint32_t handleCount;
    uint32_t gdiObjects;
    uint32_t userObjects;
    int32_t syncRequestCount;
    int32_t nativeLogItems;
    uint32_t nativeLogTrimmed;
    uint32_t windowDcReleaseCount;
    uint32_t sampleTick;
};

namespace NativeOptimization
{
constexpr int kNativeLogLimit = 1000;
constexpr int kNativeLogRetainAfterTrim = 900;

bool Install(uintptr_t mainBase);
void Tick(uintptr_t mainBase);
void __stdcall BeforeNativeLog(void* owner);
bool GetSnapshot(NativeOptimizationSnapshot& snapshot);
}

extern "C" __declspec(dllexport)
BOOL WINAPI MyPatchGetOptimizationSnapshot(
    NativeOptimizationSnapshot* snapshot,
    DWORD snapshotSize);
