// Inline hooking version - patches QueryPerformanceCounter function directly
// More reliable than IAT hooking - intercepts ALL calls regardless of how they're made

#include "speedhack.h"
#include <windows.h>
#include <psapi.h>
#include <vector>

// Global speed multiplier
double g_SpeedMultiplier = 1.0;

// Original function pointers
QueryPerformanceCounter_t OriginalQueryPerformanceCounter = nullptr;
QueryPerformanceFrequency_t OriginalQueryPerformanceFrequency = nullptr;

// Static variables to track timing
static LARGE_INTEGER s_LastCounter = {0};
static LARGE_INTEGER s_BaseCounter = {0};
static bool s_FirstCall = true;
static double s_AccumulatedTime = 0.0;

// Original bytes (for unhooking)
static BYTE s_OriginalBytes[16] = {0};
static DWORD s_OriginalBytesSize = 0;
static bool s_Hooked = false;

// Trampoline function pointer (points to original function after hook)
static QueryPerformanceCounter_t s_TrampolineQPC = nullptr;

// Hooked QueryPerformanceCounter
BOOL WINAPI HookedQueryPerformanceCounter(LARGE_INTEGER* lpPerformanceCount)
{
    if (!s_TrampolineQPC)
    {
        return FALSE;
    }

    LARGE_INTEGER realCounter;
    if (!s_TrampolineQPC(&realCounter))
    {
        return FALSE;
    }

    if (s_FirstCall)
    {
        s_BaseCounter = realCounter;
        s_LastCounter = realCounter;
        s_FirstCall = false;
        s_AccumulatedTime = 0.0;
        *lpPerformanceCount = realCounter;
        return TRUE;
    }

    int64_t delta = realCounter.QuadPart - s_LastCounter.QuadPart;
    double scaledDelta = delta / g_SpeedMultiplier;
    s_AccumulatedTime += scaledDelta;
    
    int64_t newCounter = s_BaseCounter.QuadPart + (int64_t)s_AccumulatedTime;
    lpPerformanceCount->QuadPart = newCounter;
    
    s_LastCounter = realCounter;
    return TRUE;
}

BOOL WINAPI HookedQueryPerformanceFrequency(LARGE_INTEGER* lpFrequency)
{
    if (!OriginalQueryPerformanceFrequency)
    {
        return FALSE;
    }
    return OriginalQueryPerformanceFrequency(lpFrequency);
}

// Inline hook - patch the function directly with trampoline
bool InstallInlineHook(LPVOID targetFunc, LPVOID hookFunc)
{
    if (!targetFunc || !hookFunc)
    {
        return false;
    }
    
    // Allocate memory for trampoline (original function + jump back)
    // We need at least 16 bytes for original code + 14 bytes for trampoline
    BYTE* trampoline = (BYTE*)VirtualAlloc(NULL, 32, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!trampoline)
    {
        return false;
    }
    
    // Copy first 16 bytes of original function to trampoline
    memcpy(trampoline, targetFunc, 16);
    
    // Add jump back to original function + 16 (skip the patched bytes)
    BYTE* pTramp = trampoline + 16;
    int64_t offsetBack = ((int64_t)targetFunc + 16) - ((int64_t)pTramp + 5);
    pTramp[0] = 0xE9; // JMP rel32
    *(int32_t*)(pTramp + 1) = (int32_t)offsetBack;
    
    // Set trampoline as the original function
    s_TrampolineQPC = (QueryPerformanceCounter_t)trampoline;
    
    // Save original bytes
    memcpy(s_OriginalBytes, targetFunc, sizeof(s_OriginalBytes));
    s_OriginalBytesSize = sizeof(s_OriginalBytes);
    
    // Calculate relative jump offset to hook function
    int64_t offset = (int64_t)hookFunc - ((int64_t)targetFunc + 5);
    
    // Check if offset fits in 32-bit signed integer
    if (offset > INT_MAX || offset < INT_MIN)
    {
        // Too far for relative jump, use absolute jump
        // FF 25 00 00 00 00 = JMP [RIP+0] followed by 8-byte address
        DWORD oldProtect;
        if (!VirtualProtect(targetFunc, 14, PAGE_EXECUTE_READWRITE, &oldProtect))
        {
            VirtualFree(trampoline, 0, MEM_RELEASE);
            return false;
        }
        
        BYTE* p = (BYTE*)targetFunc;
        p[0] = 0xFF; // JMP [RIP+0]
        p[1] = 0x25;
        *(int32_t*)(p + 2) = 0;
        *(int64_t*)(p + 6) = (int64_t)hookFunc;
        
        VirtualProtect(targetFunc, 14, oldProtect, &oldProtect);
        return true;
    }
    
    DWORD oldProtect;
    if (!VirtualProtect(targetFunc, 16, PAGE_EXECUTE_READWRITE, &oldProtect))
    {
        VirtualFree(trampoline, 0, MEM_RELEASE);
        return false;
    }
    
    // Write jump instruction: JMP rel32 (x64)
    BYTE* p = (BYTE*)targetFunc;
    p[0] = 0xE9; // JMP rel32
    *(int32_t*)(p + 1) = (int32_t)offset;
    
    // Fill rest with NOPs
    for (int i = 5; i < 16; i++)
    {
        p[i] = 0x90; // NOP
    }
    
    VirtualProtect(targetFunc, 16, oldProtect, &oldProtect);
    return true;
}

// Install hooks using inline hooking (more reliable)
bool InstallHooks()
{
    // Get original function addresses
    HMODULE hKernelBase = GetModuleHandleA("kernelbase.dll");
    if (!hKernelBase)
    {
        return false;
    }
    
    OriginalQueryPerformanceCounter = (QueryPerformanceCounter_t)
        GetProcAddress(hKernelBase, "QueryPerformanceCounter");
    OriginalQueryPerformanceFrequency = (QueryPerformanceFrequency_t)
        GetProcAddress(hKernelBase, "QueryPerformanceFrequency");
    
    if (!OriginalQueryPerformanceCounter || !OriginalQueryPerformanceFrequency)
    {
        return false;
    }
    
    // Install inline hook on QueryPerformanceCounter
    if (InstallInlineHook(OriginalQueryPerformanceCounter, HookedQueryPerformanceCounter))
    {
        s_Hooked = true;
        return true;
    }
    
    return false;
}

void RemoveHooks()
{
    if (s_Hooked && OriginalQueryPerformanceCounter && s_OriginalBytesSize > 0)
    {
        DWORD oldProtect;
        if (VirtualProtect(OriginalQueryPerformanceCounter, s_OriginalBytesSize, PAGE_EXECUTE_READWRITE, &oldProtect))
        {
            memcpy(OriginalQueryPerformanceCounter, s_OriginalBytes, s_OriginalBytesSize);
            VirtualProtect(OriginalQueryPerformanceCounter, s_OriginalBytesSize, oldProtect, &oldProtect);
            s_Hooked = false;
        }
    }
    
    // Free trampoline
    if (s_TrampolineQPC)
    {
        VirtualFree((LPVOID)s_TrampolineQPC, 0, MEM_RELEASE);
        s_TrampolineQPC = nullptr;
    }
}

void SetSpeedMultiplier(double multiplier)
{
    if (multiplier > 0.0 && multiplier <= 100.0)
    {
        g_SpeedMultiplier = multiplier;
    }
}

double GetSpeedMultiplier()
{
    return g_SpeedMultiplier;
}

