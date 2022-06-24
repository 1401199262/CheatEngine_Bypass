#include <Windows.h>
#include "MinHook/include/MinHook.h"

HANDLE g_hDriver = INVALID_HANDLE_VALUE;
#define STATUS_SUCCESS                   ((NTSTATUS)0x00000000L)    // ntsubauth
#define IOCTL_BLACKBONE_GRANT_ACCESS   (ULONG)CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)

typedef struct _HANDLE_GRANT_ACCESS
{
    HANDLE  handle;      // Handle to modify
    ULONG      pid;         // Process ID
    ULONG      access;      // Access flags to grant
} HANDLE_GRANT_ACCESS, * PHANDLE_GRANT_ACCESS;



BOOL EnsureDrvLoaded()
{
    // Already open
    if (g_hDriver && g_hDriver != INVALID_HANDLE_VALUE)
        return TRUE;

    // Try to open handle to existing driver
    g_hDriver = CreateFileW(
        L"\\\\.\\CE_Bypass",
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL, OPEN_EXISTING, 0, NULL
    );

    if (g_hDriver && g_hDriver != INVALID_HANDLE_VALUE)
        return TRUE;

    
    return FALSE;
}


typedef NTSTATUS (NTAPI*_NtGetContextThread)(__in HANDLE ThreadHandle, __inout PCONTEXT ThreadContext);
_NtGetContextThread RealNtGetContextThread = 0;

typedef NTSTATUS (NTAPI *_NtOpenThread)(OUT PHANDLE ThreadHandle, IN ACCESS_MASK AccessMask, IN PVOID ObjectAttributes, IN PVOID ClientId);
_NtOpenThread RealNtOpenThread = 0;

typedef NTSTATUS (NTAPI* _NtOpenProcess)(OUT PHANDLE ProcessHandle, IN ACCESS_MASK AccessMask, IN PVOID ObjectAttributes, IN PVOID ClientId);
_NtOpenProcess RealNtOpenProcess = 0;

NTSTATUS NTAPI HookNtGetContextThread(__in HANDLE ThreadHandle, __inout PCONTEXT ThreadContext)
{
    if (ThreadHandle != INVALID_HANDLE_VALUE && ThreadHandle)
    {
        HANDLE_GRANT_ACCESS buffer{};
        buffer.access = THREAD_ALL_ACCESS;
        buffer.handle = ThreadHandle;
        buffer.pid = GetCurrentProcessId();

        ULONG64 OutBuffer = 0;
        DeviceIoControl(g_hDriver, IOCTL_BLACKBONE_GRANT_ACCESS, &buffer, sizeof(HANDLE_GRANT_ACCESS), &OutBuffer, 8, 0, 0);
    }

    return RealNtGetContextThread(ThreadHandle, ThreadContext);
}

NTSTATUS NTAPI HookNtOpenProcess(OUT PHANDLE ProcessHandle, IN ACCESS_MASK AccessMask, IN PVOID ObjectAttributes, IN PVOID ClientId)
{
    NTSTATUS status = RealNtOpenProcess(ProcessHandle, AccessMask, ObjectAttributes, ClientId);
    if (status != STATUS_SUCCESS || !ProcessHandle || *ProcessHandle == INVALID_HANDLE_VALUE || *ProcessHandle == NULL) return status;

    HANDLE_GRANT_ACCESS buffer{};
    buffer.access = PROCESS_ALL_ACCESS;
    buffer.handle = *ProcessHandle;
    buffer.pid = GetCurrentProcessId();

    ULONG64 OutBuffer = 0;
    DeviceIoControl(g_hDriver, IOCTL_BLACKBONE_GRANT_ACCESS, &buffer, sizeof(HANDLE_GRANT_ACCESS), &OutBuffer, 8, 0, 0);

    return status;
}

NTSTATUS NTAPI HookNtOpenThread(OUT PHANDLE ThreadHandle, IN ACCESS_MASK AccessMask, IN PVOID ObjectAttributes, IN PVOID ClientId)
{
    NTSTATUS status = RealNtOpenThread(ThreadHandle, AccessMask, ObjectAttributes, ClientId);

    if (status && ThreadHandle && *ThreadHandle != INVALID_HANDLE_VALUE && *ThreadHandle)
    {
        HANDLE_GRANT_ACCESS buffer{};
        buffer.access = THREAD_ALL_ACCESS;
        buffer.handle = *ThreadHandle;
        buffer.pid = GetCurrentProcessId();

        ULONG64 OutBuffer = 0;
        DeviceIoControl(g_hDriver, IOCTL_BLACKBONE_GRANT_ACCESS, &buffer, sizeof(HANDLE_GRANT_ACCESS), &OutBuffer, 8, 0, 0);
    }

    return status;    
}

//ntopenthread
//readprocessmemory  zwreadvirtualmemory ntqueryinformationprocess ...

BOOL HookAll()
{    

    if (!EnsureDrvLoaded())
    {
        MessageBox(0, L"DrvNotLoad", L"DrvNotLoad", 0);
        return FALSE;
    }
       
    if (MH_Initialize() != MH_OK) { MessageBox(0, L"MH_Initialize failed", 0, 0); return FALSE; }
    if (MH_CreateHookApi(L"ntdll.dll", "NtOpenProcess", HookNtOpenProcess, (LPVOID*)&RealNtOpenProcess) != MH_OK) { MessageBox(0, L"MH_CreateHookApi failed", 0, 0); return FALSE; }
    if (MH_CreateHookApi(L"ntdll.dll", "NtOpenThread", HookNtOpenThread, (LPVOID*)&RealNtOpenThread) != MH_OK) { MessageBox(0, L"MH_CreateHookApi failed", 0, 0); return FALSE; }
    if (MH_CreateHookApi(L"ntdll.dll", "NtGetContextThread", HookNtGetContextThread, (LPVOID*)&RealNtGetContextThread) != MH_OK) { MessageBox(0, L"MH_CreateHookApi failed", 0, 0); return FALSE; }
    // and more

    if (MH_EnableHook(MH_ALL_HOOKS) != MH_OK) { MessageBox(0, L"MH_EnableHook failed", 0, 0); return FALSE; }

    return TRUE;
}

BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
    if (ul_reason_for_call == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(hModule);
        if (!HookAll()) { MessageBox(0, L"HookAll failed", 0, 0); exit(0); }
    }
    else if (ul_reason_for_call == DLL_PROCESS_DETACH)
    {
        CloseHandle(g_hDriver);
    }

    return TRUE;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// µ¼³öº¯Êý
#pragma comment(linker, "/EXPORT:SymGetOmapBlockBase=dbghelpOrg.SymGetOmapBlockBase,@1")
#pragma comment(linker, "/EXPORT:DbgHelpCreateUserDump=dbghelpOrg.DbgHelpCreateUserDump,@2")
#pragma comment(linker, "/EXPORT:DbgHelpCreateUserDumpW=dbghelpOrg.DbgHelpCreateUserDumpW,@3")
#pragma comment(linker, "/EXPORT:EnumDirTree=dbghelpOrg.EnumDirTree,@4")
#pragma comment(linker, "/EXPORT:EnumDirTreeW=dbghelpOrg.EnumDirTreeW,@5")
#pragma comment(linker, "/EXPORT:EnumerateLoadedModules=dbghelpOrg.EnumerateLoadedModules,@6")
#pragma comment(linker, "/EXPORT:EnumerateLoadedModules64=dbghelpOrg.EnumerateLoadedModules64,@7")
#pragma comment(linker, "/EXPORT:EnumerateLoadedModulesEx=dbghelpOrg.EnumerateLoadedModulesEx,@8")
#pragma comment(linker, "/EXPORT:EnumerateLoadedModulesExW=dbghelpOrg.EnumerateLoadedModulesExW,@9")
#pragma comment(linker, "/EXPORT:EnumerateLoadedModulesW64=dbghelpOrg.EnumerateLoadedModulesW64,@10")
#pragma comment(linker, "/EXPORT:ExtensionApiVersion=dbghelpOrg.ExtensionApiVersion,@11")
#pragma comment(linker, "/EXPORT:FindDebugInfoFile=dbghelpOrg.FindDebugInfoFile,@12")
#pragma comment(linker, "/EXPORT:FindDebugInfoFileEx=dbghelpOrg.FindDebugInfoFileEx,@13")
#pragma comment(linker, "/EXPORT:FindDebugInfoFileExW=dbghelpOrg.FindDebugInfoFileExW,@14")
#pragma comment(linker, "/EXPORT:FindExecutableImage=dbghelpOrg.FindExecutableImage,@15")
#pragma comment(linker, "/EXPORT:FindExecutableImageEx=dbghelpOrg.FindExecutableImageEx,@16")
#pragma comment(linker, "/EXPORT:FindExecutableImageExW=dbghelpOrg.FindExecutableImageExW,@17")
#pragma comment(linker, "/EXPORT:FindFileInPath=dbghelpOrg.FindFileInPath,@18")
#pragma comment(linker, "/EXPORT:FindFileInSearchPath=dbghelpOrg.FindFileInSearchPath,@19")
#pragma comment(linker, "/EXPORT:GetSymLoadError=dbghelpOrg.GetSymLoadError,@20")
#pragma comment(linker, "/EXPORT:GetTimestampForLoadedLibrary=dbghelpOrg.GetTimestampForLoadedLibrary,@21")
#pragma comment(linker, "/EXPORT:ImageDirectoryEntryToData=dbghelpOrg.ImageDirectoryEntryToData,@22")
#pragma comment(linker, "/EXPORT:ImageDirectoryEntryToDataEx=dbghelpOrg.ImageDirectoryEntryToDataEx,@23")
#pragma comment(linker, "/EXPORT:ImageNtHeader=dbghelpOrg.ImageNtHeader,@24")
#pragma comment(linker, "/EXPORT:ImageRvaToSection=dbghelpOrg.ImageRvaToSection,@25")
#pragma comment(linker, "/EXPORT:ImageRvaToVa=dbghelpOrg.ImageRvaToVa,@26")
#pragma comment(linker, "/EXPORT:ImagehlpApiVersion=dbghelpOrg.ImagehlpApiVersion,@27")
#pragma comment(linker, "/EXPORT:ImagehlpApiVersionEx=dbghelpOrg.ImagehlpApiVersionEx,@28")
#pragma comment(linker, "/EXPORT:MakeSureDirectoryPathExists=dbghelpOrg.MakeSureDirectoryPathExists,@29")
#pragma comment(linker, "/EXPORT:MiniDumpReadDumpStream=dbghelpOrg.MiniDumpReadDumpStream,@30")
#pragma comment(linker, "/EXPORT:MiniDumpWriteDump=dbghelpOrg.MiniDumpWriteDump,@31")
#pragma comment(linker, "/EXPORT:RangeMapAddPeImageSections=dbghelpOrg.RangeMapAddPeImageSections,@32")
#pragma comment(linker, "/EXPORT:RangeMapCreate=dbghelpOrg.RangeMapCreate,@33")
#pragma comment(linker, "/EXPORT:RangeMapFree=dbghelpOrg.RangeMapFree,@34")
#pragma comment(linker, "/EXPORT:RangeMapRead=dbghelpOrg.RangeMapRead,@35")
#pragma comment(linker, "/EXPORT:RangeMapRemove=dbghelpOrg.RangeMapRemove,@36")
#pragma comment(linker, "/EXPORT:RangeMapWrite=dbghelpOrg.RangeMapWrite,@37")
#pragma comment(linker, "/EXPORT:RemoveInvalidModuleList=dbghelpOrg.RemoveInvalidModuleList,@38")
#pragma comment(linker, "/EXPORT:ReportSymbolLoadSummary=dbghelpOrg.ReportSymbolLoadSummary,@39")
#pragma comment(linker, "/EXPORT:SearchTreeForFile=dbghelpOrg.SearchTreeForFile,@40")
#pragma comment(linker, "/EXPORT:SearchTreeForFileW=dbghelpOrg.SearchTreeForFileW,@41")
#pragma comment(linker, "/EXPORT:SetCheckUserInterruptShared=dbghelpOrg.SetCheckUserInterruptShared,@42")
#pragma comment(linker, "/EXPORT:SetSymLoadError=dbghelpOrg.SetSymLoadError,@43")
#pragma comment(linker, "/EXPORT:StackWalk=dbghelpOrg.StackWalk,@44")
#pragma comment(linker, "/EXPORT:StackWalk64=dbghelpOrg.StackWalk64,@45")
#pragma comment(linker, "/EXPORT:StackWalkEx=dbghelpOrg.StackWalkEx,@46")
#pragma comment(linker, "/EXPORT:SymAddSourceStream=dbghelpOrg.SymAddSourceStream,@47")
#pragma comment(linker, "/EXPORT:SymAddSourceStreamA=dbghelpOrg.SymAddSourceStreamA,@48")
#pragma comment(linker, "/EXPORT:SymAddSourceStreamW=dbghelpOrg.SymAddSourceStreamW,@49")
#pragma comment(linker, "/EXPORT:SymAddSymbol=dbghelpOrg.SymAddSymbol,@50")
#pragma comment(linker, "/EXPORT:SymAddSymbolW=dbghelpOrg.SymAddSymbolW,@51")
#pragma comment(linker, "/EXPORT:SymAddrIncludeInlineTrace=dbghelpOrg.SymAddrIncludeInlineTrace,@52")
#pragma comment(linker, "/EXPORT:SymCleanup=dbghelpOrg.SymCleanup,@53")
#pragma comment(linker, "/EXPORT:SymCompareInlineTrace=dbghelpOrg.SymCompareInlineTrace,@54")
#pragma comment(linker, "/EXPORT:SymDeleteSymbol=dbghelpOrg.SymDeleteSymbol,@55")
#pragma comment(linker, "/EXPORT:SymDeleteSymbolW=dbghelpOrg.SymDeleteSymbolW,@56")
#pragma comment(linker, "/EXPORT:SymEnumLines=dbghelpOrg.SymEnumLines,@57")
#pragma comment(linker, "/EXPORT:SymEnumLinesW=dbghelpOrg.SymEnumLinesW,@58")
#pragma comment(linker, "/EXPORT:SymEnumProcesses=dbghelpOrg.SymEnumProcesses,@59")
#pragma comment(linker, "/EXPORT:SymEnumSourceFileTokens=dbghelpOrg.SymEnumSourceFileTokens,@60")
#pragma comment(linker, "/EXPORT:SymEnumSourceFiles=dbghelpOrg.SymEnumSourceFiles,@61")
#pragma comment(linker, "/EXPORT:SymEnumSourceFilesW=dbghelpOrg.SymEnumSourceFilesW,@62")
#pragma comment(linker, "/EXPORT:SymEnumSourceLines=dbghelpOrg.SymEnumSourceLines,@63")
#pragma comment(linker, "/EXPORT:SymEnumSourceLinesW=dbghelpOrg.SymEnumSourceLinesW,@64")
#pragma comment(linker, "/EXPORT:SymEnumSym=dbghelpOrg.SymEnumSym,@65")
#pragma comment(linker, "/EXPORT:SymEnumSymbols=dbghelpOrg.SymEnumSymbols,@66")
#pragma comment(linker, "/EXPORT:SymEnumSymbolsEx=dbghelpOrg.SymEnumSymbolsEx,@67")
#pragma comment(linker, "/EXPORT:SymEnumSymbolsExW=dbghelpOrg.SymEnumSymbolsExW,@68")
#pragma comment(linker, "/EXPORT:SymEnumSymbolsForAddr=dbghelpOrg.SymEnumSymbolsForAddr,@69")
#pragma comment(linker, "/EXPORT:SymEnumSymbolsForAddrW=dbghelpOrg.SymEnumSymbolsForAddrW,@70")
#pragma comment(linker, "/EXPORT:SymEnumSymbolsW=dbghelpOrg.SymEnumSymbolsW,@71")
#pragma comment(linker, "/EXPORT:SymEnumTypes=dbghelpOrg.SymEnumTypes,@72")
#pragma comment(linker, "/EXPORT:SymEnumTypesByName=dbghelpOrg.SymEnumTypesByName,@73")
#pragma comment(linker, "/EXPORT:SymEnumTypesByNameW=dbghelpOrg.SymEnumTypesByNameW,@74")
#pragma comment(linker, "/EXPORT:SymEnumTypesW=dbghelpOrg.SymEnumTypesW,@75")
#pragma comment(linker, "/EXPORT:SymEnumerateModules=dbghelpOrg.SymEnumerateModules,@76")
#pragma comment(linker, "/EXPORT:SymEnumerateModules64=dbghelpOrg.SymEnumerateModules64,@77")
#pragma comment(linker, "/EXPORT:SymEnumerateModulesW64=dbghelpOrg.SymEnumerateModulesW64,@78")
#pragma comment(linker, "/EXPORT:SymEnumerateSymbols=dbghelpOrg.SymEnumerateSymbols,@79")
#pragma comment(linker, "/EXPORT:SymEnumerateSymbols64=dbghelpOrg.SymEnumerateSymbols64,@80")
#pragma comment(linker, "/EXPORT:SymEnumerateSymbolsW=dbghelpOrg.SymEnumerateSymbolsW,@81")
#pragma comment(linker, "/EXPORT:SymEnumerateSymbolsW64=dbghelpOrg.SymEnumerateSymbolsW64,@82")
#pragma comment(linker, "/EXPORT:SymFindDebugInfoFile=dbghelpOrg.SymFindDebugInfoFile,@83")
#pragma comment(linker, "/EXPORT:SymFindDebugInfoFileW=dbghelpOrg.SymFindDebugInfoFileW,@84")
#pragma comment(linker, "/EXPORT:SymFindExecutableImage=dbghelpOrg.SymFindExecutableImage,@85")
#pragma comment(linker, "/EXPORT:SymFindExecutableImageW=dbghelpOrg.SymFindExecutableImageW,@86")
#pragma comment(linker, "/EXPORT:SymFindFileInPath=dbghelpOrg.SymFindFileInPath,@87")
#pragma comment(linker, "/EXPORT:SymFindFileInPathW=dbghelpOrg.SymFindFileInPathW,@88")
#pragma comment(linker, "/EXPORT:SymFromAddr=dbghelpOrg.SymFromAddr,@89")
#pragma comment(linker, "/EXPORT:SymFromAddrW=dbghelpOrg.SymFromAddrW,@90")
#pragma comment(linker, "/EXPORT:SymFromIndex=dbghelpOrg.SymFromIndex,@91")
#pragma comment(linker, "/EXPORT:SymFromIndexW=dbghelpOrg.SymFromIndexW,@92")
#pragma comment(linker, "/EXPORT:SymFromInlineContext=dbghelpOrg.SymFromInlineContext,@93")
#pragma comment(linker, "/EXPORT:SymFromInlineContextW=dbghelpOrg.SymFromInlineContextW,@94")
#pragma comment(linker, "/EXPORT:SymFromName=dbghelpOrg.SymFromName,@95")
#pragma comment(linker, "/EXPORT:SymFromNameW=dbghelpOrg.SymFromNameW,@96")
#pragma comment(linker, "/EXPORT:SymFromToken=dbghelpOrg.SymFromToken,@97")
#pragma comment(linker, "/EXPORT:SymFromTokenW=dbghelpOrg.SymFromTokenW,@98")
#pragma comment(linker, "/EXPORT:SymFunctionTableAccess=dbghelpOrg.SymFunctionTableAccess,@99")
#pragma comment(linker, "/EXPORT:SymFunctionTableAccess64=dbghelpOrg.SymFunctionTableAccess64,@100")
#pragma comment(linker, "/EXPORT:SymFunctionTableAccess64AccessRoutines=dbghelpOrg.SymFunctionTableAccess64AccessRoutines,@101")
#pragma comment(linker, "/EXPORT:SymGetFileLineOffsets64=dbghelpOrg.SymGetFileLineOffsets64,@102")
#pragma comment(linker, "/EXPORT:SymGetHomeDirectory=dbghelpOrg.SymGetHomeDirectory,@103")
#pragma comment(linker, "/EXPORT:SymGetHomeDirectoryW=dbghelpOrg.SymGetHomeDirectoryW,@104")
#pragma comment(linker, "/EXPORT:SymGetLineFromAddr=dbghelpOrg.SymGetLineFromAddr,@105")
#pragma comment(linker, "/EXPORT:SymGetLineFromAddr64=dbghelpOrg.SymGetLineFromAddr64,@106")
#pragma comment(linker, "/EXPORT:SymGetLineFromAddrW64=dbghelpOrg.SymGetLineFromAddrW64,@107")
#pragma comment(linker, "/EXPORT:SymGetLineFromInlineContext=dbghelpOrg.SymGetLineFromInlineContext,@108")
#pragma comment(linker, "/EXPORT:SymGetLineFromInlineContextW=dbghelpOrg.SymGetLineFromInlineContextW,@109")
#pragma comment(linker, "/EXPORT:SymGetLineFromName=dbghelpOrg.SymGetLineFromName,@110")
#pragma comment(linker, "/EXPORT:SymGetLineFromName64=dbghelpOrg.SymGetLineFromName64,@111")
#pragma comment(linker, "/EXPORT:SymGetLineFromNameW64=dbghelpOrg.SymGetLineFromNameW64,@112")
#pragma comment(linker, "/EXPORT:SymGetLineNext=dbghelpOrg.SymGetLineNext,@113")
#pragma comment(linker, "/EXPORT:SymGetLineNext64=dbghelpOrg.SymGetLineNext64,@114")
#pragma comment(linker, "/EXPORT:SymGetLineNextW64=dbghelpOrg.SymGetLineNextW64,@115")
#pragma comment(linker, "/EXPORT:SymGetLinePrev=dbghelpOrg.SymGetLinePrev,@116")
#pragma comment(linker, "/EXPORT:SymGetLinePrev64=dbghelpOrg.SymGetLinePrev64,@117")
#pragma comment(linker, "/EXPORT:SymGetLinePrevW64=dbghelpOrg.SymGetLinePrevW64,@118")
#pragma comment(linker, "/EXPORT:SymGetModuleBase=dbghelpOrg.SymGetModuleBase,@119")
#pragma comment(linker, "/EXPORT:SymGetModuleBase64=dbghelpOrg.SymGetModuleBase64,@120")
#pragma comment(linker, "/EXPORT:SymGetModuleInfo=dbghelpOrg.SymGetModuleInfo,@121")
#pragma comment(linker, "/EXPORT:SymGetModuleInfo64=dbghelpOrg.SymGetModuleInfo64,@122")
#pragma comment(linker, "/EXPORT:SymGetModuleInfoW=dbghelpOrg.SymGetModuleInfoW,@123")
#pragma comment(linker, "/EXPORT:SymGetModuleInfoW64=dbghelpOrg.SymGetModuleInfoW64,@124")
#pragma comment(linker, "/EXPORT:SymGetOmaps=dbghelpOrg.SymGetOmaps,@125")
#pragma comment(linker, "/EXPORT:SymGetOptions=dbghelpOrg.SymGetOptions,@126")
#pragma comment(linker, "/EXPORT:SymGetScope=dbghelpOrg.SymGetScope,@127")
#pragma comment(linker, "/EXPORT:SymGetScopeW=dbghelpOrg.SymGetScopeW,@128")
#pragma comment(linker, "/EXPORT:SymGetSearchPath=dbghelpOrg.SymGetSearchPath,@129")
#pragma comment(linker, "/EXPORT:SymGetSearchPathW=dbghelpOrg.SymGetSearchPathW,@130")
#pragma comment(linker, "/EXPORT:SymGetSourceFile=dbghelpOrg.SymGetSourceFile,@131")
#pragma comment(linker, "/EXPORT:SymGetSourceFileFromToken=dbghelpOrg.SymGetSourceFileFromToken,@132")
#pragma comment(linker, "/EXPORT:SymGetSourceFileFromTokenW=dbghelpOrg.SymGetSourceFileFromTokenW,@133")
#pragma comment(linker, "/EXPORT:SymGetSourceFileToken=dbghelpOrg.SymGetSourceFileToken,@134")
#pragma comment(linker, "/EXPORT:SymGetSourceFileTokenW=dbghelpOrg.SymGetSourceFileTokenW,@135")
#pragma comment(linker, "/EXPORT:SymGetSourceFileW=dbghelpOrg.SymGetSourceFileW,@136")
#pragma comment(linker, "/EXPORT:SymGetSourceVarFromToken=dbghelpOrg.SymGetSourceVarFromToken,@137")
#pragma comment(linker, "/EXPORT:SymGetSourceVarFromTokenW=dbghelpOrg.SymGetSourceVarFromTokenW,@138")
#pragma comment(linker, "/EXPORT:SymGetSymFromAddr=dbghelpOrg.SymGetSymFromAddr,@139")
#pragma comment(linker, "/EXPORT:SymGetSymFromAddr64=dbghelpOrg.SymGetSymFromAddr64,@140")
#pragma comment(linker, "/EXPORT:SymGetSymFromName=dbghelpOrg.SymGetSymFromName,@141")
#pragma comment(linker, "/EXPORT:SymGetSymFromName64=dbghelpOrg.SymGetSymFromName64,@142")
#pragma comment(linker, "/EXPORT:SymGetSymNext=dbghelpOrg.SymGetSymNext,@143")
#pragma comment(linker, "/EXPORT:SymGetSymNext64=dbghelpOrg.SymGetSymNext64,@144")
#pragma comment(linker, "/EXPORT:SymGetSymPrev=dbghelpOrg.SymGetSymPrev,@145")
#pragma comment(linker, "/EXPORT:SymGetSymPrev64=dbghelpOrg.SymGetSymPrev64,@146")
#pragma comment(linker, "/EXPORT:SymGetSymbolFile=dbghelpOrg.SymGetSymbolFile,@147")
#pragma comment(linker, "/EXPORT:SymGetSymbolFileW=dbghelpOrg.SymGetSymbolFileW,@148")
#pragma comment(linker, "/EXPORT:SymGetTypeFromName=dbghelpOrg.SymGetTypeFromName,@149")
#pragma comment(linker, "/EXPORT:SymGetTypeFromNameW=dbghelpOrg.SymGetTypeFromNameW,@150")
#pragma comment(linker, "/EXPORT:SymGetTypeInfo=dbghelpOrg.SymGetTypeInfo,@151")
#pragma comment(linker, "/EXPORT:SymGetTypeInfoEx=dbghelpOrg.SymGetTypeInfoEx,@152")
#pragma comment(linker, "/EXPORT:SymGetUnwindInfo=dbghelpOrg.SymGetUnwindInfo,@153")
#pragma comment(linker, "/EXPORT:SymInitialize=dbghelpOrg.SymInitialize,@154")
#pragma comment(linker, "/EXPORT:SymInitializeW=dbghelpOrg.SymInitializeW,@155")
#pragma comment(linker, "/EXPORT:SymLoadModule=dbghelpOrg.SymLoadModule,@156")
#pragma comment(linker, "/EXPORT:SymLoadModule64=dbghelpOrg.SymLoadModule64,@157")
#pragma comment(linker, "/EXPORT:SymLoadModuleEx=dbghelpOrg.SymLoadModuleEx,@158")
#pragma comment(linker, "/EXPORT:SymLoadModuleExW=dbghelpOrg.SymLoadModuleExW,@159")
#pragma comment(linker, "/EXPORT:SymMatchFileName=dbghelpOrg.SymMatchFileName,@160")
#pragma comment(linker, "/EXPORT:SymMatchFileNameW=dbghelpOrg.SymMatchFileNameW,@161")
#pragma comment(linker, "/EXPORT:SymMatchString=dbghelpOrg.SymMatchString,@162")
#pragma comment(linker, "/EXPORT:SymMatchStringA=dbghelpOrg.SymMatchStringA,@163")
#pragma comment(linker, "/EXPORT:SymMatchStringW=dbghelpOrg.SymMatchStringW,@164")
#pragma comment(linker, "/EXPORT:SymNext=dbghelpOrg.SymNext,@165")
#pragma comment(linker, "/EXPORT:SymNextW=dbghelpOrg.SymNextW,@166")
#pragma comment(linker, "/EXPORT:SymPrev=dbghelpOrg.SymPrev,@167")
#pragma comment(linker, "/EXPORT:SymPrevW=dbghelpOrg.SymPrevW,@168")
#pragma comment(linker, "/EXPORT:SymQueryInlineTrace=dbghelpOrg.SymQueryInlineTrace,@169")
#pragma comment(linker, "/EXPORT:SymRefreshModuleList=dbghelpOrg.SymRefreshModuleList,@170")
#pragma comment(linker, "/EXPORT:SymRegisterCallback=dbghelpOrg.SymRegisterCallback,@171")
#pragma comment(linker, "/EXPORT:SymRegisterCallback64=dbghelpOrg.SymRegisterCallback64,@172")
#pragma comment(linker, "/EXPORT:SymRegisterCallbackW64=dbghelpOrg.SymRegisterCallbackW64,@173")
#pragma comment(linker, "/EXPORT:SymRegisterFunctionEntryCallback=dbghelpOrg.SymRegisterFunctionEntryCallback,@174")
#pragma comment(linker, "/EXPORT:SymRegisterFunctionEntryCallback64=dbghelpOrg.SymRegisterFunctionEntryCallback64,@175")
#pragma comment(linker, "/EXPORT:SymSearch=dbghelpOrg.SymSearch,@176")
#pragma comment(linker, "/EXPORT:SymSearchW=dbghelpOrg.SymSearchW,@177")
#pragma comment(linker, "/EXPORT:SymSetContext=dbghelpOrg.SymSetContext,@178")
#pragma comment(linker, "/EXPORT:SymSetHomeDirectory=dbghelpOrg.SymSetHomeDirectory,@179")
#pragma comment(linker, "/EXPORT:SymSetHomeDirectoryW=dbghelpOrg.SymSetHomeDirectoryW,@180")
#pragma comment(linker, "/EXPORT:SymSetOptions=dbghelpOrg.SymSetOptions,@181")
#pragma comment(linker, "/EXPORT:SymSetParentWindow=dbghelpOrg.SymSetParentWindow,@182")
#pragma comment(linker, "/EXPORT:SymSetScopeFromAddr=dbghelpOrg.SymSetScopeFromAddr,@183")
#pragma comment(linker, "/EXPORT:SymSetScopeFromIndex=dbghelpOrg.SymSetScopeFromIndex,@184")
#pragma comment(linker, "/EXPORT:SymSetScopeFromInlineContext=dbghelpOrg.SymSetScopeFromInlineContext,@185")
#pragma comment(linker, "/EXPORT:SymSetSearchPath=dbghelpOrg.SymSetSearchPath,@186")
#pragma comment(linker, "/EXPORT:SymSetSearchPathW=dbghelpOrg.SymSetSearchPathW,@187")
#pragma comment(linker, "/EXPORT:SymSrvDeltaName=dbghelpOrg.SymSrvDeltaName,@188")
#pragma comment(linker, "/EXPORT:SymSrvDeltaNameW=dbghelpOrg.SymSrvDeltaNameW,@189")
#pragma comment(linker, "/EXPORT:SymSrvGetFileIndexInfo=dbghelpOrg.SymSrvGetFileIndexInfo,@190")
#pragma comment(linker, "/EXPORT:SymSrvGetFileIndexInfoW=dbghelpOrg.SymSrvGetFileIndexInfoW,@191")
#pragma comment(linker, "/EXPORT:SymSrvGetFileIndexString=dbghelpOrg.SymSrvGetFileIndexString,@192")
#pragma comment(linker, "/EXPORT:SymSrvGetFileIndexStringW=dbghelpOrg.SymSrvGetFileIndexStringW,@193")
#pragma comment(linker, "/EXPORT:SymSrvGetFileIndexes=dbghelpOrg.SymSrvGetFileIndexes,@194")
#pragma comment(linker, "/EXPORT:SymSrvGetFileIndexesW=dbghelpOrg.SymSrvGetFileIndexesW,@195")
#pragma comment(linker, "/EXPORT:SymSrvGetSupplement=dbghelpOrg.SymSrvGetSupplement,@196")
#pragma comment(linker, "/EXPORT:SymSrvGetSupplementW=dbghelpOrg.SymSrvGetSupplementW,@197")
#pragma comment(linker, "/EXPORT:SymSrvIsStore=dbghelpOrg.SymSrvIsStore,@198")
#pragma comment(linker, "/EXPORT:SymSrvIsStoreW=dbghelpOrg.SymSrvIsStoreW,@199")
#pragma comment(linker, "/EXPORT:SymSrvStoreFile=dbghelpOrg.SymSrvStoreFile,@200")
#pragma comment(linker, "/EXPORT:SymSrvStoreFileW=dbghelpOrg.SymSrvStoreFileW,@201")
#pragma comment(linker, "/EXPORT:SymSrvStoreSupplement=dbghelpOrg.SymSrvStoreSupplement,@202")
#pragma comment(linker, "/EXPORT:SymSrvStoreSupplementW=dbghelpOrg.SymSrvStoreSupplementW,@203")
#pragma comment(linker, "/EXPORT:SymUnDName=dbghelpOrg.SymUnDName,@204")
#pragma comment(linker, "/EXPORT:SymUnDName64=dbghelpOrg.SymUnDName64,@205")
#pragma comment(linker, "/EXPORT:SymUnloadModule=dbghelpOrg.SymUnloadModule,@206")
#pragma comment(linker, "/EXPORT:SymUnloadModule64=dbghelpOrg.SymUnloadModule64,@207")
#pragma comment(linker, "/EXPORT:UnDecorateSymbolName=dbghelpOrg.UnDecorateSymbolName,@208")
#pragma comment(linker, "/EXPORT:UnDecorateSymbolNameW=dbghelpOrg.UnDecorateSymbolNameW,@209")
#pragma comment(linker, "/EXPORT:WinDbgExtensionDllInit=dbghelpOrg.WinDbgExtensionDllInit,@210")
#pragma comment(linker, "/EXPORT:block=dbghelpOrg.block,@211")
#pragma comment(linker, "/EXPORT:chksym=dbghelpOrg.chksym,@212")
#pragma comment(linker, "/EXPORT:dbghelp=dbghelpOrg.dbghelp,@213")
#pragma comment(linker, "/EXPORT:dh=dbghelpOrg.dh,@214")
#pragma comment(linker, "/EXPORT:fptr=dbghelpOrg.fptr,@215")
#pragma comment(linker, "/EXPORT:homedir=dbghelpOrg.homedir,@216")
#pragma comment(linker, "/EXPORT:inlinedbg=dbghelpOrg.inlinedbg,@217")
#pragma comment(linker, "/EXPORT:itoldyouso=dbghelpOrg.itoldyouso,@218")
#pragma comment(linker, "/EXPORT:lmi=dbghelpOrg.lmi,@219")
#pragma comment(linker, "/EXPORT:lminfo=dbghelpOrg.lminfo,@220")
#pragma comment(linker, "/EXPORT:omap=dbghelpOrg.omap,@221")
#pragma comment(linker, "/EXPORT:optdbgdump=dbghelpOrg.optdbgdump,@222")
#pragma comment(linker, "/EXPORT:optdbgdumpaddr=dbghelpOrg.optdbgdumpaddr,@223")
#pragma comment(linker, "/EXPORT:srcfiles=dbghelpOrg.srcfiles,@224")
#pragma comment(linker, "/EXPORT:stack_force_ebp=dbghelpOrg.stack_force_ebp,@225")
#pragma comment(linker, "/EXPORT:stackdbg=dbghelpOrg.stackdbg,@226")
#pragma comment(linker, "/EXPORT:sym=dbghelpOrg.sym,@227")
#pragma comment(linker, "/EXPORT:symsrv=dbghelpOrg.symsrv,@228")
#pragma comment(linker, "/EXPORT:vc7fpo=dbghelpOrg.vc7fpo,@229")
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
