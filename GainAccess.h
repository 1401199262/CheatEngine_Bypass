#pragma once


/// <summary>
/// Input for IOCTL_BLACKBONE_GRANT_ACCESS
/// </summary>
typedef struct _HANDLE_GRANT_ACCESS
{
    ULONGLONG  handle;      // Handle to modify
    ULONG      pid;         // Process ID
    ULONG      access;      // Access flags to grant
} HANDLE_GRANT_ACCESS, * PHANDLE_GRANT_ACCESS;

typedef struct _HANDLE_TABLE
{
    ULONG NextHandleNeedingPool;
    long ExtraInfoPages;
    LONG_PTR TableCode;
    PEPROCESS QuotaProcess;
    LIST_ENTRY HandleTableList;
    ULONG UniqueProcessId;
    ULONG Flags;
    EX_PUSH_LOCK HandleContentionEvent;
    EX_PUSH_LOCK HandleTableLock;
    // More fields here...
} HANDLE_TABLE, * PHANDLE_TABLE;


typedef union _EXHANDLE
{
    struct
    {
        int TagBits : 2;
        int Index : 30;
    } u;
    void* GenericHandleOverlay;
    ULONG_PTR Value;
} EXHANDLE, * PEXHANDLE;

typedef struct _HANDLE_TABLE_ENTRY // Size=16
{
    union
    {
        ULONG_PTR VolatileLowValue; // Size=8 Offset=0
        ULONG_PTR LowValue; // Size=8 Offset=0
        struct _HANDLE_TABLE_ENTRY_INFO* InfoTable; // Size=8 Offset=0
        struct
        {
            ULONG_PTR Unlocked : 1; // Size=8 Offset=0 BitOffset=0 BitCount=1
            ULONG_PTR RefCnt : 16; // Size=8 Offset=0 BitOffset=1 BitCount=16
            ULONG_PTR Attributes : 3; // Size=8 Offset=0 BitOffset=17 BitCount=3
            ULONG_PTR ObjectPointerBits : 44; // Size=8 Offset=0 BitOffset=20 BitCount=44
        };
    };
    union
    {
        ULONG_PTR HighValue; // Size=8 Offset=8
        struct _HANDLE_TABLE_ENTRY* NextFreeHandleEntry; // Size=8 Offset=8
        union _EXHANDLE LeafHandleValue; // Size=8 Offset=8
        struct
        {
            ULONG GrantedAccessBits : 25; // Size=4 Offset=8 BitOffset=0 BitCount=25
            ULONG NoRightsUpgrade : 1; // Size=4 Offset=8 BitOffset=25 BitCount=1
            ULONG Spare : 6; // Size=4 Offset=8 BitOffset=26 BitCount=6
        };
    };
    ULONG TypeInfo; // Size=4 Offset=12
} HANDLE_TABLE_ENTRY, * PHANDLE_TABLE_ENTRY;

typedef BOOLEAN(*EX_ENUMERATE_HANDLE_ROUTINE)(
#if !defined(_WIN7_)
    IN PHANDLE_TABLE HandleTable,
#endif
    IN PHANDLE_TABLE_ENTRY HandleTableEntry,
    IN HANDLE Handle,
    IN PVOID EnumParameter
    );

NTKERNELAPI
VOID
FASTCALL
ExfUnblockPushLock(
    IN OUT PEX_PUSH_LOCK PushLock,
    IN OUT PVOID WaitBlock
);

NTKERNELAPI
BOOLEAN
ExEnumHandleTable(
    IN PHANDLE_TABLE HandleTable,
    IN EX_ENUMERATE_HANDLE_ROUTINE EnumHandleProcedure,
    IN PVOID EnumParameter,
    OUT PHANDLE Handle
);

#define EX_ADDITIONAL_INFO_SIGNATURE (ULONG_PTR)(-2)

#define ExpIsValidObjectEntry(Entry) \
    ( (Entry != NULL) && (Entry->LowValue != 0) && (Entry->HighValue != EX_ADDITIONAL_INFO_SIGNATURE) )

NTSTATUS BBGrantAccess(IN PHANDLE_GRANT_ACCESS pAccess);

extern ULONG g_ObjTable;
