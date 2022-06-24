#include "defs.h"
#include "GainAccess.h"

/// <summary>
/// Handle enumeration callback
/// </summary>
/// <param name="HandleTable">Process handle table</param>
/// <param name="HandleTableEntry">Handle entry</param>
/// <param name="Handle">Handle value</param>
/// <param name="EnumParameter">User context</param>
/// <returns>TRUE when desired handle is found</returns>
BOOLEAN BBHandleCallback(
#if !defined(_WIN7_)
    IN PHANDLE_TABLE HandleTable,
#endif
    IN PHANDLE_TABLE_ENTRY HandleTableEntry,
    IN HANDLE Handle,
    IN PVOID EnumParameter
)
{

    BOOLEAN result = FALSE;
    ASSERT(EnumParameter);

    if (EnumParameter != NULL)
    {
        PHANDLE_GRANT_ACCESS pAccess = (PHANDLE_GRANT_ACCESS)EnumParameter;
        if (Handle == (HANDLE)pAccess->handle)
        {
            if (ExpIsValidObjectEntry(HandleTableEntry))
            {
                // Update access
                HandleTableEntry->GrantedAccessBits = pAccess->access;
                result = TRUE;
            }
            //else
            //    DPRINT("BlackBone: %s: 0x%X:0x%X handle is invalid\n. HandleEntry = 0x%p",
            //        __FUNCTION__, pAccess->pid, pAccess->handle, HandleTableEntry
            //    );
        }
    }

#if !defined(_WIN7_)
    // Release implicit locks
    _InterlockedExchangeAdd8((char*)&HandleTableEntry->VolatileLowValue, 1);  // Set Unlocked flag to 1
    if (HandleTable != NULL && HandleTable->HandleContentionEvent)
        ExfUnblockPushLock(&HandleTable->HandleContentionEvent, NULL);
#endif

    return result;
}

/// <summary>
/// Change handle granted access
/// </summary>
/// <param name="pAccess">Request params</param>
/// <returns>Status code</returns>
NTSTATUS BBGrantAccess(IN PHANDLE_GRANT_ACCESS pAccess)
{
    //DPRINT("Raise Access of process: id = %d\n", pAccess->pid);

    NTSTATUS status = STATUS_SUCCESS;
    PEPROCESS pProcess = NULL;

    // Validate dynamic offset
    if (g_ObjTable == 0)
    {
        //DPRINT("BlackBone: %s: Invalid ObjTable address\n", __FUNCTION__);
        return STATUS_INVALID_ADDRESS;
    }

    status = PsLookupProcessByProcessId((HANDLE)pAccess->pid, &pProcess);

    if (NT_SUCCESS(status))
    {
        PHANDLE_TABLE pTable = *(PHANDLE_TABLE*)((PUCHAR)pProcess + g_ObjTable);
        BOOLEAN found = ExEnumHandleTable(pTable, &BBHandleCallback, pAccess, NULL);
        if (found == FALSE)
            status = STATUS_NOT_FOUND;
    }
    else
        //DPRINT("BlackBone: %s: PsLookupProcessByProcessId failed with status 0x%X\n", __FUNCTION__, status);

    if (pProcess)
        ObDereferenceObject(pProcess);

    return status;
}