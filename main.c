#include "defs.h"
#include "Dispatch.h"
ULONG g_ObjTable;

ULONG GetObjTableOffset()
{
    RTL_OSVERSIONINFOW ver = { 0 };
    if (RtlGetVersion(&ver) == STATUS_SUCCESS)
    {
        if (ver.dwBuildNumber < 18363) return 0x418;
        
        return 0x570;
    }
}



VOID BBUnload(IN PDRIVER_OBJECT DriverObject)
{
    UNICODE_STRING deviceLinkUnicodeString;

    RtlUnicodeStringInit(&deviceLinkUnicodeString, L"\\DosDevices\\CE_Bypass");
    IoDeleteSymbolicLink(&deviceLinkUnicodeString);
    IoDeleteDevice(DriverObject->DeviceObject);

    return;
}

NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegistryPath)
{
    NTSTATUS status = STATUS_SUCCESS;
    PDEVICE_OBJECT deviceObject = NULL;
    UNICODE_STRING deviceName;
    UNICODE_STRING deviceLink;

    UNREFERENCED_PARAMETER(RegistryPath);

    g_ObjTable = GetObjTableOffset();

    RtlUnicodeStringInit(&deviceName, L"\\Device\\CE_Bypass");

    status = IoCreateDevice(DriverObject, 0, &deviceName, FILE_DEVICE_UNKNOWN, 0, FALSE, &deviceObject);
    if (!NT_SUCCESS(status))
    {
        //DPRINT("BlackBone: %s: IoCreateDevice failed with status 0x%X\n", __FUNCTION__, status);
        return status;
    }

    DriverObject->MajorFunction[IRP_MJ_CREATE] =
    DriverObject->MajorFunction[IRP_MJ_CLOSE] =
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = BBDispatch;
    DriverObject->DriverUnload = BBUnload;

    RtlUnicodeStringInit(&deviceLink, L"\\DosDevices\\CE_Bypass");

    status = IoCreateSymbolicLink(&deviceLink, &deviceName);

    if (!NT_SUCCESS(status))
    {
        //DPRINT("BlackBone: %s: IoCreateSymbolicLink failed with status 0x%X\n", __FUNCTION__, status);
        IoDeleteDevice(deviceObject);
    }

    return status;
}

