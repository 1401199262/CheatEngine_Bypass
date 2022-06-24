#include "defs.h"
#include "Dispatch.h"
#include "GainAccess.h"

/// <summary>
/// CTL dispatcher
/// </summary>
/// <param name="DeviceObject">Device object</param>
/// <param name="Irp">IRP</param>
/// <returns>Status code</returns>
NTSTATUS BBDispatch(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    NTSTATUS status = STATUS_SUCCESS;
    PIO_STACK_LOCATION irpStack;
    PVOID ioBuffer = NULL;
    ULONG inputBufferLength = 0;
    ULONG outputBufferLength = 0;
    ULONG ioControlCode = 0;

    UNREFERENCED_PARAMETER(DeviceObject);

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;

    irpStack = IoGetCurrentIrpStackLocation(Irp);
    ioBuffer = Irp->AssociatedIrp.SystemBuffer;
    inputBufferLength = irpStack->Parameters.DeviceIoControl.InputBufferLength;
    outputBufferLength = irpStack->Parameters.DeviceIoControl.OutputBufferLength;
    
    switch (irpStack->MajorFunction)
    {
        case IRP_MJ_DEVICE_CONTROL:
        {
            ioControlCode = irpStack->Parameters.DeviceIoControl.IoControlCode;

            switch (ioControlCode)
            {
                case IOCTL_BLACKBONE_GRANT_ACCESS:
                {
                    if (inputBufferLength >= sizeof(HANDLE_GRANT_ACCESS) && ioBuffer)
                        Irp->IoStatus.Status = BBGrantAccess((PHANDLE_GRANT_ACCESS)ioBuffer);
                    else
                        Irp->IoStatus.Status = STATUS_INFO_LENGTH_MISMATCH;
                }
                break;

                default:
                    //DPRINT("BlackBone: %s: Unknown IRP_MJ_DEVICE_CONTROL 0x%X\n", __FUNCTION__, ioControlCode);
                    Irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
                    break;
            }
            
        }
        break;
    }

    status = Irp->IoStatus.Status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

