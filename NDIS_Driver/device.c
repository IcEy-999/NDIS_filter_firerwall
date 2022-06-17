

//4

#include "precomp.h"
//#include "IC_Fun_Struct.h"
#pragma NDIS_INIT_FUNCTION(FilterRegisterDevice)
//#include "IC_Fun_Struct.h"

_IRQL_requires_max_(PASSIVE_LEVEL)
NDIS_STATUS
FilterRegisterDevice(
    VOID
    )
{
    //DbgBreakPoint();
    NDIS_STATUS            Status = NDIS_STATUS_SUCCESS;
    UNICODE_STRING         DeviceName;
    UNICODE_STRING         DeviceLinkUnicodeString;
    PDRIVER_DISPATCH       DispatchTable[IRP_MJ_MAXIMUM_FUNCTION+1];
    NDIS_DEVICE_OBJECT_ATTRIBUTES   DeviceAttribute;
    PFILTER_DEVICE_EXTENSION        FilterDeviceExtension;

    DEBUGP(DL_TRACE, "==>FilterRegisterDevice\n");

    NdisZeroMemory(DispatchTable, (IRP_MJ_MAXIMUM_FUNCTION+1) * sizeof(PDRIVER_DISPATCH));

    DispatchTable[IRP_MJ_CREATE] = FilterDispatch;
    DispatchTable[IRP_MJ_CLEANUP] = FilterDispatch;
    DispatchTable[IRP_MJ_CLOSE] = FilterDispatch;
    DispatchTable[IRP_MJ_DEVICE_CONTROL] = FilterDeviceIoControl;


    NdisInitUnicodeString(&DeviceName, NTDEVICE_STRING);
    NdisInitUnicodeString(&DeviceLinkUnicodeString, LINKNAME_STRING);

    //
    // Create a device object and register our dispatch handlers
    //
    NdisZeroMemory(&DeviceAttribute, sizeof(NDIS_DEVICE_OBJECT_ATTRIBUTES));

    DeviceAttribute.Header.Type = NDIS_OBJECT_TYPE_DEVICE_OBJECT_ATTRIBUTES;
    DeviceAttribute.Header.Revision = NDIS_DEVICE_OBJECT_ATTRIBUTES_REVISION_1;
    DeviceAttribute.Header.Size = sizeof(NDIS_DEVICE_OBJECT_ATTRIBUTES);

    DeviceAttribute.DeviceName = &DeviceName;
    DeviceAttribute.SymbolicName = &DeviceLinkUnicodeString;
    DeviceAttribute.MajorFunctions = &DispatchTable[0];
    DeviceAttribute.ExtensionSize = sizeof(FILTER_DEVICE_EXTENSION);

    Status = NdisRegisterDeviceEx(
                FilterDriverHandle,
                &DeviceAttribute,
                &NdisDeviceObject,
                &NdisFilterDeviceHandle
                );


    if (Status == NDIS_STATUS_SUCCESS)
    {
        FilterDeviceExtension = NdisGetDeviceReservedExtension(NdisDeviceObject);

        FilterDeviceExtension->Signature = 'FTDR';
        FilterDeviceExtension->Handle = FilterDriverHandle;
    }


    DEBUGP(DL_TRACE, "<==FilterRegisterDevice: %x\n", Status);

    return (Status);

}

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID
FilterDeregisterDevice(
    VOID
    )

{
    //DbgBreakPoint();
    if (NdisFilterDeviceHandle != NULL)
    {
        NdisDeregisterDeviceEx(NdisFilterDeviceHandle);
    }

    NdisFilterDeviceHandle = NULL;

}

_Use_decl_annotations_
NTSTATUS
FilterDispatch(
    PDEVICE_OBJECT       DeviceObject,
    PIRP                 Irp
    )
{
    PIO_STACK_LOCATION       IrpStack;
    NTSTATUS                 Status = STATUS_SUCCESS;
    //DbgBreakPoint();
    UNREFERENCED_PARAMETER(DeviceObject);

    IrpStack = IoGetCurrentIrpStackLocation(Irp);

    switch (IrpStack->MajorFunction)
    {
        case IRP_MJ_CREATE:
        {   
            break;
        }
        case IRP_MJ_CLEANUP:
            break;

        case IRP_MJ_CLOSE:
            break;

        default:
            break;
    }

    Irp->IoStatus.Status = Status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return Status;
}

_Use_decl_annotations_
NTSTATUS
FilterDeviceIoControl(
    PDEVICE_OBJECT        DeviceObject,
    PIRP                  Irp
    )
{
    PIO_STACK_LOCATION          IrpSp;
    NTSTATUS                    Status = STATUS_SUCCESS;
    PFILTER_DEVICE_EXTENSION    FilterDeviceExtension;
    PUCHAR                      InputBuffer;
    PUCHAR                      OutputBuffer;
    ULONG                       InputBufferLength, OutputBufferLength;
    PLIST_ENTRY                 Link;
    PUCHAR                      pInfo;
    ULONG                       InfoLength = 0;
    PMS_FILTER                  pFilter = NULL;
    BOOLEAN                     bFalse = FALSE;


    UNREFERENCED_PARAMETER(DeviceObject);

    //DbgBreakPoint();

    IrpSp = IoGetCurrentIrpStackLocation(Irp);

    if (IrpSp->FileObject == NULL)
    {
        return(STATUS_UNSUCCESSFUL);
    }


    FilterDeviceExtension = (PFILTER_DEVICE_EXTENSION)NdisGetDeviceReservedExtension(DeviceObject);

    ASSERT(FilterDeviceExtension->Signature == 'FTDR');

    Irp->IoStatus.Information = 0;
    DbgBreakPoint();
    switch (IrpSp->Parameters.DeviceIoControl.IoControlCode)
    {
        

        case IOCTL_FILTER_RESTART_ALL:
        { 
            break; 
        }

        case IOCTL_FILTER_RESTART_ONE_INSTANCE:
        {   InputBuffer = OutputBuffer = (PUCHAR)Irp->AssociatedIrp.SystemBuffer;
            InputBufferLength = IrpSp->Parameters.DeviceIoControl.InputBufferLength;

            pFilter = filterFindFilterModule (InputBuffer, InputBufferLength);

            if (pFilter == NULL)
            {

                break;
            }

            NdisFRestartFilter(pFilter->FilterHandle);

            break;
        }
        case IOCTL_FILTER_ENUMERATE_ALL_INSTANCES:
        {InputBuffer = OutputBuffer = (PUCHAR)Irp->AssociatedIrp.SystemBuffer;
            InputBufferLength = IrpSp->Parameters.DeviceIoControl.InputBufferLength;
            OutputBufferLength = IrpSp->Parameters.DeviceIoControl.OutputBufferLength;


            pInfo = OutputBuffer;

            FILTER_ACQUIRE_LOCK(&FilterListLock, bFalse);

            Link = FilterModuleList.Flink;

            while (Link != &FilterModuleList)
            {
                pFilter = CONTAINING_RECORD(Link, MS_FILTER, FilterModuleLink);


                InfoLength += (pFilter->FilterModuleName.Length + sizeof(USHORT));

                if (InfoLength <= OutputBufferLength)
                {
                    *(PUSHORT)pInfo = pFilter->FilterModuleName.Length;
                    NdisMoveMemory(pInfo + sizeof(USHORT),
                                   (PUCHAR)(pFilter->FilterModuleName.Buffer),
                                   pFilter->FilterModuleName.Length);

                    pInfo += (pFilter->FilterModuleName.Length + sizeof(USHORT));
                }

                Link = Link->Flink;
            }

            FILTER_RELEASE_LOCK(&FilterListLock, bFalse);
            if (InfoLength <= OutputBufferLength)
            {

                Status = NDIS_STATUS_SUCCESS;
            }
            //
            // Buffer is small
            //
            else
            {
                Status = STATUS_BUFFER_TOO_SMALL;
            }
            break;
        }
        case NEW_FC_CODE://新增条件
        {
            if (FC_list.num >= 10)
                break;
            PFilter_Condition PFC = (PFilter_Condition)ExAllocatePool(NonPagedPool, sizeof(Filter_Condition));//申请存放的空间
            if (PFC == NULL)
            {
                DbgPrint("PFC分配内存失败\n");
                break;
            }
    
            memcpy(PFC, Irp->AssociatedIrp.SystemBuffer, sizeof(Filter_Condition));//读入数据
            Irp->IoStatus.Information = sizeof(Filter_Condition);
            if (FC_list.head == NULL)
                FC_list.head = FC_list.last = PFC;
            else
            {
                FC_list.last->next = PFC;
                PFC->prior = FC_list.last;
                FC_list.last = PFC;
                FC_list.last->next = NULL;
            }
            FC_list.num++;
            break;
        }
        case DEL_FC_CODE://删除条件
        {
            int fflag = -1;
            memcpy(&fflag, Irp->AssociatedIrp.SystemBuffer, sizeof(int));//读入数据
            PFilter_Condition ls = FC_list.head;
            do {
                if (ls->flag == fflag)
                {
                    if (ls->prior == NULL)//链表第一个
                    {
                        if (FC_list.num == 1)//链表只有一个
                        {
                            ExFreePool(FC_list.head);
                            FC_list.last = FC_list.head = NULL;
                            FC_list.num--;
                            break;
                        }
                        //不是只有一个
                        FC_list.head = ls->next;
                        ExFreePool(ls);
                        FC_list.num--;
                        break;
                    }
                    //不是第一个
                    PFilter_Condition lss = ls->prior;
                    lss->next = ls->next;
                    if (ls->next != NULL)//是不是最后一个
                        ls->next->prior = lss;
                    ExFreePool(ls);
                    FC_list.num--;
                    break;
                }
                ls = ls->next;
            } while (ls != NULL);
            break;
        }
        case START_FC_CODE://开启
        {
            start_flag = 1;
            break;
        }
        case STOP_FC_CODE://暂停
        {
            start_flag = 0;
            break;
        }
        default:
            break;
    }

    Irp->IoStatus.Status = Status;
    Irp->IoStatus.Information = InfoLength;

    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return Status;


}


_IRQL_requires_max_(DISPATCH_LEVEL)
PMS_FILTER
filterFindFilterModule(
    _In_reads_bytes_(BufferLength)
         PUCHAR                   Buffer,
    _In_ ULONG                    BufferLength
    )
{
   //DbgBreakPoint();
   PMS_FILTER              pFilter;
   PLIST_ENTRY             Link;
   BOOLEAN                  bFalse = FALSE;

   FILTER_ACQUIRE_LOCK(&FilterListLock, bFalse);

   Link = FilterModuleList.Flink;

   while (Link != &FilterModuleList)
   {
       pFilter = CONTAINING_RECORD(Link, MS_FILTER, FilterModuleLink);

       if (BufferLength >= pFilter->FilterModuleName.Length)
       {
           if (NdisEqualMemory(Buffer, pFilter->FilterModuleName.Buffer, pFilter->FilterModuleName.Length))
           {
               FILTER_RELEASE_LOCK(&FilterListLock, bFalse);
               return pFilter;
           }
       }

       Link = Link->Flink;
   }

   FILTER_RELEASE_LOCK(&FilterListLock, bFalse);
   return NULL;
}




