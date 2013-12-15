/*++
 *
 * The file contains the routines to create a device and handle ioctls
 *
-- */

#include "precomp.h"
#include "structures.h"

#pragma NDIS_INIT_FUNCTION(NDISFilterDriverRegisterDevice)

VOID AddIPv4Rule(IN PFILTER_DEVICE_EXTENSION FilterDeviceExtension, IN PRULE_IPV4 Rule);
VOID DelIPv4Rule(IN PFILTER_DEVICE_EXTENSION FilterDeviceExtension, IN ULONG Id);
VOID AddIPv6Rule(IN PFILTER_DEVICE_EXTENSION FilterDeviceExtension, IN PRULE_IPV6 Rule);
VOID DelIPv6Rule(IN PFILTER_DEVICE_EXTENSION FilterDeviceExtension, IN ULONG Id);
VOID ActivateRules(IN PFILTER_DEVICE_EXTENSION FilterDeviceExtension);
VOID DeactivateRules(IN PFILTER_DEVICE_EXTENSION FilterDeviceExtension);

_IRQL_requires_max_(PASSIVE_LEVEL)
NDIS_STATUS
NDISFilterDriverRegisterDevice(OUT PFILTER_DEVICE_EXTENSION *Extension)
{
    NDIS_STATUS            Status = NDIS_STATUS_SUCCESS;
    UNICODE_STRING         DeviceName;
    UNICODE_STRING         DeviceLinkUnicodeString;
    PDRIVER_DISPATCH       DispatchTable[IRP_MJ_MAXIMUM_FUNCTION+1];
    NDIS_DEVICE_OBJECT_ATTRIBUTES   DeviceAttribute;
    PFILTER_DEVICE_EXTENSION        FilterDeviceExtension;
    PDRIVER_OBJECT                  DriverObject;
   
    DEBUGP(DL_TRACE, "==>NDISFilterDriverRegisterDevice\n");
   
    
    NdisZeroMemory(DispatchTable, (IRP_MJ_MAXIMUM_FUNCTION+1) * sizeof(PDRIVER_DISPATCH));
    
    DispatchTable[IRP_MJ_CREATE] = NDISFilterDriverDispatch;
    DispatchTable[IRP_MJ_CLEANUP] = NDISFilterDriverDispatch;
    DispatchTable[IRP_MJ_CLOSE] = NDISFilterDriverDispatch;
    DispatchTable[IRP_MJ_DEVICE_CONTROL] = NDISFilterDriverDeviceIoControl;
    
    
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
                &DeviceObject,
                &NdisFilterDeviceHandle
                );
   
   
    if (Status == NDIS_STATUS_SUCCESS)
    {
		*Extension = FilterDeviceExtension = NdisGetDeviceReservedExtension(DeviceObject);
   
        FilterDeviceExtension->Signature = 'FTDR';
        FilterDeviceExtension->Handle = FilterDriverHandle;
		PRULES_LISTS FilterRules = ExAllocatePool(PagedPool, sizeof(RULES_LISTS));
		FilterRules->IsActive = FALSE;
		FilterRules->FirstRuleIPv4 = NULL;
		FilterRules->FirstRuleIPv6 = NULL;
		FilterDeviceExtension->FilterRules = FilterRules;

        //
        // Workaround NDIS bug
        //
        DriverObject = (PDRIVER_OBJECT)FilterDriverObject;
    }
              
        
    DEBUGP(DL_TRACE, "<==NDISFilterDriverRegisterDevice: %x\n", Status);
        
    return (Status);
        
}

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID
NDISFilterDriverDeregisterDevice(
    VOID
    )

{
    if (NdisFilterDeviceHandle != NULL)
    {
        NdisDeregisterDeviceEx(NdisFilterDeviceHandle);
    }

    NdisFilterDeviceHandle = NULL;

}

_Use_decl_annotations_
NTSTATUS
NDISFilterDriverDispatch(
    PDEVICE_OBJECT       DeviceObject,
    PIRP                 Irp
    )
{
    PIO_STACK_LOCATION       IrpStack;
    NTSTATUS                 Status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(DeviceObject);

    IrpStack = IoGetCurrentIrpStackLocation(Irp);
    
    switch (IrpStack->MajorFunction)
    {
        case IRP_MJ_CREATE:
            break;

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
NDISFilterDriverDeviceIoControl(
    PDEVICE_OBJECT        DeviceObject,
    PIRP                  Irp
    )
{
	DbgPrint("NDISFilterDriverDeviceIoControl\n");
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


    IrpSp = IoGetCurrentIrpStackLocation(Irp);

    if (IrpSp->FileObject == NULL)
    {
        return(STATUS_UNSUCCESSFUL);
    }


    FilterDeviceExtension = (PFILTER_DEVICE_EXTENSION)NdisGetDeviceReservedExtension(DeviceObject);

    ASSERT(FilterDeviceExtension->Signature == 'FTDR');
    
    Irp->IoStatus.Information = 0;

    switch (IrpSp->Parameters.DeviceIoControl.IoControlCode)
    {
		case IOCTL_ADD_IPV4_RULE:
			DbgPrint("IOCTL_ADD_IPV4_RULE BEGIN\n");
			InputBuffer = Irp->UserBuffer;
			InputBufferLength = IrpSp->Parameters.DeviceIoControl.InputBufferLength;
			if (InputBufferLength != sizeof(RULE_IPV4))
			{
				Status = NDIS_STATUS_FAILURE;
				break;
			}
			PRULE_IPV4 pRuleIPv4 = ExAllocatePool(NonPagedPool, sizeof(RULE_IPV4));
			RtlCopyMemory(pRuleIPv4, InputBuffer, InputBufferLength);
			AddIPv4Rule(FilterDeviceExtension, pRuleIPv4);
			DbgPrint("IOCTL_ADD_IPV4_RULE END\n");
			break;
		case IOCTL_DEL_IPV4_RULE:
			DbgPrint("IOCTL_DEL_IPV4_RULE BEGIN\n");
			InputBuffer = Irp->UserBuffer;
			InputBufferLength = IrpSp->Parameters.DeviceIoControl.InputBufferLength;
			if (InputBufferLength != sizeof(ULONG))
			{
				Status = NDIS_STATUS_FAILURE;
				break;
			}
			ULONG IdIPv4 = *((PULONG)(InputBuffer));
			DelIPv4Rule(FilterDeviceExtension, IdIPv4);
			DbgPrint("IOCTL_DEL_IPV4_RULE END\n");
			break;
		case IOCTL_ADD_IPV6_RULE:
			DbgPrint("IOCTL_ADD_IPV6_RULE BEGIN\n");
			InputBuffer = Irp->UserBuffer;
			InputBufferLength = IrpSp->Parameters.DeviceIoControl.InputBufferLength;
			if (InputBufferLength != sizeof(RULE_IPV6))
			{
				Status = NDIS_STATUS_FAILURE;
				break;
			}
			PRULE_IPV6 pRuleIPv6 = ExAllocatePool(NonPagedPool, sizeof(RULE_IPV6));
			RtlCopyMemory(pRuleIPv6, InputBuffer, InputBufferLength);
			AddIPv6Rule(FilterDeviceExtension, pRuleIPv6);
			DbgPrint("IOCTL_ADD_IPV6_RULE END\n");
			break;
		case IOCTL_DEL_IPV6_RULE:
			DbgPrint("IOCTL_DEL_IPV6_RULE BEGIN\n");
			InputBuffer = Irp->UserBuffer;
			InputBufferLength = IrpSp->Parameters.DeviceIoControl.InputBufferLength;
			if (InputBufferLength != sizeof(ULONG))
			{
				Status = NDIS_STATUS_FAILURE;
				break;
			}
			ULONG IdIPv6 = *((PULONG)(InputBuffer));
			DelIPv6Rule(FilterDeviceExtension, IdIPv6);
			DbgPrint("IOCTL_END_IPV6_RULE END\n");
			break;
		case IOCTL_ACTIVATE_FILTER:
			DbgPrint("IOCTL_ACTIVATE_FILTER BEGIN\n");
			InputBuffer = Irp->UserBuffer;
			InputBufferLength = IrpSp->Parameters.DeviceIoControl.InputBufferLength;
			if (InputBufferLength != 0)
			{
				Status = NDIS_STATUS_FAILURE;
				break;
			}
			ActivateRules(FilterDeviceExtension);
			DbgPrint("IOCTL_ACTIVATE_FILTER END\n");
			break;
		case IOCTL_DEACTIVATE_FILTER:
			DbgPrint("IOCTL_DEACTIVATE_FILTER BEGIN\n");
			InputBuffer = Irp->UserBuffer;
			InputBufferLength = IrpSp->Parameters.DeviceIoControl.InputBufferLength;
			if (InputBufferLength != 0)
			{
				Status = NDIS_STATUS_FAILURE;
				break;
			}
			DeactivateRules(FilterDeviceExtension);
			DbgPrint("IOCTL_DEACTIVATE_FILTER END\n");
			break;
        case IOCTL_FILTER_RESTART_ALL:
            break;

        case IOCTL_FILTER_RESTART_ONE_INSTANCE:
            InputBuffer = OutputBuffer = (PUCHAR)Irp->AssociatedIrp.SystemBuffer;
            InputBufferLength = IrpSp->Parameters.DeviceIoControl.InputBufferLength;

            pFilter = filterFindFilterModule (InputBuffer, InputBufferLength);

            if (pFilter == NULL)
            {
                
                break;
            }

            NdisFRestartFilter(pFilter->FilterHandle);

            break;

        case IOCTL_FILTER_ENUERATE_ALL_INSTANCES:
            
            InputBuffer = OutputBuffer = (PUCHAR)Irp->AssociatedIrp.SystemBuffer;
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

VOID AddIPv4Rule(IN PFILTER_DEVICE_EXTENSION FilterDeviceExtension, IN PRULE_IPV4 Rule)
{
	DbgPrint("AddIPv4Rule\n");
	DbgPrint("Id: %lu Begin:%d.%d.%d.%d End:%d.%d.%d.%d\n",
		Rule->Id,
		Rule->Begin[0],
		Rule->Begin[1],
		Rule->Begin[2],
		Rule->Begin[3],
		Rule->End[0],
		Rule->End[1],
		Rule->End[2],
		Rule->End[3]);
	PRULES_LISTS RulesLists = FilterDeviceExtension->FilterRules;
	PRULE_IPV4 List = RulesLists->FirstRuleIPv4;
	Rule->Next = List;
	RulesLists->FirstRuleIPv4 = Rule;
}

VOID DelIPv4Rule(IN PFILTER_DEVICE_EXTENSION FilterDeviceExtension, IN ULONG Id)
{
	DbgPrint("DelIPv4Rule\n");
	DbgPrint("Id: %lu\n",Id);
	PRULES_LISTS RulesLists = FilterDeviceExtension->FilterRules;
	PRULE_IPV4 CurrentRule = RulesLists->FirstRuleIPv4;

	if (CurrentRule != NULL && CurrentRule->Id == Id)
	{
		RulesLists->FirstRuleIPv4 = CurrentRule->Next;
		ExFreePool(CurrentRule);
		return;
	}

	PRULE_IPV4 PreviousRule = CurrentRule;
	CurrentRule = CurrentRule->Next;

	while (CurrentRule != NULL)
	{
		if (CurrentRule->Id == Id)
		{
			PreviousRule->Next = CurrentRule->Next;
			ExFreePool(CurrentRule);
		}
	}
}

VOID AddIPv6Rule(IN PFILTER_DEVICE_EXTENSION FilterDeviceExtension, IN PRULE_IPV6 Rule)
{
	PRULES_LISTS RulesLists = FilterDeviceExtension->FilterRules;
	PRULE_IPV6 List = RulesLists->FirstRuleIPv6;
	Rule->Next = List;
	RulesLists->FirstRuleIPv6 = Rule;
}

VOID DelIPv6Rule(IN PFILTER_DEVICE_EXTENSION FilterDeviceExtension, IN ULONG Id)
{
	PRULES_LISTS RulesLists = FilterDeviceExtension->FilterRules;
	PRULE_IPV6 CurrentRule = RulesLists->FirstRuleIPv6;

	if (CurrentRule != NULL && CurrentRule->Id == Id)
	{
		RulesLists->FirstRuleIPv6 = CurrentRule->Next;
		ExFreePool(CurrentRule);
		return;
	}

	PRULE_IPV6 PreviousRule = CurrentRule;
	CurrentRule = CurrentRule->Next;

	while (CurrentRule != NULL)
	{
		if (CurrentRule->Id == Id)
		{
			PreviousRule->Next = CurrentRule->Next;
			ExFreePool(CurrentRule);
		}
	}
}

VOID ActivateRules(IN PFILTER_DEVICE_EXTENSION FilterDeviceExtension)
{
	PRULES_LISTS RulesLists = FilterDeviceExtension->FilterRules;
	RulesLists->IsActive = TRUE;
}

VOID DeactivateRules(IN PFILTER_DEVICE_EXTENSION FilterDeviceExtension)
{
	PRULES_LISTS RulesLists = FilterDeviceExtension->FilterRules;
	RulesLists->IsActive = FALSE;
}

