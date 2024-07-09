#include "minifilters.h"

BOOL DcmbValidatePotentialCallbackNodes(PCALLBACK_NODE PotentialCallbackNode, PFLT_INSTANCE FltInstance, DWORD64 DriverStartAddr, DWORD64 DriverSize) {
	if (PotentialCallbackNode->Instance != FltInstance) return FALSE;
	if (PotentialCallbackNode->PreOperation) {
		if (!((DWORD64)PotentialCallbackNode->PreOperation > DriverStartAddr && (DWORD64)PotentialCallbackNode->PreOperation < (DriverStartAddr + DriverSize))) {
			return FALSE;
		}
	}
	if (PotentialCallbackNode->PostOperation) {
		if (!((DWORD64)PotentialCallbackNode->PostOperation > DriverStartAddr && (DWORD64)PotentialCallbackNode->PostOperation < (DriverStartAddr + DriverSize))) {
			return FALSE;
		}
	}

	if (!PotentialCallbackNode->PreOperation && !PotentialCallbackNode->PostOperation) return FALSE;

	return TRUE;
	/* take the range of the driver instead of enumerating the driver every validation
	return ((PotentialCallbackNode->Instance == FltInstance) &&
		(DWORD64)PotentialCallbackNode->PreOperation > DriverStartAddr &&
		(DWORD64)PotentialCallbackNode->PreOperation < (DriverStartAddr + DriverSize) &&
		(DWORD64)PotentialCallbackNode->PostOperation > DriverStartAddr &&
		(DWORD64)PotentialCallbackNode->PostOperation < (DriverStartAddr + DriverSize));*/
}

BOOL DcmbReadMemorySafe(PVOID TargetAddress, PVOID AllocatedBuffer, SIZE_T LengthToRead) {
	PHYSICAL_ADDRESS PhysicalAddr = MmGetPhysicalAddress(TargetAddress);
	if (PhysicalAddr.QuadPart) {
		PVOID NewVirtualAddr = MmMapIoSpace(PhysicalAddr, LengthToRead, MmNonCached);
		if (NewVirtualAddr) {
			for (SIZE_T i = 0; i < LengthToRead; i++) {
				*(PBYTE)((DWORD64)AllocatedBuffer + i) = *(PBYTE)((DWORD64)NewVirtualAddr + i);
			}
			MmUnmapIoSpace(NewVirtualAddr, LengthToRead);
			return TRUE;
		}
	}
	return FALSE;
}

BOOL DcmbEnumFilterInstances(PFLT_FILTER TargetFilter, PFLT_INSTANCE** InstanceListOutput, PULONG InstanceCount) {
	NTSTATUS result = STATUS_UNSUCCESSFUL;
	BOOL output = FALSE;
	PFLT_INSTANCE* InstanceListBuffer = NULL;
	ULONG NumberOfInstanceReturned = 0;
	ULONG InstanceListBufferSize = 0;

	result = FltEnumerateInstances(NULL, TargetFilter, InstanceListBuffer, InstanceListBufferSize, &NumberOfInstanceReturned);
	if (result != STATUS_BUFFER_TOO_SMALL) {
		return output; // FltEnumerateInstances result is unexpected
	}

	while (result == STATUS_BUFFER_TOO_SMALL) {
		InstanceListBufferSize += 0x1000;
		InstanceListBuffer = (PFLT_INSTANCE*)ExAllocatePool(NonPagedPoolNx, InstanceListBufferSize);
		if (!InstanceListBuffer)
			return output;

		result = FltEnumerateInstances(NULL, TargetFilter, InstanceListBuffer, InstanceListBufferSize, &NumberOfInstanceReturned);
		if (!NT_SUCCESS(result)) {
			ExFreePool((PVOID)InstanceListBuffer);
			InstanceListBuffer = NULL;
		}
		else {
			output = TRUE;
		}
	}

	*InstanceListOutput = InstanceListBuffer;
	*InstanceCount = NumberOfInstanceReturned;

	return output;
}

BOOL DcmbEnumerateFilters() {
	NTSTATUS result = STATUS_UNSUCCESSFUL;
	BOOL output = FALSE;
	PFLT_FILTER* FilterListBuffer = NULL;
	ULONG NumberOfFiltersReturned = 0;
	ULONG FilterListBufferSize = 0;
	WCHAR FilterNameBuffer[256] = { 0 };
	WCHAR FilterAltitudeBuffer[256] = { 0 };

	result = FltEnumerateFilters(FilterListBuffer, FilterListBufferSize, &NumberOfFiltersReturned);
	if (result != STATUS_BUFFER_TOO_SMALL) {
		return output; // result is not expected
	}

	while (result == STATUS_BUFFER_TOO_SMALL) {
		FilterListBufferSize += 0x1000;
		FilterListBuffer = (PFLT_FILTER*)ExAllocatePool(NonPagedPoolNx, FilterListBufferSize);
		if (!FilterListBuffer)
			return output;

		result = FltEnumerateFilters(FilterListBuffer, FilterListBufferSize, &NumberOfFiltersReturned);
		if (!NT_SUCCESS(result)) {
			ExFreePool((PVOID)FilterListBuffer);
			FilterListBuffer = NULL;
		}
	}

	if (!NT_SUCCESS(result))
		return output;


	// get the filters info
	for (ULONG i = 0; i < NumberOfFiltersReturned; i++) {
		PFLT_FILTER CurrentFilter = *(PFLT_FILTER*)((DWORD64)FilterListBuffer + (i * sizeof(PFLT_FILTER)));
		PFILTER_AGGREGATE_BASIC_INFORMATION FilterBasicInfoBuffer = NULL;
		ULONG FilterBasicInfoReturnedSize = 0;
		ULONG FilterBasicInfoSize = 0;
		PFLT_INSTANCE* InstanceListBase = NULL;
		ULONG InstanceCount = 0;

		result = FltGetFilterInformation(CurrentFilter, FilterAggregateBasicInformation, FilterBasicInfoBuffer, FilterBasicInfoSize, &FilterBasicInfoReturnedSize);
		if (result != STATUS_BUFFER_TOO_SMALL) {
			continue;
		}

		while (result == STATUS_BUFFER_TOO_SMALL) {
			FilterBasicInfoSize += 0x1000;
			FilterBasicInfoBuffer = (PFILTER_AGGREGATE_BASIC_INFORMATION)ExAllocatePool(NonPagedPoolNx, FilterBasicInfoSize);
			if (!FilterBasicInfoBuffer)
				break;

			result = FltGetFilterInformation(CurrentFilter, FilterAggregateBasicInformation, FilterBasicInfoBuffer, FilterBasicInfoSize, &FilterBasicInfoReturnedSize);
			if (!NT_SUCCESS(result)) {
				ExFreePool((PVOID)FilterBasicInfoBuffer);
				FilterBasicInfoBuffer = NULL;
			}
		}

		if (!NT_SUCCESS(result))
			continue;

		PWCHAR FilterNameAddr = (PWCHAR)((DWORD64)FilterBasicInfoBuffer + FilterBasicInfoBuffer->Type.MiniFilter.FilterNameBufferOffset);
		PWCHAR FilterAltitudeAddr = (PWCHAR)((DWORD64)FilterBasicInfoBuffer + FilterBasicInfoBuffer->Type.MiniFilter.FilterAltitudeBufferOffset);

		if (FilterBasicInfoBuffer->Type.MiniFilter.FilterNameLength < 256)
			memcpy(FilterNameBuffer, FilterNameAddr, FilterBasicInfoBuffer->Type.MiniFilter.FilterNameLength);
		else {
			memcpy(FilterNameBuffer, FilterNameAddr, 252 * sizeof(WCHAR));
			memcpy(FilterNameBuffer + 252, L"...", 3 * sizeof(WCHAR));
		}

		memcpy(FilterAltitudeBuffer, FilterAltitudeAddr, FilterBasicInfoBuffer->Type.MiniFilter.FilterAltitudeLength);

		// prints filter name
		DbgPrintEx(0, 0, "[DCMB] Found minifilter %ws with altitude %ws!\n", FilterNameBuffer, FilterAltitudeBuffer);

		// free filter basic info pool
		ExFreePool((PVOID)FilterBasicInfoBuffer);

		// null filter name buffer and filter altitude buffer
		memset(FilterNameBuffer, 0x00, 256 * sizeof(WCHAR));
		memset(FilterAltitudeBuffer, 0x00, 256 * sizeof(WCHAR));

		// enum filter instances
		if (!DcmbEnumFilterInstances(CurrentFilter, &InstanceListBase, &InstanceCount)) continue;

		// enum callbacks
		if (!DcmbEnumInstancesCallbacks(InstanceListBase, InstanceCount, FALSE)) {
			ExFreePool(InstanceListBase);
			continue;
		}
		else continue;
	}

	// free filter list pool
	ExFreePool((PVOID)FilterListBuffer);

	return output;
}

BOOL DcmbEnumInstancesCallbacks(PFLT_INSTANCE* InstanceListBase, ULONG InstanceCount, BOOL Verbose) {
	BOOL output = TRUE;
	PRTL_PROCESS_MODULES ModuleInformation = NULL;
	NTSTATUS result;
	ULONG SizeNeeded;
	SIZE_T InfoRegionSize;
	PROTOTYPE_ZWQUERYSYSTEMINFORMATION ZwQuerySystemInformation;
	UNICODE_STRING ZWQSIName;
	int PreOpsCallbackCount = 0;
	int PostOpsCallbackCount = 0;

	RtlInitUnicodeString(&ZWQSIName, L"ZwQuerySystemInformation");
	ZwQuerySystemInformation = (PROTOTYPE_ZWQUERYSYSTEMINFORMATION)MmGetSystemRoutineAddress(&ZWQSIName);

	// get system module info size
	result = ZwQuerySystemInformation(0x0B, NULL, 0, &SizeNeeded);
	if (result != 0xC0000004) {
		return output;
	}
	InfoRegionSize = SizeNeeded;

	// get system module info
	while (result == 0xC0000004) {
		InfoRegionSize += 0x1000;
		ModuleInformation = (PRTL_PROCESS_MODULES)ExAllocatePool(NonPagedPoolNx, InfoRegionSize);
		if (ModuleInformation == NULL) {
			return output;
		}

		result = ZwQuerySystemInformation(0x0B, (PVOID)ModuleInformation, (ULONG)InfoRegionSize, &SizeNeeded);
		if (!NT_SUCCESS(result)) {
			ExFreePool((PVOID)ModuleInformation);
			ModuleInformation = NULL;
		}
	}

	if (!NT_SUCCESS(result)) {
		return output;
	}

	// go through the instances
	for (ULONG i = 0; i < InstanceCount; i++) {
		PCALLBACK_NODE TargetCallbackNode = NULL;
		PFLT_INSTANCE CurrentInstance = *(PFLT_INSTANCE*)((DWORD64)InstanceListBase + (i * sizeof(PFLT_INSTANCE)));

		//fpDbgPrintEx(0, 0, "Checking instance %i...", i);

		// copy instance memory
		PFLT_INSTANCE CurrentInstanceVA = ExAllocatePool(NonPagedPoolNx, 0x230);
		if (!DcmbReadMemorySafe((PVOID)CurrentInstance, (PVOID)CurrentInstanceVA, 0x230)) {
			ExFreePool((PVOID)CurrentInstanceVA);
			break;
		}

		// scan for our callback node
		for (DWORD x = 0; x < 0x230; x++) {
			DWORD64 PotentialPointer = *(PDWORD64)((DWORD64)CurrentInstanceVA + x);
			PCALLBACK_NODE PotentialNode = (PCALLBACK_NODE)PotentialPointer;

			if (MmIsAddressValid((PVOID)PotentialPointer)) {
				try {
					for (DWORD i = 0; i < ModuleInformation->NumberOfModules; i++) {
						// check if callback address falls into the memmory range of the driver 
						if (DcmbValidatePotentialCallbackNodes(PotentialNode,
							CurrentInstance, (DWORD64)ModuleInformation->Modules[i].ImageBase,
							ModuleInformation->Modules[i].ImageSize)) {
							TargetCallbackNode = PotentialNode;

							//DbgPrintEx(0, 0, "   Instance : 0x%p, TargetCallbackNode : 0x%p\n", CurrentInstance, TargetCallbackNode);

							if (TargetCallbackNode->PreOperation) {
								PreOpsCallbackCount++;

								if (Verbose) DbgPrintEx(0, 0, "   [DCMB] Found minifilter pre-operation callback : %s+0x%x = 0x%p\n",
									DcmbGetBaseNameFromFullName(ModuleInformation->Modules[i].FullPathName),
									(DWORD64)TargetCallbackNode->PreOperation - (DWORD64)ModuleInformation->Modules[i].ImageBase,
									TargetCallbackNode->PreOperation);
							}

							if (TargetCallbackNode->PostOperation) {
								PostOpsCallbackCount++;
								
								if (Verbose) DbgPrintEx(0, 0, "   [DCMB] Found minifilter post-operation callback : %s+0x%x = 0x%p\n",
									DcmbGetBaseNameFromFullName(ModuleInformation->Modules[i].FullPathName),
									(DWORD64)TargetCallbackNode->PostOperation - (DWORD64)ModuleInformation->Modules[i].ImageBase,
									TargetCallbackNode->PostOperation);
							}

							break;
						}
					}
				}except(EXCEPTION_EXECUTE_HANDLER) {}
			}
		}

		/*if (TargetCallbackNode) {
			// check if there is other callback
			PCALLBACK_NODE CurrentCallbackNode = TargetCallbackNode;
			while ((DWORD64)CurrentCallbackNode->CallbackLinks.Flink != (DWORD64)TargetCallbackNode) {
				try {
					CurrentCallbackNode = (PCALLBACK_NODE)CurrentCallbackNode->CallbackLinks.Flink;

					for (DWORD i = 0; i < ModuleInformation->NumberOfModules; i++) {
						// check if callback address falls into the memmory range of the driver 
						if (DcmbValidatePotentialCallbackNodes(CurrentCallbackNode,
							CurrentInstance, (DWORD64)ModuleInformation->Modules[i].ImageBase,
							ModuleInformation->Modules[i].ImageSize)) {
							
							//DbgPrintEx(0, 0, "Instance : 0x%p, CurrentCallbackNode : 0x%p\n", CurrentInstance, CurrentCallbackNode);
							if (TargetCallbackNode->PreOperation) {
								PreOpsCallbackCount++;

								if (Verbose) DbgPrintEx(0, 0, "   [DCMB] Found minifilter pre-operation callback : %s+0x%x = 0x%p\n",
									DcmbGetBaseNameFromFullName(ModuleInformation->Modules[i].FullPathName),
									(DWORD64)TargetCallbackNode->PreOperation - (DWORD64)ModuleInformation->Modules[i].ImageBase,
									TargetCallbackNode->PreOperation);
							}

							if (TargetCallbackNode->PostOperation) {
								PostOpsCallbackCount++;

								if (Verbose) DbgPrintEx(0, 0, "   [DCMB] Found minifilter post-operation callback : %s+0x%x = 0x%p\n",
									DcmbGetBaseNameFromFullName(ModuleInformation->Modules[i].FullPathName),
									(DWORD64)TargetCallbackNode->PostOperation - (DWORD64)ModuleInformation->Modules[i].ImageBase,
									TargetCallbackNode->PostOperation);
							}
						}
					}
				}except(EXCEPTION_EXECUTE_HANDLER) {
					break;
				}
			}
		}*/

		// free instance mem pool
		ExFreePool((PVOID)CurrentInstanceVA);
	}

	// free the pool
	ExFreePool((PVOID)ModuleInformation);

	DbgPrintEx(0, 0, "   [DCMB] %i pre-ops callback and %i post-ops callback enumerated.\n", PreOpsCallbackCount, PostOpsCallbackCount);

	return TRUE;
}