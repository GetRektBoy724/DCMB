#include "dcmb.h"

PCHAR DcmbGetBaseNameFromFullName(PCHAR FullName) {
	SIZE_T FullNameLength = strlen(FullName);

	for (SIZE_T i = FullNameLength; i > 0; i--) {
		if (*(FullName + i) == '\\') {
			return FullName + i + 1;
		}
	}

	return NULL;
}

DWORD64 DcmbGetKernelBase() {
	PRTL_PROCESS_MODULES ModuleInformation = NULL;
	NTSTATUS result;
	ULONG SizeNeeded;
	SIZE_T InfoRegionSize;
	DWORD64 output = 0;
	PROTOTYPE_ZWQUERYSYSTEMINFORMATION ZwQuerySystemInformation;
	UNICODE_STRING ZWQSIName;

	RtlInitUnicodeString(&ZWQSIName, L"ZwQuerySystemInformation");
	ZwQuerySystemInformation = (PROTOTYPE_ZWQUERYSYSTEMINFORMATION)MmGetSystemRoutineAddress(&ZWQSIName);

	// get info size
	result = ZwQuerySystemInformation(0x0B, NULL, 0, &SizeNeeded);
	if (result != 0xC0000004) {
		return output;
	}
	InfoRegionSize = SizeNeeded;

	// get info
	while (result == 0xC0000004) {
		InfoRegionSize += 0x1000;
		ModuleInformation = (PRTL_PROCESS_MODULES)ExAllocatePool(NonPagedPoolNx, InfoRegionSize);
		if (ModuleInformation == NULL) {
			return output;
		}

		result = ZwQuerySystemInformation(0x0B, (PVOID)ModuleInformation, (ULONG)InfoRegionSize, &SizeNeeded);
		if (result == 0xC0000004) {
			ExFreePool((PVOID)ModuleInformation);
			ModuleInformation = NULL;
		}
	}

	if (!NT_SUCCESS(result)) {
		return output;
	}

	output = (DWORD64)ModuleInformation->Modules[0].ImageBase;

	// free pool
	ExFreePool((PVOID)ModuleInformation);

	return output;
}

DWORD64 DcmbGetRoutineFromSSDT(DWORD64 KernelBase, WORD FuncIndex) {
	DWORD64 KiServiceTableAddr = 0;
	DWORD64 KeRemoveSystemServiceTableAddr = 0;
	DWORD64 KeServiceDescriptorTableFilterAddr = 0;
	DWORD RoutineOffset = 0;
	UNICODE_STRING KeRemoveSystemServiceTableName;

	RtlInitUnicodeString(&KeRemoveSystemServiceTableName, L"KeRemoveSystemServiceTable");
	KeRemoveSystemServiceTableAddr = (DWORD64)MmGetSystemRoutineAddress(&KeRemoveSystemServiceTableName);
	if (!KeRemoveSystemServiceTableAddr)
		return 0;

	// search for LEA instruction
	for (int i = 0; i < 300; i++) {
		if ((*(PBYTE)(KeRemoveSystemServiceTableAddr + i) == 0x48 || *(PBYTE)(KeRemoveSystemServiceTableAddr + i) == 0x4C) && *(PBYTE)(KeRemoveSystemServiceTableAddr + i + 1) == 0x8D) {
			DWORD KeServiceDescriptorTableFilterOffset = *(PDWORD)(KeRemoveSystemServiceTableAddr + i + 3);
			KeServiceDescriptorTableFilterAddr = KeRemoveSystemServiceTableAddr + i + 7 + KeServiceDescriptorTableFilterOffset;
			break;
		}
	}

	if (!KeServiceDescriptorTableFilterAddr)
		return 0;

	KiServiceTableAddr = *(PDWORD64)(KeServiceDescriptorTableFilterAddr);
	if (!KiServiceTableAddr)
		return 0;

	RoutineOffset = *(PDWORD)(KiServiceTableAddr + (FuncIndex * 4));
	if (!RoutineOffset)
		return 0;

	return (KiServiceTableAddr + (RoutineOffset >> 4));
}

WORD DcmbGetRoutineSyscallIndex(LPCSTR RoutineName) {
	NTSTATUS result = 0;
	HANDLE SectionHandle = NULL;
	UNICODE_STRING SectionName;
	OBJECT_ATTRIBUTES ObjectAttr;
	PVOID SectionBaseAddr = NULL;
	SIZE_T ViewSize = 0;
	PVOID RoutineAddr = NULL;
	WORD OutputRoutineSyscallIndex = 0;

	RtlInitUnicodeString(&SectionName, L"\\KnownDlls\\ntdll.dll");
	InitializeObjectAttributes(&ObjectAttr, &SectionName, OBJ_CASE_INSENSITIVE, NULL, NULL);

	result = ZwOpenSection(&SectionHandle, SECTION_MAP_EXECUTE | SECTION_MAP_READ, &ObjectAttr);
	if (!NT_SUCCESS(result)) {
		return 0;
	}

	result = ZwMapViewOfSection(SectionHandle, (HANDLE)(-1), &SectionBaseAddr, 0, 0, NULL, &ViewSize, ViewUnmap, 0, PAGE_READONLY);
	if (!NT_SUCCESS(result)) {
		ZwClose(SectionHandle);
		return 0;
	}

	// parse the PE header
	PVOID OptHeader = (PVOID)((SIZE_T)SectionBaseAddr + *((PDWORD)((SIZE_T)SectionBaseAddr + 0x3c)) + 0x18);
	WORD Magic = *((PWORD)OptHeader);
	PVOID DataDirectory = NULL;
	if (Magic == 0x10b) { // 32 bit 
		DataDirectory = (PVOID)((SIZE_T)OptHeader + 0x60);
	}
	else if (Magic == 0x20b) { // 64 bit
		DataDirectory = (PVOID)((SIZE_T)OptHeader + 0x70);
	}
	else {
		return 0;
	}

	// parse the export header
	DWORD ExportRVA = *((PDWORD)DataDirectory);
	DWORD OrdinalBase = *((PDWORD)((SIZE_T)SectionBaseAddr + ExportRVA + 0x10));
	DWORD NumberOfNames = *((PDWORD)((SIZE_T)SectionBaseAddr + ExportRVA + 0x18));
	DWORD FunctionsRVA = *((PDWORD)((SIZE_T)SectionBaseAddr + ExportRVA + 0x1C));
	DWORD NamesRVA = *((PDWORD)((SIZE_T)SectionBaseAddr + ExportRVA + 0x20));
	DWORD OrdinalsRVA = *((PDWORD)((SIZE_T)SectionBaseAddr + ExportRVA + 0x24));

	for (DWORD i = 0; i < NumberOfNames; i++) {
		DWORD FunctionNameRVA = *((PDWORD)((SIZE_T)SectionBaseAddr + NamesRVA + (i * 4)));
		PCHAR FunctionName = (PCHAR)((SIZE_T)SectionBaseAddr + FunctionNameRVA);

		if (strcmp(FunctionName, (PCHAR)RoutineName) == 0) {
			WORD FunctionOrdinal = *((PWORD)((SIZE_T)SectionBaseAddr + OrdinalsRVA + (i * 2))) + (WORD)OrdinalBase;
			DWORD FunctionRVA = *((PDWORD)((SIZE_T)SectionBaseAddr + FunctionsRVA + (4 * (FunctionOrdinal - OrdinalBase))));
			RoutineAddr = (PVOID)((SIZE_T)SectionBaseAddr + FunctionRVA);
		}
	}

	if (!RoutineAddr)
		return 0;

	OutputRoutineSyscallIndex = (*((PBYTE)RoutineAddr + 5) << 8) | *((PBYTE)RoutineAddr + 4);

	ZwUnmapViewOfSection((HANDLE)(-1), SectionBaseAddr);
	ZwClose(SectionHandle);

	return OutputRoutineSyscallIndex;
}

DWORD64 DcmbGetNotifyRoutineArray(DWORD64 KernelBase, DCMB_CALLBACK_TYPE CallbackType) {
	DWORD64 NotifyRoutineAddr = 0;
	DWORD64 PspNotifyRoutineAddr = 0;
	DWORD64 PspNotifyRoutineArrayAddr = 0;
	UNICODE_STRING NotifyRoutineName;

	switch (CallbackType) {
		case LoadImageCallback: {
			RtlInitUnicodeString(&NotifyRoutineName, L"PsSetLoadImageNotifyRoutine");
			NotifyRoutineAddr = MmGetSystemRoutineAddress(&NotifyRoutineName);
			break;
		}

		case ProcessCreationCallback: {
			RtlInitUnicodeString(&NotifyRoutineName, L"PsSetCreateProcessNotifyRoutine");
			NotifyRoutineAddr = MmGetSystemRoutineAddress(&NotifyRoutineName);
			break;
		}

		case ThreadCreationCallback: {
			RtlInitUnicodeString(&NotifyRoutineName, L"PsSetCreateThreadNotifyRoutine");
			NotifyRoutineAddr = MmGetSystemRoutineAddress(&NotifyRoutineName);
			break;
		}

		case ProcessObjectCreationCallback: {
			WORD RoutineSyscallIndex = DcmbGetRoutineSyscallIndex("NtSuspendProcess");
			if (!RoutineSyscallIndex) break;

			NotifyRoutineAddr = DcmbGetRoutineFromSSDT(KernelBase, RoutineSyscallIndex);
			break;
		}

		case ThreadObjectCreationCallback: {
			WORD RoutineSyscallIndex = DcmbGetRoutineSyscallIndex("NtSuspendThread");
			if (!RoutineSyscallIndex) break;

			NotifyRoutineAddr = DcmbGetRoutineFromSSDT(KernelBase, RoutineSyscallIndex);
			break;
		}

		case RegistryCallback: {
			RtlInitUnicodeString(&NotifyRoutineName, L"CmRegisterCallback");
			NotifyRoutineAddr = MmGetSystemRoutineAddress(&NotifyRoutineName);
			break;
		}

		default: {
			break;
		}
	}

	if (!NotifyRoutineAddr) {
		return 0;
	}

	//DbgPrintEx(0, 0, "CmRegisterCallback = 0x%p", NotifyRoutineAddr);

	// check for CALL or JMP instruction
	if (CallbackType == ProcessObjectCreationCallback || CallbackType == ThreadObjectCreationCallback) {
		RtlInitUnicodeString(&NotifyRoutineName, L"ObReferenceObjectByHandle");
		DWORD64 ObReferenceObjectByHandleAddr = (DWORD64)MmGetSystemRoutineAddress(&NotifyRoutineName);
		RtlInitUnicodeString(&NotifyRoutineName, L"ObReferenceObjectByHandleWithTag");
		DWORD64 ObReferenceObjectByHandleWithTagAddr = (DWORD64)MmGetSystemRoutineAddress(&NotifyRoutineName);
		DWORD64 ObpReferenceObjectByHandleWithTagAddr = 0;
		if (ObReferenceObjectByHandleWithTagAddr) {
			// get ObpReferenceObjectByHandleWithTag address
			for (int i = 0; i < 100; i++) {
				if (*(PBYTE)(ObReferenceObjectByHandleWithTagAddr + i) == 0xE8) {
					ObpReferenceObjectByHandleWithTagAddr = ObReferenceObjectByHandleWithTagAddr + i + 5 + *(PLONG)(ObReferenceObjectByHandleWithTagAddr + i + 1);
					break;
				}
			}
		}
		LONG ObReferenceObjectByHandleOffset = 0;
		LONG ObReferenceObjectByHandleWithTagOffset = 0;
		LONG ObpReferenceObjectByHandleWithTagOffset = 0;

		for (int i = 0; i < 200; i++) {
			// check if ObReferenceObjectByHandle is exist, if it is then calculate the offset
			if (ObReferenceObjectByHandleAddr) ObReferenceObjectByHandleOffset = ObReferenceObjectByHandleAddr - (NotifyRoutineAddr + i + 5);

			// check if ObReferenceObjectByHandleWithTag is exist, if it is then calculate the offset
			if (ObReferenceObjectByHandleWithTagAddr) ObReferenceObjectByHandleWithTagOffset = ObReferenceObjectByHandleWithTagAddr - (NotifyRoutineAddr + i + 5);

			// check if ObpReferenceObjectByHandleWithTag is exist, if it is then calculate the offset
			if (ObpReferenceObjectByHandleWithTagAddr) ObpReferenceObjectByHandleWithTagOffset = ObpReferenceObjectByHandleWithTagAddr - (NotifyRoutineAddr + i + 5);

			// check if the offset is valid with our calculation
			if (*(PBYTE)(NotifyRoutineAddr + i) == 0xE8 && (*(PLONG)(NotifyRoutineAddr + i + 1) == ObReferenceObjectByHandleOffset || *(PLONG)(NotifyRoutineAddr + i + 1) == ObReferenceObjectByHandleWithTagOffset || *(PLONG)(NotifyRoutineAddr + i + 1) == ObpReferenceObjectByHandleWithTagOffset)) {
				PspNotifyRoutineAddr = NotifyRoutineAddr + i;
				break;
			}
		}
	}
	else {
		for (int i = 0; i < 200; i++) {
			if (*(PBYTE)(NotifyRoutineAddr + i) == 0xE9 || *(PBYTE)(NotifyRoutineAddr + i) == 0xE8) {
				LONG PspNotifyRoutineOffset = *(PLONG)(NotifyRoutineAddr + i + 1);
				PspNotifyRoutineAddr = NotifyRoutineAddr + i + 5 + PspNotifyRoutineOffset;
				break;
			}
		}
	}

	if (!PspNotifyRoutineAddr) {
		return 0;
	}

	//DbgPrintEx(0, 0, "PspNotifyRoutineAddr = 0x%p", PspNotifyRoutineAddr);

	if (CallbackType == RegistryCallback) {
		// we scan for last INT 3 instruction (0xCC)
		DWORD64 CmpInsertCallbackInListByAltitudeAddr = 0;
		for (int i = 0; i < 1024; i++) {
			if (*(PBYTE)(PspNotifyRoutineAddr + i) == 0xCC) {
				while (*(PBYTE)(PspNotifyRoutineAddr + i) == 0xCC) i++;
				CmpInsertCallbackInListByAltitudeAddr = PspNotifyRoutineAddr + i;
				break;
			}
		}

		// start searching LEA instruction
		for (int i = 0; i < 300; i++) {
			if ((*(PBYTE)(CmpInsertCallbackInListByAltitudeAddr + i) == 0x4C) && *(PBYTE)(CmpInsertCallbackInListByAltitudeAddr + i + 1) == 0x8D) {
				LONG PspNotifyRoutineArrayOffset = *(PLONG)(CmpInsertCallbackInListByAltitudeAddr + i + 3);
				PspNotifyRoutineArrayAddr = CmpInsertCallbackInListByAltitudeAddr + i + 7 + PspNotifyRoutineArrayOffset;
				break;
			}
		}
	}
	else if (CallbackType == ProcessObjectCreationCallback || CallbackType == ThreadObjectCreationCallback) {
		// we scan for MOV instruction, backwards
		for (int i = 0; i < 50; i++) {
			if ((*(PBYTE)(PspNotifyRoutineAddr - i) == 0x48 || *(PBYTE)(PspNotifyRoutineAddr - i) == 0x4C) && *(PBYTE)(PspNotifyRoutineAddr - i + 1) == 0x8B) {
				LONG PspNotifyRoutineArrayOffset = *(PLONG)(PspNotifyRoutineAddr - i + 3);
				PspNotifyRoutineArrayAddr = PspNotifyRoutineAddr - i + 7 + PspNotifyRoutineArrayOffset;
				PspNotifyRoutineArrayAddr = *(PDWORD64)(PspNotifyRoutineArrayAddr) + 0xc8;
				break;
			}
		}
	}
	else {
		// check for LEA instruction
		for (int i = 0; i < 300; i++) {
			if ((*(PBYTE)(PspNotifyRoutineAddr + i) == 0x48 || *(PBYTE)(PspNotifyRoutineAddr + i) == 0x4C) && *(PBYTE)(PspNotifyRoutineAddr + i + 1) == 0x8D) {
				LONG PspNotifyRoutineArrayOffset = *(PLONG)(PspNotifyRoutineAddr + i + 3);
				PspNotifyRoutineArrayAddr = PspNotifyRoutineAddr + i + 7 + PspNotifyRoutineArrayOffset;
				break;
			}
		}
	}

	return PspNotifyRoutineArrayAddr;
}

BOOL ZbzrEnumerateDriver(DWORD64 CallbackAddress, PCHAR* DriverFound, PDWORD64 FoundDriverBase) {
	PRTL_PROCESS_MODULES ModuleInformation = NULL;
	NTSTATUS result;
	ULONG SizeNeeded;
	SIZE_T InfoRegionSize;
	BOOL output = FALSE;
	PROTOTYPE_ZWQUERYSYSTEMINFORMATION ZwQuerySystemInformation;
	UNICODE_STRING ZWQSIName;

	RtlInitUnicodeString(&ZWQSIName, L"ZwQuerySystemInformation");
	ZwQuerySystemInformation = (PROTOTYPE_ZWQUERYSYSTEMINFORMATION)MmGetSystemRoutineAddress(&ZWQSIName);

	// get info size
	result = ZwQuerySystemInformation(0x0B, NULL, 0, &SizeNeeded);
	if (result != 0xC0000004) {
		return output;
	}
	InfoRegionSize = SizeNeeded;

	// get info
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

	// enumerate through the drivers
	for (DWORD i = 0; i < ModuleInformation->NumberOfModules; i++) {
		// check if callback address falls into the memmory range of the driver 
		if (((DWORD64)ModuleInformation->Modules[i].ImageBase < CallbackAddress) && (CallbackAddress < ((DWORD64)ModuleInformation->Modules[i].ImageBase + ModuleInformation->Modules[i].ImageSize))) {
			*DriverFound = ModuleInformation->Modules[i].FullPathName;
			*FoundDriverBase = ModuleInformation->Modules[i].ImageBase;
			output = TRUE;
		}
	}

	// free the pool
	ExFreePool((PVOID)ModuleInformation);

	return output;
}

void DcmbEnumerateCallbacks(DCMB_CALLBACK_TYPE CallbackType, DWORD64 KernelBase) {
	DWORD64 CallbackArrayAddr = 0;
	if (!(CallbackArrayAddr = DcmbGetNotifyRoutineArray(KernelBase, CallbackType))) return;

	if (CallbackType == RegistryCallback) {
		PREGISTRY_CALLBACK_ITEM CurrentRegistryCallback = (PREGISTRY_CALLBACK_ITEM)CallbackArrayAddr;

		while (TRUE) {
			DWORD64 CurrentCallbackAddress = CurrentRegistryCallback->Function;

			PCHAR DriverPath = NULL;
			DWORD64 DriverBase = 0;
			if (ZbzrEnumerateDriver(CurrentCallbackAddress, &DriverPath, &DriverBase)) {
				DbgPrintEx(0, 0, "   [DCMB] Registry Read/Write : %s+0x%x = 0x%p\n", DcmbGetBaseNameFromFullName(DriverPath), CurrentCallbackAddress - DriverBase, CurrentCallbackAddress);
			}

			if ((PVOID)CurrentRegistryCallback->Item.Flink == (PVOID)CallbackArrayAddr)
				break;

			CurrentRegistryCallback = (PREGISTRY_CALLBACK_ITEM)CurrentRegistryCallback->Item.Flink;
		}
	}
	else if (CallbackType == ProcessObjectCreationCallback || CallbackType == ThreadObjectCreationCallback) {
		POB_CALLBACK_ENTRY CurrentObjectCallbackEntryItem = (POB_CALLBACK_ENTRY)CallbackArrayAddr;

		do {
			PCHAR DriverPath = NULL;
			DWORD64 DriverBase = 0;
			if (ZbzrEnumerateDriver((DWORD64)CurrentObjectCallbackEntryItem->PostOperation, &DriverPath, &DriverBase)) {
				if (CallbackType == ProcessObjectCreationCallback) {
					DbgPrintEx(0, 0, "   [DCMB] Process Object Post-Creation : %s+0x%x = 0x%p\n", DcmbGetBaseNameFromFullName(DriverPath), (DWORD64)CurrentObjectCallbackEntryItem->PostOperation - DriverBase, (DWORD64)CurrentObjectCallbackEntryItem->PostOperation);
				}
				else {
					DbgPrintEx(0, 0, "   [DCMB] Thread Object Post-Creation : %s+0x%x = 0x%p\n", DcmbGetBaseNameFromFullName(DriverPath), (DWORD64)CurrentObjectCallbackEntryItem->PostOperation - DriverBase, (DWORD64)CurrentObjectCallbackEntryItem->PostOperation);
				}
			}

			if (ZbzrEnumerateDriver((DWORD64)CurrentObjectCallbackEntryItem->PreOperation, &DriverPath, &DriverBase)) {
				if (CallbackType == ProcessObjectCreationCallback) {
					DbgPrintEx(0, 0, "   [DCMB] Process Object Pre-Creation : %s+0x%x = 0x%p\n", DcmbGetBaseNameFromFullName(DriverPath), (DWORD64)CurrentObjectCallbackEntryItem->PreOperation - DriverBase, (DWORD64)CurrentObjectCallbackEntryItem->PreOperation);
				}
				else {
					DbgPrintEx(0, 0, "   [DCMB] Thread Object Pre-Creation : %s+0x%x = 0x%p\n", DcmbGetBaseNameFromFullName(DriverPath), (DWORD64)CurrentObjectCallbackEntryItem->PreOperation - DriverBase, (DWORD64)CurrentObjectCallbackEntryItem->PreOperation);
				}
			}
			CurrentObjectCallbackEntryItem = (POB_CALLBACK_ENTRY)CurrentObjectCallbackEntryItem->CallbackList.Flink;
		} while ((DWORD64)CurrentObjectCallbackEntryItem->CallbackList.Flink != (DWORD64)CallbackArrayAddr);
	}
	else {
		for (int i = 0; i < 64; i++) {
			DWORD64 CurrentCallback = *(PDWORD64)(CallbackArrayAddr + (i * 8));

			// skip null entries
			if (CurrentCallback == 0)
				continue;

			DWORD64 CurrentCallbackAddress = *(PDWORD64)(CurrentCallback &= ~(1ULL << 3) + 0x1);

			// do some checks
			PCHAR DriverPath = NULL;
			DWORD64 DriverBase = 0;
			if (ZbzrEnumerateDriver(CurrentCallbackAddress, &DriverPath, &DriverBase)) {
				if (CallbackType == ProcessCreationCallback) {
					DbgPrintEx(0, 0, "   [DCMB] Process Creation : %s+0x%x = 0x%p\n", DcmbGetBaseNameFromFullName(DriverPath), CurrentCallbackAddress - DriverBase, CurrentCallbackAddress);
				}
				else if (CallbackType == ThreadCreationCallback) {
					DbgPrintEx(0, 0, "   [DCMB] Thread Creation : %s+0x%x = 0x%p\n", DcmbGetBaseNameFromFullName(DriverPath), CurrentCallbackAddress - DriverBase, CurrentCallbackAddress);
				}
				else {
					DbgPrintEx(0, 0, "   [DCMB] Load Image : %s+0x%x = 0x%p\n", DcmbGetBaseNameFromFullName(DriverPath), CurrentCallbackAddress - DriverBase, CurrentCallbackAddress);
				}
			}
		}
	}
}
