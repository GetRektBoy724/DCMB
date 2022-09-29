#include "dcmb.h"

PCHAR DcmbItoa(DWORD64 i)
{
	/* Room for UINT_DIGITS digits and '\0' */
	static char buf[20 + 1];
	char* p = buf + 20;	/* points to terminating '\0' */
	do {
		*--p = '0' + (i % 10);
		i /= 10;
	} while (i != 0);
	return p;
}

/*DWORD64 DcmbGetKernelBase(PDRIVER_OBJECT driverObject) {
	PKLDR_DATA_TABLE_ENTRY pThisModule = (PKLDR_DATA_TABLE_ENTRY)driverObject->DriverSection;
	UNICODE_STRING ntoskrnlName;

	RtlInitUnicodeString(&ntoskrnlName, L"ntoskrnl.exe");

    // Get PsLoadedModuleList address
	for (PLIST_ENTRY pListEntry = pThisModule->InLoadOrderLinks.Flink; pListEntry != &pThisModule->InLoadOrderLinks; pListEntry = pListEntry->Flink)
	{
		// Search for Ntoskrnl entry
		PKLDR_DATA_TABLE_ENTRY pEntry = CONTAINING_RECORD(pListEntry, KLDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
		if (RtlCompareUnicodeString(&(pEntry->BaseDllName), &ntoskrnlName, TRUE))
		{
			return (DWORD64)pEntry->DllBase;
		}
	}

	return 0;
}*/

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
			if (!RoutineSyscallIndex)
				break;

			NotifyRoutineAddr = DcmbGetRoutineFromSSDT(KernelBase, RoutineSyscallIndex);
			break;
		}

		case ThreadObjectCreationCallback: {
			WORD RoutineSyscallIndex = DcmbGetRoutineSyscallIndex("NtSuspendThread");
			if (!RoutineSyscallIndex)
				break;

			NotifyRoutineAddr = DcmbGetRoutineFromSSDT(KernelBase, RoutineSyscallIndex);
			break;
		}

		case RegistryCallback: {
			RtlInitUnicodeString(&NotifyRoutineName, L"CmUnRegisterCallback");
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

	// check for CALL or JMP instruction
	if (CallbackType == RegistryCallback) {
		PspNotifyRoutineAddr = NotifyRoutineAddr;
	}
	else if (CallbackType == ProcessObjectCreationCallback || CallbackType == ThreadObjectCreationCallback) {
		RtlInitUnicodeString(&NotifyRoutineName, L"ObReferenceObjectByHandle");
		DWORD64 ObReferenceObjectByHandleAddr = (DWORD64)MmGetSystemRoutineAddress(&NotifyRoutineName);
		RtlInitUnicodeString(&NotifyRoutineName, L"ObReferenceObjectByHandleWithTag");
		DWORD64 ObReferenceObjectByHandleWithTagAddr = (DWORD64)MmGetSystemRoutineAddress(&NotifyRoutineName);
		DWORD ObReferenceObjectByHandleOffset = 0;
		DWORD ObReferenceObjectByHandleWithTagOffset = 0;

		for (int i = 0; i < 200; i++) {
			// check if ObReferenceObjectByHandle is exist, if it is then calculate the offset
			if (ObReferenceObjectByHandleAddr)
				ObReferenceObjectByHandleOffset = ObReferenceObjectByHandleAddr - (NotifyRoutineAddr + i + 5);

			// check if ObReferenceObjectByHandleWithTag is exist, if it is then calculate the offset
			if (ObReferenceObjectByHandleWithTagAddr)
				ObReferenceObjectByHandleWithTagOffset = ObReferenceObjectByHandleWithTagAddr - (NotifyRoutineAddr + i + 5);

			// check if the offset is valid with our calculation
			if (*(PBYTE)(NotifyRoutineAddr + i) == 0xE8 && (*(PDWORD)(NotifyRoutineAddr + i + 1) == ObReferenceObjectByHandleOffset || *(PDWORD)(NotifyRoutineAddr + i + 1) == ObReferenceObjectByHandleWithTagOffset)) {
				PspNotifyRoutineAddr = NotifyRoutineAddr + i;
				break;
			}
		}
	}
	else {
		for (int i = 0; i < 200; i++) {
			if (*(PBYTE)(NotifyRoutineAddr + i) == 0xE9 || *(PBYTE)(NotifyRoutineAddr + i) == 0xE8) {
				DWORD PspNotifyRoutineOffset = *(PDWORD)(NotifyRoutineAddr + i + 1);
				PspNotifyRoutineAddr = NotifyRoutineAddr + i + 5 + PspNotifyRoutineOffset;
				break;
			}
		}
	}

	if (!PspNotifyRoutineAddr) {
		return 0;
	}

	if (CallbackType == RegistryCallback) {
		// we scan backwards
		for (int i = 175; i > 0; i--) {
			if ((*(PBYTE)(PspNotifyRoutineAddr + i) == 0x48 || *(PBYTE)(PspNotifyRoutineAddr + i) == 0x4C) && *(PBYTE)(PspNotifyRoutineAddr + i + 1) == 0x8D) {
				DWORD PspNotifyRoutineArrayOffset = *(PDWORD)(PspNotifyRoutineAddr + i + 3);
				PspNotifyRoutineArrayAddr = PspNotifyRoutineAddr + i + 7 + PspNotifyRoutineArrayOffset;
				break;
			}
		}
	}
	else if (CallbackType == ProcessObjectCreationCallback || CallbackType == ThreadObjectCreationCallback) {
		// we scan for MOV instruction, backwards
		for (int i = 0; i < 50; i++) {
			if ((*(PBYTE)(PspNotifyRoutineAddr - i) == 0x48 || *(PBYTE)(PspNotifyRoutineAddr - i) == 0x4C) && *(PBYTE)(PspNotifyRoutineAddr - i + 1) == 0x8B) {
				DWORD PspNotifyRoutineArrayOffset = *(PDWORD)(PspNotifyRoutineAddr - i + 3);
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

				DWORD PspNotifyRoutineArrayOffset = *(PDWORD)(PspNotifyRoutineAddr + i + 3);
				PspNotifyRoutineArrayAddr = PspNotifyRoutineAddr + i + 7 + PspNotifyRoutineArrayOffset;
				break;
			}
		}
	}

	return PspNotifyRoutineArrayAddr;
}
