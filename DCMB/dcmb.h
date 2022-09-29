#include <ntifs.h>
#include <ntddk.h>
#include <ntimage.h>
#include <minwindef.h>
#include <intrin.h>
#include <ntddndis.h>
#include <strsafe.h>
#include <ntifs.h>
#pragma once

typedef enum _DCMB_CALLBACK_TYPE {
	LoadImageCallback,
	ProcessCreationCallback,
	ThreadCreationCallback,
	ProcessObjectCreationCallback,
	ThreadObjectCreationCallback,
	RegistryCallback
} DCMB_CALLBACK_TYPE;

typedef enum _SYSTEM_INFORMATION_CLASS {
    SystemBasicInformation = 0,
    SystemPerformanceInformation = 2,
    SystemTimeOfDayInformation = 3,
    SystemProcessInformation = 5,
    SystemProcessorPerformanceInformation = 8,
    SystemInterruptInformation = 23,
    SystemExceptionInformation = 33,
    SystemRegistryQuotaInformation = 37,
    SystemLookasideInformation = 45,
    SystemCodeIntegrityInformation = 103,
    SystemPolicyInformation = 134,
} SYSTEM_INFORMATION_CLASS;

typedef struct _RTL_PROCESS_MODULE_INFORMATION
{
    ULONG Section;
    PVOID MappedBase;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    CHAR FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES
{
    ULONG NumberOfModules;
    RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;

typedef struct _KLDR_DATA_TABLE_ENTRY
{
    LIST_ENTRY InLoadOrderLinks;
    PVOID ExceptionTable;
    ULONG ExceptionTableSize;
    PVOID GpValue;
    PNON_PAGED_DEBUG_INFO NonPagedDebugInfo;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG Flags;
    USHORT LoadCount;
    USHORT __Unused5;
    PVOID SectionPointer;
    ULONG CheckSum;
    PVOID LoadedImports;
    PVOID PatchInformation;
} KLDR_DATA_TABLE_ENTRY, * PKLDR_DATA_TABLE_ENTRY;

typedef NTSTATUS(NTAPI* PROTOTYPE_ZWQUERYSYSTEMINFORMATION)(SYSTEM_INFORMATION_CLASS info, PVOID infoinout, ULONG len, PULONG retLen);

PCHAR DcmbItoa(DWORD64 i);
DWORD64 DcmbGetKernelBase();
DWORD64 DcmbGetRoutineFromSSDT(DWORD64 KernelBase, WORD FuncIndex);
WORD DcmbGetRoutineSyscallIndex(LPCSTR RoutineName);
DWORD64 DcmbGetNotifyRoutineArray(DWORD64 KernelBase, DCMB_CALLBACK_TYPE CallbackType);
