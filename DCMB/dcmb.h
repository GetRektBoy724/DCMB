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

typedef struct _REGISTRY_CALLBACK_ITEM
{
    LIST_ENTRY Item;
    DWORD64 Unknown1[2];
    DWORD64 Context;
    DWORD64 Function;
    UNICODE_STRING Altitude;
    DWORD64 Unknown2[2];
} REGISTRY_CALLBACK_ITEM, * PREGISTRY_CALLBACK_ITEM;

typedef struct OB_CALLBACK_ENTRY_t {
    LIST_ENTRY CallbackList; // linked element tied to _OBJECT_TYPE.CallbackList
    OB_OPERATION Operations; // bitfield : 1 for Creations, 2 for Duplications
    BOOL Enabled;            // self-explanatory
    struct OB_CALLBACK_t* Entry;      // points to the structure in which it is included
    POBJECT_TYPE ObjectType; // points to the object type affected by the callback
    POB_PRE_OPERATION_CALLBACK PreOperation;      // callback function called before each handle operation
    POB_POST_OPERATION_CALLBACK PostOperation;     // callback function called after each handle operation
    KSPIN_LOCK Lock;         // lock object used for synchronization
} OB_CALLBACK_ENTRY, * POB_CALLBACK_ENTRY;

typedef NTSTATUS(NTAPI* PROTOTYPE_ZWQUERYSYSTEMINFORMATION)(SYSTEM_INFORMATION_CLASS info, PVOID infoinout, ULONG len, PULONG retLen);

PCHAR DcmbGetBaseNameFromFullName(PCHAR FullName);
DWORD64 DcmbGetKernelBase();
DWORD64 DcmbGetRoutineFromSSDT(DWORD64 KernelBase, WORD FuncIndex);
WORD DcmbGetRoutineSyscallIndex(LPCSTR RoutineName);
DWORD64 DcmbGetNotifyRoutineArray(DWORD64 KernelBase, DCMB_CALLBACK_TYPE CallbackType);
void DcmbEnumerateCallbacks(DCMB_CALLBACK_TYPE CallbackType, DWORD64 KernelBase);
