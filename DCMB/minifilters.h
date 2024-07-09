#pragma once
#include "dcmb.h"


typedef struct _CALLBACK_NODE
{
    LIST_ENTRY CallbackLinks;
    PFLT_INSTANCE Instance;
    union {
        PVOID PreOperation;
        PVOID GenerateFileName;
        PVOID NormalizeNameComponent;
        PVOID NormalizeNameComponentEx;
    };
    union {
        PVOID NormalizeContextCleanup;
        PVOID PostOperation;
    };
    DWORD64 Flags;
    //...
} CALLBACK_NODE, * PCALLBACK_NODE;

BOOL DcmbEnumerateFilters();
BOOL DcmbEnumFilterInstances(PFLT_FILTER TargetFilter, PFLT_INSTANCE** InstanceListOutput, PULONG InstanceCount);
BOOL DcmbValidatePotentialCallbackNodes(PCALLBACK_NODE PotentialCallbackNode, PFLT_INSTANCE FltInstance, DWORD64 DriverStartAddr, DWORD64 DriverSize);
BOOL DcmbReadMemorySafe(PVOID TargetAddress, PVOID AllocatedBuffer, SIZE_T LengthToRead);
BOOL DcmbEnumInstancesCallbacks(PFLT_INSTANCE* InstanceListBase, ULONG InstanceCount, BOOL Verbose);