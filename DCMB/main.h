#include "dcmb.h"
#include "minifilters.h"
#pragma once

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath);
NTSTATUS UnloadDriver(PDRIVER_OBJECT pDriverObject);
