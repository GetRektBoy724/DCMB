#include "main.h"

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath) {
	pDriverObject->DriverUnload = UnloadDriver;
	CHAR msg[1024];

	DbgPrintEx(0, 0, "DCMB said Hello from the kernel!\n");

	DWORD64 Kernelbase = DcmbGetKernelBase();

	if (!Kernelbase)
		return STATUS_SUCCESS;

	strcpy(msg, "Kernel base address : ");
	strcat(msg, DcmbItoa(Kernelbase));
	DbgPrintEx(0, 0, msg);
	RtlSecureZeroMemory(msg, 1024);
	
	strcpy(msg, "Load image callback array address : ");
	strcat(msg, DcmbItoa(DcmbGetNotifyRoutineArray(Kernelbase, LoadImageCallback)));
	DbgPrintEx(0, 0, msg);
	RtlSecureZeroMemory(msg, 1024);

	strcpy(msg, "Process creation callback array address : ");
	strcat(msg, DcmbItoa(DcmbGetNotifyRoutineArray(Kernelbase, ProcessCreationCallback)));
	DbgPrintEx(0, 0, msg);
	RtlSecureZeroMemory(msg, 1024);

	strcpy(msg, "Thread creation callback array address : ");
	strcat(msg, DcmbItoa(DcmbGetNotifyRoutineArray(Kernelbase, ThreadCreationCallback)));
	DbgPrintEx(0, 0, msg);
	RtlSecureZeroMemory(msg, 1024);

	strcpy(msg, "Registry RW callback list head address : ");
	strcat(msg, DcmbItoa(DcmbGetNotifyRoutineArray(Kernelbase, RegistryCallback)));
	DbgPrintEx(0, 0, msg);
	RtlSecureZeroMemory(msg, 1024);
	
	strcpy(msg, "PsProcessType object callback list address : ");
	strcat(msg, DcmbItoa(DcmbGetNotifyRoutineArray(Kernelbase, ProcessObjectCreationCallback)));
	DbgPrintEx(0, 0, msg);
	RtlSecureZeroMemory(msg, 1024);

	strcpy(msg, "PsThreadType object callback list address : ");
	strcat(msg, DcmbItoa(DcmbGetNotifyRoutineArray(Kernelbase, ThreadObjectCreationCallback)));
	DbgPrintEx(0, 0, msg);
	RtlSecureZeroMemory(msg, 1024);

	return STATUS_SUCCESS;
}

NTSTATUS UnloadDriver(PDRIVER_OBJECT pDriverObject) {

	DbgPrintEx(0, 0, "DCMB said Goodbye!\n");

	return STATUS_SUCCESS;
}