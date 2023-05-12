#include "main.h"

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath) {
	//pDriverObject->DriverUnload = UnloadDriver;

	DbgPrintEx(0, 0, "DCMB said Hello from the kernel!\n");

	try {
		DWORD64 Kernelbase = DcmbGetKernelBase();

		if (!Kernelbase)
			return STATUS_SUCCESS;

		DbgPrintEx(0, 0, "[DCMB] Kernel base address : 0x%p\n", Kernelbase);

		DbgPrintEx(0, 0, "[DCMB] Load image callback array address : 0x%p\n", (PVOID)DcmbGetNotifyRoutineArray(Kernelbase, LoadImageCallback));
		DcmbEnumerateCallbacks(LoadImageCallback, Kernelbase);

		DbgPrintEx(0, 0, "[DCMB] Process creation callback array address : 0x%p\n", (PVOID)DcmbGetNotifyRoutineArray(Kernelbase, ProcessCreationCallback));
		DcmbEnumerateCallbacks(ProcessCreationCallback, Kernelbase);

		DbgPrintEx(0, 0, "[DCMB] Thread creation callback array address : 0x%p\n", (PVOID)DcmbGetNotifyRoutineArray(Kernelbase, ThreadCreationCallback));
		DcmbEnumerateCallbacks(ThreadCreationCallback, Kernelbase);

		DbgPrintEx(0, 0, "[DCMB] Registry RW callback list head address : 0x%p\n", (PVOID)DcmbGetNotifyRoutineArray(Kernelbase, RegistryCallback));
		DcmbEnumerateCallbacks(RegistryCallback, Kernelbase);

		DbgPrintEx(0, 0, "[DCMB] PsProcessType object callback list address : 0x%p\n", (PVOID)DcmbGetNotifyRoutineArray(Kernelbase, ProcessObjectCreationCallback));
		DcmbEnumerateCallbacks(ProcessObjectCreationCallback, Kernelbase);

		DbgPrintEx(0, 0, "[DCMB] PsThreadType object callback list address : 0x%p\n", (PVOID)DcmbGetNotifyRoutineArray(Kernelbase, ThreadObjectCreationCallback));
		DcmbEnumerateCallbacks(ThreadObjectCreationCallback, Kernelbase);

		DbgPrintEx(0, 0, "[DCMB] Driver verification callback array address : 0x%p\n", (PVOID)DcmbGetNotifyRoutineArray(Kernelbase, DriverVerificationCallback));
		DcmbEnumerateCallbacks(DriverVerificationCallback, Kernelbase);

		DbgPrintEx(0, 0, "DCMB exiting gracefully... Goodbye!");
		return STATUS_UNSUCCESSFUL;
	}except(EXCEPTION_EXECUTE_HANDLER) {
		DbgPrintEx(0, 0, "DCMB main exception handler triggered!");
		return STATUS_UNHANDLED_EXCEPTION;
	}
}

/*NTSTATUS UnloadDriver(PDRIVER_OBJECT pDriverObject) {

	DbgPrintEx(0, 0, "DCMB said Goodbye!\n");

	return STATUS_SUCCESS;
}*/