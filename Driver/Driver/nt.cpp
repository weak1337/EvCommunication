#include "includes.h"

NTSTATUS nt::find_kernel_module(const char* moduleName, uintptr_t* moduleStart, size_t* moduleSize) {
	DWORD size = 0x0;
	ZwQuerySystemInformation(0xB, nullptr, size, reinterpret_cast<PULONG>(&size));

	auto listHeader = ExAllocatePool(NonPagedPool, size);

	if (!listHeader)
		return STATUS_MEMORY_NOT_ALLOCATED;


	if (const auto status = ZwQuerySystemInformation(0xB, listHeader, size, reinterpret_cast<PULONG>(&size))) {
		ExFreePoolWithTag(listHeader, 0);
		return status;
	}

	auto currentModule = reinterpret_cast<PSYSTEM_MODULE_INFORMATION>(listHeader)->Module;

	for (size_t i{}; i < reinterpret_cast<PSYSTEM_MODULE_INFORMATION>(listHeader)->Count; ++i, ++currentModule) {
		const auto currentModuleName = reinterpret_cast<const char*>(currentModule->FullPathName + currentModule->OffsetToFileName);
		if (!strcmp(moduleName, currentModuleName)) {
			*moduleStart = reinterpret_cast<uintptr_t>(currentModule->ImageBase);
			*moduleSize = currentModule->ImageSize;
			ExFreePoolWithTag(listHeader, 0);
			return STATUS_SUCCESS;
		}
	}
	ExFreePoolWithTag(listHeader, 0);
	return STATUS_NOT_FOUND;
}

NTSTATUS nt::find_export(const uintptr_t imageBase, const char* exportName, uintptr_t* functionPointer) {
	if (!imageBase)
		return STATUS_INVALID_PARAMETER_1;

	if (reinterpret_cast<PIMAGE_DOS_HEADER>(imageBase)->e_magic != 0x5A4D)
		return STATUS_INVALID_IMAGE_NOT_MZ;

	const auto ntHeader = reinterpret_cast<PIMAGE_NT_HEADERS64>(imageBase + reinterpret_cast<PIMAGE_DOS_HEADER>(imageBase)->e_lfanew);
	const auto exportDirectory = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(imageBase + ntHeader->OptionalHeader.DataDirectory[0].VirtualAddress);
	if (!exportDirectory)
		STATUS_INVALID_IMAGE_FORMAT;

	const auto exportedFunctions = reinterpret_cast<DWORD*>(imageBase + exportDirectory->AddressOfFunctions);
	const auto exportedNames = reinterpret_cast<DWORD*>(imageBase + exportDirectory->AddressOfNames);
	const auto exportedNameOrdinals = reinterpret_cast<UINT16*>(imageBase + exportDirectory->AddressOfNameOrdinals);

	for (size_t i{}; i < exportDirectory->NumberOfNames; ++i) {
		const auto functionName = reinterpret_cast<const char*>(imageBase + exportedNames[i]);
		if (!strcmp(exportName, functionName)) {
			*functionPointer = imageBase + exportedFunctions[exportedNameOrdinals[i]];
			return STATUS_SUCCESS;
		}
	}

	return STATUS_NOT_FOUND;
}