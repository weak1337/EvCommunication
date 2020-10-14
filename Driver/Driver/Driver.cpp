#include "includes.h"
Hook NtTokenManager;

struct Info {
	DWORD type;
};

void handler(uintptr_t user_paramter) {
	DbgPrint("Hook got called\n");
	NtTokenManager.hook_undo();

	uintptr_t address_of_buffer = user_paramter;
	Info* info = (Info*)address_of_buffer;

	WCHAR user_event[0xFF] = L"\\BaseNamedObjects\\Global\\bruhmomentumuser";
	WCHAR kernel_event[0xFF] = L"\\BaseNamedObjects\\Global\\bruhmomentumkernel";
	NTSTATUS status;
	//
	UNICODE_STRING event_user;
	RtlInitUnicodeString(&event_user, user_event);
	HANDLE handle_to_user_event;
	OBJECT_ATTRIBUTES ObjectAttributes;
	InitializeObjectAttributes(&ObjectAttributes, &event_user, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL,0);
	status= ZwOpenEvent(&handle_to_user_event, EVENT_ALL_ACCESS, &ObjectAttributes);
	//
	UNICODE_STRING event_kernel;
	RtlInitUnicodeString(&event_kernel, kernel_event);
	HANDLE handle_to_kernel_event;
	OBJECT_ATTRIBUTES ObjectAttributes2;
	InitializeObjectAttributes(&ObjectAttributes2, &event_kernel, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, 0);
	status = ZwOpenEvent(&handle_to_kernel_event, EVENT_ALL_ACCESS, &ObjectAttributes2);
	//

	LONG last;
	ZwSetEvent(handle_to_kernel_event, &last); //Signal usermode we are done
	
	LARGE_INTEGER Timeout;
	Timeout.QuadPart = (-60 * 3) * 1000 * 1000 * 10;
	bool terminate = false;
	while (!terminate)
	{
		
		status = ZwWaitForSingleObject(handle_to_user_event, TRUE, &Timeout); //Wait for SetEvent(user_event_handle)
		if (status == STATUS_TIMEOUT || status == STATUS_ALERTED)
		{
			terminate = true;
			break;
		}
		DbgPrint("Communication got called with param: %x\n", info->type);
		if (!NT_SUCCESS(ZwSetEvent(handle_to_kernel_event, &last))) { //Signal usermode -> operation done
			terminate = true;
		}
	}
}

NTSTATUS DriverEntry(){
	uintptr_t base;
	size_t size;
	NTSTATUS status;
	if (!NT_SUCCESS(status = nt::find_kernel_module("dxgkrnl.sys", &base, &size)))
		return status;
	uintptr_t function_address;
	if (!NT_SUCCESS(status = nt::find_export(base, "NtTokenManagerCreateFlipObjectReturnTokenHandle", &function_address)))
		return status;
	DbgPrint("Found NtTokenManagerCreateFlipObjectReturnTokenHandle at %p\n", function_address);
	NtTokenManager.initialize(function_address, (uintptr_t)&handler);
	NtTokenManager.hook_do();
	return STATUS_SUCCESS;
}

NTSTATUS fake_entry(PDRIVER_OBJECT driver, PUNICODE_STRING registryPath) {
	return DriverEntry();
}

