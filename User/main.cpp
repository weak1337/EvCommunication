#include <Windows.h>
#include <iostream>
struct Info {
	DWORD type;
};
static Info* test_stuff;
int main() {
	LoadLibraryA("user32.dll");
	HMODULE winlib = LoadLibraryA("win32u.dll");
	uintptr_t function = (uintptr_t)GetProcAddress(winlib, "NtTokenManagerCreateFlipObjectReturnTokenHandle");

	WCHAR user_event[0xFF] = L"\\BaseNamedObjects\\Global\\bruhmomentumuser";
	WCHAR kernel_event[0xFF] = L"\\BaseNamedObjects\\Global\\bruhmomentumkernel";

	HANDLE event_user = CreateEventW(NULL, FALSE, FALSE, &user_event[18]);
	HANDLE event_kernel = CreateEventW(NULL, FALSE, FALSE, &kernel_event[18]);

	test_stuff = new Info();
	test_stuff->type = 0xC0FFE;
	CreateThread(0, 0, (LPTHREAD_START_ROUTINE)function, test_stuff, 0, 0);
	WaitForSingleObject(event_kernel, 3 * 1000 * 60);
	printf("%x %x\n", event_user, event_kernel);


	test_stuff->type = 0x6969;
	SetEvent(event_user);
	WaitForSingleObject(event_kernel, 3 * 1000 * 60);

	test_stuff->type = 0x1337;
	SetEvent(event_user);
	WaitForSingleObject(event_kernel, 3 * 1000 * 60);

	test_stuff->type = 0x420;
	SetEvent(event_user);
	WaitForSingleObject(event_kernel, 3 * 1000 * 60);
	system("pause");
}