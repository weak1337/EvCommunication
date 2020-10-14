class Hook {
private:
	uintptr_t address_original;
	uintptr_t address_handler;
	BYTE original[12];
	BYTE jmp[12] = { 0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xE0 };
public:
	void initialize(uintptr_t to_hook, uintptr_t handler);
	void hook_do();
	void hook_undo();

};