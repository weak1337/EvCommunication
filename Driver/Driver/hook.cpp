#include "includes.h"


void Hook::initialize(uintptr_t to_hook, uintptr_t handler) {
	this->address_original = to_hook;
	this->address_handler = handler;
	memcpy((void*)this->original, (void*)to_hook, sizeof(this->original));
	*(uintptr_t*)(&this->jmp[2]) = this->address_handler;
}
void Hook::hook_do() {
	mem::write_ro(this->address_original, (uintptr_t)this->jmp, sizeof(this->jmp));
	DbgPrint("Function hooked\n");
}
void Hook::hook_undo() {
	mem::write_ro(this->address_original, (uintptr_t)this->original, sizeof(this->original));
	DbgPrint("Function unhooked\n");
}