#include "includes.h"

KIRQL wp_off()
{
	KIRQL  irql = KeRaiseIrqlToDpcLevel();
	UINT64  cr0 = __readcr0();
	cr0 &= 0xfffffffffffeffff;
	__writecr0(cr0);
	_disable();
	return  irql;
}

void wp_on(KIRQL irql)
{
	UINT64 cr0 = __readcr0();
	cr0 |= 0x10000;
	_enable();
	__writecr0(cr0);
	KeLowerIrql(irql);
}

void mem::write_ro(uintptr_t dst, uintptr_t src, size_t size) {
	KIRQL irql = wp_off();
	memcpy((void*)dst, (void*)src, size);
	wp_on(irql);
}