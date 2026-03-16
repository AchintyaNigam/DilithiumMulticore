#include "mem_profile.h"
#include <stdio.h>
#include <stdint.h>
#include <malloc.h>

extern char* sbrk(int incr);

/* Linker-provided symbol: top of stack */
extern uint32_t __StackTop;

static uint32_t max_stack_usage_core0 = 0;

void check_stack_usage_core0(void) {
    uint32_t sp;
    asm volatile("mov %0, sp" : "=r"(sp));

    uint32_t stack_top = (uint32_t)&__StackTop;
    uint32_t usage = stack_top - sp;

    if (usage > max_stack_usage_core0)
        max_stack_usage_core0 = usage;
}

//Sanity Check
// void check_stack_usage_core0(void) {
//     uint32_t sp;
//     asm volatile("mov %0, sp" : "=r"(sp));

//     printf("SP = 0x%08X\n", sp);
// }


void print_stack_usage_core0(void) {
    printf("Core0 max stack usage: %u bytes\n", max_stack_usage_core0);
}

void print_ram_usage(void) {
    printf("Heap end addr: %p\n", sbrk(0));
}
