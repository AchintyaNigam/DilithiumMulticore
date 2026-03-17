#include "mem_profile.h"
#include <stdio.h>
#include <stdint.h>
#include <malloc.h>

extern char* sbrk(int incr);

/* Linker-provided symbol: top of stack (Core0) */
extern uint32_t __StackTop;

/* Peak stack trackers */
static uint32_t max_stack_usage_core0 = 0;
volatile uint32_t max_stack_usage_core1 = 0;

/* =========================
   Core0 stack tracking
   ========================= */
void check_stack_usage_core0(void) {
    uint32_t sp;
    asm volatile("mov %0, sp" : "=r"(sp));

    uint32_t stack_top = (uint32_t)&__StackTop;
    uint32_t usage = stack_top - sp;

    if (usage > max_stack_usage_core0)
        max_stack_usage_core0 = usage;
}

/* =========================
   Core1 stack tracking
   ========================= */
void check_stack_usage_core1(void) {
    uint32_t sp;
    asm volatile("mov %0, sp" : "=r"(sp));

    /*
      Core1 stack top is typically same SRAM end.
      Using same symbol works in RP2040 because both
      stacks grow down from high memory.
    */
    uint32_t stack_top = (uint32_t)&__StackTop;
    uint32_t usage = stack_top - sp;

    if (usage > max_stack_usage_core1)
        max_stack_usage_core1 = usage;
}

/* =========================
   Reporting
   ========================= */
void print_stack_usage_core0(void) {
    printf("Core0 max stack usage: %u bytes\n", max_stack_usage_core0);
}

void print_stack_usage_core1(void) {
    printf("Core1 max stack usage: %u bytes\n", max_stack_usage_core1);
}

void print_ram_usage(void) {
    printf("Heap end addr: %p\n", sbrk(0));
}
