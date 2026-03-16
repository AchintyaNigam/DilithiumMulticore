#ifndef MEM_PROFILE_H
#define MEM_PROFILE_H

#include <stdint.h>

extern volatile uint32_t core1_stack_max;

void check_stack_usage_core0(void);
void print_stack_usage_core0(void);
void print_ram_usage(void);

#endif
