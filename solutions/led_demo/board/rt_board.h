#ifndef RT_BOARD_H__
#define RT_BOARD_H__

#include <rtthread.h>

extern size_t __heap_start;
extern size_t __heap_end;

#define RAM_SIZE (64 * 1024 * 1024)
#define RAM_BASE (0x40040000)
#define RAM_END (RAM_BASE + RAM_SIZE)

#define RT_HW_HEAP_BEGIN ((void *)&__heap_start)
#define RT_HW_HEAP_END ((void *)(RAM_END))

void rt_hw_board_init(void);
void rt_init_user_mem(struct rt_thread *thread, const char *name, unsigned long *entry);

#endif