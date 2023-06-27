#include <stdio.h>
#include <rthw.h>
#include <rtthread.h>
#include <soc.h>

#include "rt_board.h"
#include "board.h"
#include <yoc/yoc.h>

extern void board_yoc_init(void);

/* auto define heap size */
extern size_t __heap_start;
extern size_t __heap_end;

int pre_main(void)
{
    rt_hw_interrupt_disable();
    extern void entry(void);
    entry();
    return 0;
}

void rt_hw_board_init(void)
{
    /* initalize interrupt */
    rt_hw_interrupt_init();

    // k_mm_init();
#ifdef RT_USING_HEAP
    /* initialize memory system */
    rt_system_heap_init(RT_HW_HEAP_BEGIN, RT_HW_HEAP_END);
#endif
#ifdef RT_USING_COMPONENTS_INIT
    rt_components_board_init();
#endif
    // int hart = 1;
    // while (hart);

    // aos_init();
    soc_hw_timer_init();

    cxx_system_init();
    board_yoc_init();
}

extern int32_t aos_debug_printf(const char *fmt, ...);
void rt_hw_console_output(const char *str)
{
    aos_debug_printf("%s\r", str);
}
