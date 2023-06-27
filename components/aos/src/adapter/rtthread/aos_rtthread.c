/*
 * Copyright (C) 2019-2020 Alibaba Group Holding Limited
 */
#include <string.h>
#include <stdlib.h>
#include <sys/time.h>

#include <rtthread.h>
#include <aos/aos.h>
#include <drv/irq.h>

#define AOS_MIN_STACK_SIZE       64
#if (RHINO_CONFIG_KOBJ_DYN_ALLOC == 0)
#warning "RHINO_CONFIG_KOBJ_DYN_ALLOC is disabled!"
#endif

static unsigned int used_bitmap;
static long long start_time_ms = 0;

extern volatile rt_uint8_t rt_interrupt_nest;

static volatile rt_uint8_t mutex_index = 0;
static volatile rt_uint8_t event_index = 0;
static volatile rt_uint8_t sem_index = 0;
static volatile rt_uint8_t mq_index = 0;

static int rhino2stderrno(int ret)
{
    switch (ret) {
    case RT_EOK:
        return 0;
    default:
        return -1;
    }

    return -1;
}

/* imp in watchdog.c */
//int aos_reboot(void)
int aos_get_hz(void)
{
    return RT_TICK_PER_SECOND;
}

const char *aos_version_get(void)
{
    return aos_get_os_version();
}

aos_status_t aos_task_create(aos_task_t *task, const char *name, void (*fn)(void *),
                             void *arg, void *stack, size_t stack_size, int32_t prio, uint32_t options)
{
    rt_thread_t ret;

    ret = rt_thread_create(name, fn, arg, stack_size,
                                      prio, 10u);

    return rhino2stderrno(ret);
}

aos_status_t aos_task_suspend(aos_task_t *task)
{
    int ret;
    rt_thread_t ktask;

    ktask = task->hdl;
    ret = rt_thread_suspend(ktask);

    return rhino2stderrno(ret);
}

aos_status_t aos_task_resume(aos_task_t *task)
{
    int ret;
    rt_thread_t ktask;

    ktask = task->hdl;
    ret = rt_thread_resume(ktask);

    return rhino2stderrno(ret);
}

aos_status_t aos_task_delete(aos_task_t *task)
{
    int ret;
    rt_thread_t ktask;

    ktask = task->hdl;

    ret = (int)rt_thread_delete(ktask);

    return rhino2stderrno(ret);
}

int aos_task_new(const char *name, void (*fn)(void *), void *arg,
                 int stack_size)
{
    return aos_task_new_ext(NULL, name, fn, arg, stack_size, AOS_DEFAULT_APP_PRI);
}

int aos_task_new_ext(aos_task_t *task, const char *name, void (*fn)(void *), void *arg,
                     int stack_size, int prio)
{
    int ret;

    aos_check_return_einval(task && fn && (stack_size >= AOS_MIN_STACK_SIZE) &&
                            (prio >= 0 && prio < RT_THREAD_PRIORITY_MAX));

    ret = rt_thread_create(name, fn, arg, stack_size,
                                      AOS_DEFAULT_APP_PRI, 10u);

    return 0;
}

void aos_task_wdt_attach(void (*will)(void *), void *args)
{
#ifdef CONFIG_SOFTWDT
    aos_wdt_attach((uint32_t)krhino_cur_task_get(), will, args);
#else
    (void)will;
    (void)args;
#endif
}

void aos_task_wdt_detach()
{
#ifdef CONFIG_SOFTWDT
    uint32_t index = (uint32_t)krhino_cur_task_get();

    aos_wdt_feed(index, 0);
    aos_wdt_detach(index);
#endif
}

void aos_task_wdt_feed(int time)
{
#ifdef CONFIG_SOFTWDT
    ktask_t *task = krhino_cur_task_get();

    if (!aos_wdt_exists((uint32_t)task))
        aos_wdt_attach((uint32_t)task, NULL, (void*)task->task_name);

    aos_wdt_feed((uint32_t)task, time);
#endif
}

void aos_task_exit(int code)
{
    (void)code;

    rt_thread_t handle;
    handle = rt_thread_self();
    rt_thread_delete(handle);
}

aos_task_t aos_task_self(void)
{
    aos_task_t task;
    task.hdl = (rt_thread_t *)rt_thread_self();

    return task;
}

const char *aos_task_name(void)
{
    return rt_thread_self()->parent.name;
}

const char *aos_task_get_name(aos_task_t *task)
{
    return rt_thread_self()->parent.name;
}

int aos_task_key_create(aos_task_key_t *key)
{
    return -1;
}

void aos_task_key_delete(aos_task_key_t key)
{

}

aos_status_t aos_task_setspecific(aos_task_key_t key, void *vp)
{
    return 0;
}

void *aos_task_getspecific(aos_task_key_t key)
{
    return NULL;
}

int aos_mutex_new(aos_mutex_t *mutex)
{
    char name[RT_NAME_MAX] = {0};
    rt_snprintf(name, RT_NAME_MAX, "mutex%02d", mutex_index++ );

    rt_sem_t  mux = rt_mutex_create(name, RT_IPC_FLAG_PRIO);
    mutex->hdl = mux;
    return mux != NULL ? 0 : -1;
}

void aos_mutex_free(aos_mutex_t *mutex)
{
    rt_mutex_delete(mutex->hdl);
}

int aos_mutex_lock(aos_mutex_t *mutex, unsigned int timeout)
{
    if (timeout == AOS_WAIT_FOREVER) {
        rt_mutex_take(mutex->hdl, timeout);
    } else {
        rt_mutex_take(mutex->hdl, rt_tick_from_millisecond(timeout));
    }

    return 0;
}

int aos_mutex_unlock(aos_mutex_t *mutex)
{
    if (mutex == NULL && mutex->hdl) {
        return;
    }
    rt_mutex_release(mutex->hdl);

    return 0;
}

int aos_mutex_is_valid(aos_mutex_t *mutex)
{
    return mutex->hdl != NULL;
}

aos_status_t aos_sem_create(aos_sem_t *sem, uint32_t count, uint32_t options)
{
    (void)options;

    char name[RT_NAME_MAX] = {0};
    rt_snprintf(name, RT_NAME_MAX, "sem%02d", sem_index++);

    rt_sem_t s = rt_sem_create(name, 0, RT_IPC_FLAG_PRIO);
    sem->hdl = s;
    return 0;
}

int aos_sem_new(aos_sem_t *sem, int count)
{
    char name[RT_NAME_MAX] = {0};
    rt_snprintf(name, RT_NAME_MAX, "sem%02d", sem_index++);

    rt_sem_t s = rt_sem_create(name, count, RT_IPC_FLAG_PRIO);
    sem->hdl = s;
    return 0;
}

void aos_sem_free(aos_sem_t *sem)
{
    if (sem == NULL || sem->hdl ) {
        return;
    }

    rt_sem_release(sem->hdl);
}

int aos_sem_wait(aos_sem_t *sem, unsigned int timeout)
{
    if (sem == NULL) {
        return -1;
    }

    if (timeout == AOS_WAIT_FOREVER) {
        rt_sem_take(sem->hdl, timeout);
    } else {
        rt_sem_take(sem->hdl, rt_tick_from_millisecond(timeout));
    }
    return 0;
}

void aos_sem_signal(aos_sem_t *sem)
{
    if (sem == NULL && sem->hdl) {
        return;
    }
    rt_sem_release(sem->hdl);
}

void aos_sem_signal_all(aos_sem_t *sem)
{
    
}

int aos_sem_is_valid(aos_sem_t *sem)
{
    return sem && sem->hdl != NULL;
}

int aos_event_new(aos_event_t *event, unsigned int flags)
{
    rt_base_t level;
    rt_event_t event_handle;
    char name[RT_NAME_MAX] = {0};

    aos_check_return_einval(event);

    rt_snprintf(name, RT_NAME_MAX, "event%02d", event_index++ );
    event_handle = rt_event_create(name, RT_IPC_FLAG_PRIO);
    // /* initlized event */
    // if(event_handle != NULL) {
    //     rt_event_send(event, (uint32_t ) flags);
    // } else {
    //     return -1;
    // }
    event->hdl = event_handle;
    return 0;
}

void aos_event_free(aos_event_t *event)
{
    aos_check_return(event && event->hdl);

    rt_event_delete(event->hdl);

    event->hdl = NULL;
}

int aos_event_get
(
    aos_event_t *event,
    unsigned int flags,
    unsigned char opt,
    unsigned int *actl_flags,
    unsigned int timeout
)
{
    uint32_t wait_bits = 0;
    uint8_t option = 0;
    rt_uint32_t recved;
    rt_base_t level;
    rt_err_t err;

    aos_check_return_einval(event && event->hdl);

    switch (opt)
    {
    case AOS_EVENT_AND:
        option |= RT_EVENT_FLAG_AND;
        break;
    case AOS_EVENT_AND_CLEAR:
        option |= RT_EVENT_FLAG_AND;
        option |= RT_EVENT_FLAG_CLEAR;
        break;
    case AOS_EVENT_OR:
        option |= RT_EVENT_FLAG_OR;
        break;
    case AOS_EVENT_OR_CLEAR:
        option |= RT_EVENT_FLAG_OR;
        option |= RT_EVENT_FLAG_CLEAR;
        break;
    default:
        break;
    }

    if (timeout == AOS_WAIT_FOREVER) {
        wait_bits = rt_event_recv(event->hdl,
                                        flags,
                                        option,
                                        timeout,
                                        &recved);
    } else {
        wait_bits=  rt_event_recv(event->hdl,
                                        flags,
                                        option,
                                        rt_tick_from_millisecond(timeout),
                                        &recved);
    }
    if ( err != RT_EOK )
    {
        level = rt_hw_interrupt_disable();
        rt_event_t ptr = event->hdl;
        recved = ptr->set;
        rt_hw_interrupt_enable(level);
    }

    *actl_flags = wait_bits;
    return 0;
}

int aos_event_set(aos_event_t *event, unsigned int flags, unsigned char opt)
{
    aos_check_return_einval(event && event->hdl);
    
    rt_event_send(event->hdl, ( rt_uint32_t ) flags);

    return 0;
}

int aos_event_is_valid(aos_event_t *event)
{
    rt_event_t k_event;

    if (event == NULL) {
        return 0;
    }

    k_event = event->hdl;

    if (k_event == NULL) {
        return 0;
    }

    return 1;
}

aos_status_t aos_queue_create(aos_queue_t *queue, size_t size, size_t max_msg, uint32_t options)
{
    size_t       malloc_len;
    void        *real_buf;
    rt_mq_t     q;

    (void)options;
    if (queue == NULL || size == 0) {
        return -EINVAL;
    }

    char name[RT_NAME_MAX] = {0};
    rt_snprintf(name, RT_NAME_MAX, "mq%02d", mq_index++ );
    q = rt_mq_create(name, size / max_msg, max_msg, RT_IPC_FLAG_PRIO);

    queue->hdl = q;

    return 0;
}

int aos_queue_new(aos_queue_t *queue, void *buf, size_t size, int max_msg)
{
    rt_mq_t q;
    (void)(buf);
    /* verify param */
    if(queue == NULL || size == 0) {
        return -1;
    }

    /* create queue object */
    char name[RT_NAME_MAX] = {0};
    rt_snprintf(name, RT_NAME_MAX, "mq%02d", mq_index++ );
    q = rt_mq_create(name, size / max_msg, max_msg, RT_IPC_FLAG_PRIO);
    if(q == NULL) {
        return -1;
    }
    queue->hdl = q;

    return 0;
}

void aos_queue_free(aos_queue_t *queue)
{
    aos_check_return(queue && queue->hdl);

    krhino_buf_queue_del(queue->hdl);

    aos_free(queue->hdl);

    queue->hdl = NULL;
}

int aos_queue_send(aos_queue_t *queue, void *msg, size_t size)
{
    /* delete queue object */
    if(queue && queue->hdl) {
        rt_mq_delete(queue->hdl);
    }

    return;
}

int aos_queue_recv(aos_queue_t *queue, unsigned int ms, void *msg, size_t *size)
{
    /* verify param */
    if(queue == NULL || msg == NULL || size == 0 ) {
        return -1;
    }

    /* receive msg from specific queue */
    return rt_mq_recv(queue->hdl, msg, (size_t *)size, ms == AOS_WAIT_FOREVER ? RT_WAITING_FOREVER : rt_tick_from_millisecond(ms));
}

int aos_queue_is_valid(aos_queue_t *queue)
{
    return queue && queue->hdl != NULL;
}

void *aos_queue_buf_ptr(aos_queue_t *queue)
{
    (void)queue;
    return NULL;
}

int aos_queue_get_count(aos_queue_t *queue)
{
    rt_ubase_t uxReturn = 0;
    struct rt_ipc_object *pipc;
    rt_uint8_t type;
    rt_base_t level;

    pipc = queue->hdl;
    RT_ASSERT( pipc != RT_NULL );
    type = rt_object_get_type(&pipc->parent);

    level = rt_hw_interrupt_disable();

    if ( type == RT_Object_Class_Mutex )
    {
        if (((rt_mutex_t)pipc)->owner == RT_NULL )
        {
            uxReturn = 1;
        }
        else
        {
            uxReturn = 0;
        }
    }
    else if ( type == RT_Object_Class_Semaphore )
    {
        uxReturn = ((rt_sem_t)pipc)->value;
    }
    else if ( type == RT_Object_Class_MessageQueue )
    {
        uxReturn = ((rt_mq_t)pipc)->entry;
    }

    rt_hw_interrupt_enable(level);

    return uxReturn;
}

typedef struct tmr_adapter {
    rt_timer_t timer;
    void (*func)(void *, void *);
    void *func_arg;
    uint8_t bIsRepeat;
} tmr_adapter_t;

int aos_timer_new(aos_timer_t *timer, void (*fn)(void *, void *),
                  void *arg, int ms, int repeat)
{
    return aos_timer_new_ext(timer, fn, arg, ms, repeat, 1);
}

int aos_timer_new_ext(aos_timer_t *timer, void (*fn)(void *, void *),
                      void *arg, int ms, int repeat, unsigned char auto_run)
{
    /* verify param */
    if (timer == NULL || ms == 0 || fn == NULL) {
        return -1;
    }

    // /* create timer wrap object ,then initlize timer object */
    // tmr_adapter_t *tmr_adapter = pvPortMalloc(sizeof(tmr_adapter_t));

    // if (tmr_adapter == NULL) {
    //     return -1;
    // }

    // tmr_adapter->func = fn;
    // tmr_adapter->func_arg = arg;
    // tmr_adapter->bIsRepeat = repeat;

    // /* create timer by kernel api */
    // TimerHandle_t ptimer = rt_timer_create("Timer", rt_tick_from_millisecond(ms), repeat, tmr_adapter, tmr_adapt_cb);

    // if (timer == NULL) {
    //     vPortFree(tmr_adapter);
    //     return -1;
    // }

    // tmr_adapter->timer = ptimer;
    // timer->hdl = (void*)tmr_adapter;

    // /* start timer if auto_run == TRUE */
    // if(auto_run) {
    //     if(aos_timer_start(timer) != 0) {
    //         return -1;
    //     }
    // }

    return 0;
}

void aos_timer_free(aos_timer_t *timer)
{
    aos_check_return(timer && timer->hdl);

    rt_timer_delete(timer->hdl);
    timer->hdl = NULL;
}

int aos_timer_start(aos_timer_t *timer)
{
    int ret;

    aos_check_return_einval(timer && timer->hdl);

    ret = rt_timer_start(timer->hdl);

    return 0;
}

int aos_timer_stop(aos_timer_t *timer)
{
    int ret;

    aos_check_return_einval(timer && timer->hdl);

    ret = rt_timer_stop(timer->hdl);

    return 0;
}

int aos_timer_change(aos_timer_t *timer, int ms)
{
    int ret;

    aos_check_return_einval(timer && timer->hdl);

    return 0;
}

int aos_timer_change_once(aos_timer_t *timer, int ms)
{
    int ret;

    aos_check_return_einval(timer && timer->hdl);

    return 0;
}

int aos_timer_is_valid(aos_timer_t *timer)
{
    return 1;
}

int aos_timer_gettime(aos_timer_t *timer, uint64_t value[4])
{

    return 0;
}

#if (RHINO_CONFIG_WORKQUEUE  > 0)
int aos_workqueue_create(aos_workqueue_t *workqueue, int pri, int stack_size)
{
    kstat_t ret;

    aos_check_return_einval(workqueue && stack_size >= AOS_MIN_STACK_SIZE);

    workqueue->hdl = (cpu_stack_t *)aos_malloc(sizeof(kworkqueue_t) + stack_size);

    if (workqueue->hdl == NULL) {
        return -ENOMEM;
    }

    workqueue->stk = (cpu_stack_t*)((char *)workqueue->hdl + sizeof(kworkqueue_t));

    ret = krhino_workqueue_create(workqueue->hdl, "AOS", pri, workqueue->stk,
                                  stack_size / sizeof(cpu_stack_t));

    if (ret != RHINO_SUCCESS) {
        aos_free(workqueue->hdl);
        workqueue->hdl = NULL;
        workqueue->stk = NULL;
    }

    return rhino2stderrno(ret);
}

int aos_workqueue_create_ext(aos_workqueue_t *workqueue, const char *name, int pri, int stack_size)
{
    kstat_t ret;

    aos_check_return_einval(workqueue && name);

    workqueue->hdl = (cpu_stack_t *)aos_malloc(sizeof(kworkqueue_t) + stack_size);

    if (workqueue->hdl == NULL) {
        return -ENOMEM;
    }

    workqueue->stk = (cpu_stack_t*)((char *)workqueue->hdl + sizeof(kworkqueue_t));

    ret = krhino_workqueue_create(workqueue->hdl, name, pri, workqueue->stk,
                                  stack_size / sizeof(cpu_stack_t));

    if (ret != RHINO_SUCCESS) {
        aos_free(workqueue->hdl);
        workqueue->hdl = NULL;
        workqueue->stk = NULL;
    }

    return rhino2stderrno(ret);
}

void aos_workqueue_del(aos_workqueue_t *workqueue)
{
    aos_check_return(workqueue && workqueue->hdl && workqueue->stk);

    krhino_workqueue_del(workqueue->hdl);
    aos_free(workqueue->hdl);
}

int aos_work_init(aos_work_t *work, void (*fn)(void *), void *arg, int dly)
{
    kstat_t  ret;
    //kwork_t *w;

    aos_check_return_einval(work);

    work->hdl = aos_malloc(sizeof(kwork_t));

    if (work->hdl == NULL) {
        return -ENOMEM;
    }

    ret = krhino_work_init(work->hdl, fn, arg, MS2TICK(dly));

    if (ret != RHINO_SUCCESS) {
        aos_free(work->hdl);
        work->hdl = NULL;

    }

    return rhino2stderrno(ret);
}

void aos_work_destroy(aos_work_t *work)
{
    kwork_t *w;

    if (work == NULL) {
        return;
    }

    w = work->hdl;

    if (w->timer != NULL) {
        krhino_timer_stop(w->timer);
        krhino_timer_dyn_del(w->timer);
    }

    aos_free(work->hdl);
    work->hdl = NULL;
}

int aos_work_run(aos_workqueue_t *workqueue, aos_work_t *work)
{
    int ret;

    if ((workqueue == NULL) || (work == NULL)) {
        return -EINVAL;
    }

    ret = krhino_work_run(workqueue->hdl, work->hdl);

    return rhino2stderrno(ret);
}

int aos_work_sched(aos_work_t *work)
{
    int ret;

    if (work == NULL) {
        return -EINVAL;
    }

    ret = krhino_work_sched(work->hdl);

    return rhino2stderrno(ret);
}

int aos_work_cancel(aos_work_t *work)
{
    int ret;

    if (work == NULL) {
        return -EINVAL;
    }

    ret = krhino_work_cancel(work->hdl);

    if (ret != RHINO_SUCCESS) {
        return -EBUSY;
    }

    return 0;
}
#endif

long long aos_now(void)
{
    return aos_now_ms() * 1000 * 1000;
}

long long aos_now_ms(void)
{
    return krhino_sys_time_get();
}

void aos_msleep(int ms)
{
    rt_thread_mdelay(ms);
}

static void trap_c_cb()
{
    aos_except_process(EPERM, NULL, 0, NULL, NULL);
}

extern void (*trap_c_callback)();


void aos_init(void)
{
    krhino_init();

    // intercept trap_c
    trap_c_callback = trap_c_cb;
}

void aos_start(void)
{
    rtthread_startup();
}

k_status_t aos_kernel_intrpt_enter(void)
{
    rt_base_t level;

    level = rt_hw_interrupt_disable();
    rt_interrupt_nest ++;
    rt_hw_interrupt_enable(level);

    return 0;
}

k_status_t aos_kernel_intrpt_exit(void)
{
    rt_base_t level;

    level = rt_hw_interrupt_disable();
    rt_interrupt_nest --;
    rt_hw_interrupt_enable(level);
    return 0;
}

/* YoC extend aos API */

int aos_get_mminfo(int32_t *total, int32_t *used, int32_t *mfree, int32_t *peak)
{
    aos_check_return_einval(total && used && mfree && peak);
    //todo
    *total = 0;
    *used =  0;
    *mfree = 0;
    *peak =  0;

    return 0;
}

int aos_mm_dump(void)
{
#if defined(CONFIG_DEBUG) && defined(CONFIG_DEBUG_MM)
    dumpsys_mm_info_func(0);
#endif

    return 0;
}

static int aos_task_list(void *task_array, uint32_t array_items)
{
    if (task_array == NULL || array_items == 0) {
        return 0;
    }

    uint32_t real_tsk_num = 0;
    return real_tsk_num;
}

static uint32_t aos_task_get_stack_space(void *task_handle)
{
    if (task_handle == NULL) {
        return 0;
    }

    size_t stack_free;
    stack_free = rt_thread_self()->stack_size;

    return (uint32_t)(4 * stack_free);
}

uint32_t TaskGetNumbers( void )
{
    uint32_t uxReturn = 0;
    rt_base_t level;
    struct rt_object_information *information;
    struct rt_list_node *node = RT_NULL;

    information = rt_object_get_information( RT_Object_Class_Thread );
    RT_ASSERT( information != RT_NULL );

    level = rt_hw_interrupt_disable();

    rt_list_for_each( node, &( information->object_list ) )
    {
        uxReturn += 1;
    }

    rt_hw_interrupt_enable( level );

    return uxReturn;
}

void aos_task_show_info(void)
{

}

/// Suspend the scheduler.
/// \return time in ticks, for how long the system can sleep or power-down.
void aos_kernel_sched_suspend(void)
{
    rt_enter_critical();
}

/// Resume the scheduler.
/// \param[in]     sleep_ticks   time in ticks for how long the system was in sleep or power-down mode.
void aos_kernel_sched_resume()
{
    rt_exit_critical();
}

void aos_task_yield()
{
    rt_thread_yield();
}

void aos_reboot_ext(int cmd)
{
    extern void drv_reboot(int cmd);
    drv_reboot(cmd);
}

void aos_reboot(void)
{
    aos_reboot_ext(0);
}

#define RHINO_OS_MS_PERIOD_TICK      (1000 / RT_TICK_PER_SECOND)
uint64_t aos_kernel_tick2ms(uint32_t ticks)
{
    return ((uint64_t)ticks * RHINO_OS_MS_PERIOD_TICK);
}

uint64_t aos_kernel_ms2tick(uint32_t ms)
{
    if (ms < RHINO_OS_MS_PERIOD_TICK) {
        return 0;
    }

    return (((uint64_t)ms) / RHINO_OS_MS_PERIOD_TICK);
}

int32_t aos_kernel_suspend(void)
{
    return 0;
}

void aos_kernel_resume(int32_t ticks)
{

}

int32_t aos_irq_context(void)
{
    return rt_interrupt_nest;
}

void *aos_zalloc(size_t size)
{
    void *tmp = NULL;

    if (size == 0) {
        return NULL;
    }

    tmp = rt_malloc(size);
    if (tmp) {
        rt_memset(tmp, 0, size);
    }

    return tmp;
}

void *aos_malloc(size_t size)
{
    void *tmp = NULL;

    if (size == 0) {
        return NULL;
    }

    tmp = rt_malloc(size);

    return tmp;
}

void *aos_calloc(size_t nitems, size_t size)
{
    void *tmp = NULL;

    tmp = rt_calloc(size, nitems);

    return tmp;
}

void *aos_realloc(void *mem, size_t size)
{
    void *tmp = NULL;

    tmp = rt_realloc(mem, size);
    return tmp;
}

void *aos_zalloc_check(size_t size)
{
    void *ptr = rt_malloc(size);

    aos_check_mem(ptr);
    if (ptr) {
        rt_memset(ptr, 0, size);
    }

    return ptr;
}

void aos_alloc_trace(void *addr, uintptr_t allocator)
{

}

void aos_free(void *mem)
{
    if (mem == NULL) {
        return;
    }

    rt_free(mem);
}

void aos_calendar_time_set(uint64_t now_ms)
{
    start_time_ms = now_ms - rt_tick_get_millisecond();
}

uint64_t aos_calendar_time_get(void)
{
    return rt_tick_get_millisecond() + start_time_ms;
}

uint64_t aos_calendar_localtime_get(void)
{
    if ((aos_calendar_time_get() - 8 * 3600 * 1000) < 0) {
        return aos_calendar_time_get();
    }
    return aos_calendar_time_get() + 8 * 3600 * 1000;
}

void *aos_malloc_check(size_t size)
{
    void *p = aos_malloc(size);
    aos_check_mem(p);

    return p;
}

void *aos_calloc_check(size_t size, size_t num)
{
    return aos_zalloc_check(size * num);
}

void *aos_realloc_check(void *ptr, size_t size)
{
    void *new_ptr = aos_realloc(ptr, size);
    aos_check_mem(new_ptr);

    return new_ptr;
}

void aos_freep(char **ptr)
{
    if (ptr && (*ptr)) {
        aos_free(*ptr);
        *ptr = NULL;
    }
}

aos_status_t aos_task_ptcb_get(aos_task_t *task, void **ptcb)
{
    return 0;
}

aos_status_t aos_task_ptcb_set(aos_task_t *task, void *ptcb)
{
    return 0;
}

aos_status_t aos_task_pri_change(aos_task_t *task, uint8_t pri, uint8_t *old_pri)
{
    return 0;
}

aos_status_t aos_task_pri_get(aos_task_t *task, uint8_t *priority)
{
    return 0;
}

aos_status_t aos_task_sched_policy_set(aos_task_t *task, uint8_t policy, uint8_t pri)
{
    return 0;
}

aos_status_t aos_task_sched_policy_get(aos_task_t *task, uint8_t *policy)
{
    return 0;
}

uint32_t aos_task_sched_policy_get_default()
{
    return 1;
}

aos_status_t aos_task_time_slice_set(aos_task_t *task, uint32_t slice)
{
    return 0;
}

aos_status_t aos_task_time_slice_get(aos_task_t *task, uint32_t *slice)
{
    return 0;
}

uint32_t aos_sched_get_priority_max(uint32_t policy)
{
    return RT_THREAD_PRIORITY_MAX;
}
