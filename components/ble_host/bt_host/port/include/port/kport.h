/*
 * Copyright (C) 2015-2017 Alibaba Group Holding Limited
 */

#ifndef KPORT_H
#define KPORT_H

#define _POLL_EVENT_OBJ_INIT(obj) \
    .poll_events = SYS_DLIST_STATIC_INIT(&obj.poll_events),
#define _POLL_EVENT sys_dlist_t poll_events


#define _K_SEM_INITIALIZER(obj, initial_count, count_limit) \
    {}

#define K_SEM_INITIALIZER DEPRECATED_MACRO _K_SEM_INITIALIZER

#define K_SEM_DEFINE(name, initial_count, count_limit)     \
    struct k_sem name __in_section(data._k_sem, static, name) = \
            _K_SEM_INITIALIZER(name, initial_count, count_limit)


#define _K_MUTEX_INITIALIZER(obj) \
    {                             \
        0                         \
    }

#define K_MUTEX_INITIALIZER DEPRECATED_MACRO _K_MUTEX_INITIALIZER

#define K_MUTEX_DEFINE(name)                                   \
    struct k_mutex name __in_section(_k_mutex, static, name) = \
            _K_MUTEX_INITIALIZER(name)

#ifndef UINT_MAX
#define UINT_MAX (~0U)
#endif

#ifdef CONFIG_OBJECT_TRACING
#define _OBJECT_TRACING_NEXT_PTR(type) struct type *__next
#define _OBJECT_TRACING_INIT .__next = NULL,
#else
#define _OBJECT_TRACING_INIT
#define _OBJECT_TRACING_NEXT_PTR(type)
#endif

#ifndef _SSIZE_T_DECLARED
typedef long ssize_t;
#define _SSIZE_T_DECLARED
#endif

typedef sys_dlist_t _wait_q_t;

/*attention: this is intialied as zero,the queue variable shoule use
 * k_queue_init\k_lifo_init\k_fifo_init again*/
#if defined(CONFIG_BT_HOST_OPTIMIZE) && CONFIG_BT_HOST_OPTIMIZE
#define _K_QUEUE_INITIALIZER(obj) \
    {                             \
       SYS_SLIST_STATIC_INIT(&obj.queue_list), \
       SYS_DLIST_STATIC_INIT(&obj.poll_events), \
    }
#else
#define _K_QUEUE_INITIALIZER(obj) \
    {                             \
        {                         \
            {                     \
                {                 \
                    0             \
                }                 \
            }                     \
        }                         \
    }
#endif
#define K_QUEUE_INITIALIZER DEPRECATED_MACRO _K_QUEUE_INITIALIZER

#define Z_WORK_INITIALIZER(work_handler) \
	{ \
	._reserved = NULL, \
	.handler = work_handler, \
	.flags = { 0 } \
	}

#define _K_LIFO_INITIALIZER(obj)                   \
    {                                              \
        ._queue = _K_QUEUE_INITIALIZER(obj._queue) \
    }

#define K_LIFO_INITIALIZER DEPRECATED_MACRO _K_LIFO_INITIALIZER

#define K_LIFO_DEFINE(name)                                   \
    struct k_lifo name __in_section(_k_queue, static, name) = \
            _K_LIFO_INITIALIZER(name)

#define _K_FIFO_INITIALIZER(obj)                   \
    {                                              \
        ._queue = _K_QUEUE_INITIALIZER(obj._queue) \
    }
#define K_FIFO_INITIALIZER DEPRECATED_MACRO _K_FIFO_INITIALIZER

#define K_FIFO_DEFINE(name)                                   \
    struct kfifo name __in_section(_k_queue, static, name) = \
            _K_FIFO_INITIALIZER(name)

struct k_thread {
    _task_t task;
};

typedef _stack_element_t k_thread_stack_t;

#define K_THREAD_STACK_DEFINE(sym, size) _stack_element_t sym[size]
#define K_THREAD_STACK_SIZEOF(sym) (sizeof(sym) / sizeof(_stack_element_t))

typedef void (*k_thread_entry_t)(void *arg);
/**
 * @brief Spawn a thread.
 *
 * This routine initializes a thread, then schedules it for execution.
 *
 * @param thread Thread data
 * @param name  Thread name
 * @param stack Pointer to the stack space.
 * @param stack_size Stack size in bytes.
 * @param fn Thread entry function.
 * @param arg entry point parameter.
 * @param prio Thread priority.
 *
 * @return 0 success.
 */
int k_thread_spawn(struct k_thread *thread, const char *name, uint32_t *stack, uint32_t stack_size, \
                   k_thread_entry_t fn, void *arg, int prio);


/**
 * @brief Yield the current thread.
 *
 * This routine causes the current thread to yield execution to another
 * thread of the same or higher priority. If there are no other ready threads
 * of the same or higher priority, the routine returns immediately.
 *
 * @return N/A
 */
int k_yield();

/**
 * @brief Lock interrupts.
 *
 * This routine disables all interrupts on the CPU. It returns an unsigned
 * integer "lock-out key", which is an architecture-dependent indicator of
 * whether interrupts were locked prior to the call. The lock-out key must be
 * passed to irq_unlock() to re-enable interrupts.
 *
 * @return Lock-out key.
 */
unsigned int irq_lock();

/**
 * @brief Unlock interrupts.
 *
 * This routine reverses the effect of a previous call to irq_lock() using
 * the associated lock-out key. The caller must call the routine once for
 * each time it called irq_lock(), supplying the keys in the reverse order
 * they were acquired, before interrupts are enabled.
 *
 * @param key Lock-out key generated by irq_lock().
 *
 * @return N/A
 */
void irq_unlock(unsigned int key);

#ifndef BIT
#define BIT(n) (1UL << (n))
#endif

#ifndef CONFIG_NET_BUF_WARN_ALLOC_INTERVAL
#define CONFIG_NET_BUF_WARN_ALLOC_INTERVAL 1
#endif
#ifndef CONFIG_HEAP_MEM_POOL_SIZE
#define CONFIG_HEAP_MEM_POOL_SIZE 1
#endif

#define SYS_TRACING_OBJ_INIT(name, obj) \
    do {                                \
    } while ((0))

static inline int k_is_in_isr()
{
    //uint32_t vec = (__get_PSR() & PSR_VEC_Msk) >> PSR_VEC_Pos;
    return 0;
}
#endif /* KPORT_H */
