/* buf.c - Buffer management */

/*
 * Copyright (c) 2015 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <errno.h>
#include <stddef.h>
#include <string.h>
#include <ble_os.h>
#include <misc/byteorder.h>
#include <stdlib.h>
#include <net/buf.h>
#include <misc/util.h>
#include "common/log.h"

#if defined(CONFIG_NET_BUF_LOG)
#define SYS_LOG_DOMAIN "net/buf"
#define SYS_LOG_LEVEL CONFIG_SYS_LOG_NET_BUF_LEVEL
#include <common/log.h>

#define NET_BUF_DBG(fmt, ...) SYS_LOG_DBG("(%p) " fmt, k_current_get(), \
					  ##__VA_ARGS__)
#define NET_BUF_ERR(fmt, ...) SYS_LOG_ERR(fmt, ##__VA_ARGS__)
#define NET_BUF_WARN(fmt, ...) SYS_LOG_WRN(fmt,	##__VA_ARGS__)
#define NET_BUF_INFO(fmt, ...) SYS_LOG_INF(fmt,  ##__VA_ARGS__)
#define NET_BUF_ASSERT(cond) do { if (!(cond)) {			  \
			NET_BUF_ERR("assert: '" #cond "' failed"); \
		} } while (0)
#else

#define NET_BUF_DBG(fmt, ...)
#define NET_BUF_ERR(fmt, ...)
#define NET_BUF_WARN(fmt, ...)
#define NET_BUF_INFO(fmt, ...)
#define NET_BUF_ASSERT(cond)
#endif /* CONFIG_NET_BUF_LOG */

#if CONFIG_NET_BUF_WARN_ALLOC_INTERVAL > 0
#define WARN_ALLOC_INTERVAL K_SECONDS(CONFIG_NET_BUF_WARN_ALLOC_INTERVAL)
#else
#define WARN_ALLOC_INTERVAL K_FOREVER
#endif

#define MAX_POOL_LIST_SIZE (15)

/* Linker-defined symbol bound to the static pool structs */
//extern struct net_buf_pool _net_buf_pool_list[];
//extern struct net_buf_pool _net_buf_pool_list_end[];

static struct net_buf_pool* net_buf_pool_list[MAX_POOL_LIST_SIZE] = {0};
static struct net_buf_pool** net_buf_pool_list_end = net_buf_pool_list;


int net_buf_pool_init(struct net_buf_pool *pool)
{
    if (net_buf_pool_list_end >= net_buf_pool_list + MAX_POOL_LIST_SIZE)
    {
        return -1;
    }
    k_lifo_init(&pool->free);
    *net_buf_pool_list_end = pool;
    net_buf_pool_list_end++;
    return 0;
}

struct net_buf_pool *net_buf_pool_get(int id)
{
	return net_buf_pool_list[id];
}

static int pool_id(struct net_buf_pool *pool)
{
    int i = 0;
    for (i = 0; net_buf_pool_list[i] && i < net_buf_pool_list_end - net_buf_pool_list; i++)
    {
        if (net_buf_pool_list[i] == pool)
        {
            return i;
        }
    }
	return -1;
}

int net_buf_pool_is_free(int id)
{
    struct net_buf_pool *pool = net_buf_pool_get(id);
    return (pool->buf_count == pool->uninit_count + k_lifo_num_get(&pool->free));
}

int net_buf_poll_is_all_free()
{
    int count = net_buf_pool_list_end - net_buf_pool_list;
    while(count)
    {
        if (!net_buf_pool_is_free(count - 1))
        {
            return 0;
        }
        count--;
    }
    return 1;
}

int net_buf_id(struct net_buf *buf)
{
	struct net_buf_pool *pool = net_buf_pool_get(buf->pool_id);

	return buf - pool->__bufs;
}

static inline struct net_buf *pool_get_uninit(struct net_buf_pool *pool,
					      u16_t uninit_count)
{
	struct net_buf *buf;

	buf = &pool->__bufs[pool->buf_count - uninit_count];

	buf->pool_id = pool_id(pool);

	return buf;
}

void net_buf_reset(struct net_buf *buf)
{
	__ASSERT_NO_MSG(buf->flags == 0U);
	__ASSERT_NO_MSG(buf->frags == NULL);

	net_buf_simple_reset(&buf->b);
}

static u8_t *generic_data_ref(struct net_buf *buf, u8_t *data)
{
	u8_t *ref_count;

	ref_count = data - 1;
	(*ref_count)++;

	return data;
}

static u8_t *mem_pool_data_alloc(struct net_buf *buf, size_t *size,
				 k_timeout_t timeout)
{
#if 0
	struct net_buf_pool *buf_pool = net_buf_pool_get(buf->pool_id);
	struct k_mem_pool *pool = buf_pool->alloc->alloc_data;
	struct k_mem_block block;
	u8_t *ref_count;

	/* Reserve extra space for k_mem_block_id and ref-count (u8_t) */
	if (k_mem_pool_alloc(pool, &block,
			     sizeof(struct k_mem_block_id) + 1 + *size,
			     timeout)) {
		return NULL;
	}

	/* save the block descriptor info at the start of the actual block */
	memcpy(block.data, &block.id, sizeof(block.id));

	ref_count = (u8_t *)block.data + sizeof(block.id);
	*ref_count = 1U;

	/* Return pointer to the byte following the ref count */
	return ref_count + 1;
#endif
    return NULL;
}

static void mem_pool_data_unref(struct net_buf *buf, u8_t *data)
{
    #if 0
	struct k_mem_block_id id;
	u8_t *ref_count;

	ref_count = data - 1;
	if (--(*ref_count)) {
		return;
	}

	/* Need to copy to local variable due to alignment */
	memcpy(&id, ref_count - sizeof(id), sizeof(id));
	k_mem_pool_free_id(&id);
    #endif
}

const struct net_buf_data_cb net_buf_var_cb = {
	.alloc = mem_pool_data_alloc,
	.ref   = generic_data_ref,
	.unref = mem_pool_data_unref,
};

static u8_t *fixed_data_alloc(struct net_buf *buf, size_t *size,
			      k_timeout_t timeout)
{
	struct net_buf_pool *pool = net_buf_pool_get(buf->pool_id);
	const struct net_buf_pool_fixed *fixed = pool->alloc->alloc_data;

	*size = MIN(fixed->data_size, *size);

#ifdef CONFIG_BT_USE_MM
	u32_t *ref_count;
	unsigned int key;
	key = irq_lock();
	ref_count = malloc(sizeof(*ref_count) + *size);
	irq_unlock(key);
	if (!ref_count) {
		return NULL;
	}

	*ref_count = 1;
	return (u8_t *)(ref_count + 1);
#else
	return fixed->data_pool + fixed->data_size * net_buf_id(buf);
#endif
}

static void fixed_data_unref(struct net_buf *buf, u8_t *data)
{
	/* Nothing needed for fixed-size data pools */
#ifdef CONFIG_BT_USE_MM
	u32_t *ref_count;

	ref_count = (u32_t *)(data - sizeof(*ref_count));
	if (--(*ref_count)) {
		return;
	}

	unsigned int key;
	key = irq_lock();
	free(ref_count);
	irq_unlock(key);
#endif
}

const struct net_buf_data_cb net_buf_fixed_cb = {
	.alloc = fixed_data_alloc,
	.unref = fixed_data_unref,
};

#if (CONFIG_HEAP_MEM_POOL_SIZE > 0)

static u8_t *heap_data_alloc(struct net_buf *buf, size_t *size,
			     k_timeout_t timeout)
{
	u8_t *ref_count;

	ref_count = malloc(1 + *size);
	if (!ref_count) {
		return NULL;
	}

	*ref_count = 1U;

	return ref_count + 1;
}

static void heap_data_unref(struct net_buf *buf, u8_t *data)
{
	u8_t *ref_count;

	ref_count = data - 1;
	if (--(*ref_count)) {
		return;
	}

	k_free(ref_count);
}

static const struct net_buf_data_cb net_buf_heap_cb = {
	.alloc = heap_data_alloc,
	.ref   = generic_data_ref,
	.unref = heap_data_unref,
};

const struct net_buf_data_alloc net_buf_heap_alloc = {
	.cb = &net_buf_heap_cb,
};

#endif /* CONFIG_HEAP_MEM_POOL_SIZE > 0 */

static u8_t *data_alloc(struct net_buf *buf, size_t *size, k_timeout_t timeout)
{
	struct net_buf_pool *pool = net_buf_pool_get(buf->pool_id);

	return pool->alloc->cb->alloc(buf, size, timeout);
}

static u8_t *data_ref(struct net_buf *buf, u8_t *data)
{
	struct net_buf_pool *pool = net_buf_pool_get(buf->pool_id);

	return pool->alloc->cb->ref(buf, data);
}

static void data_unref(struct net_buf *buf, u8_t *data)
{
	struct net_buf_pool *pool = net_buf_pool_get(buf->pool_id);

	if (buf->flags & NET_BUF_EXTERNAL_DATA) {
		return;
	}

	pool->alloc->cb->unref(buf, data);
}

#if defined(CONFIG_NET_BUF_LOG)
struct net_buf *net_buf_alloc_len_debug(struct net_buf_pool *pool, size_t size,
					k_timeout_t timeout, const char *func,
					int line)
#else
struct net_buf *net_buf_alloc_len(struct net_buf_pool *pool, size_t size,
				  k_timeout_t timeout)
#endif
{
	u32_t alloc_start = k_uptime_get_32();
	struct net_buf *buf;
	unsigned int key;

	__ASSERT_NO_MSG(pool);

	NET_BUF_DBG("%s():%d: pool %p size %zu timeout %d", func, line, pool,
		    size, timeout);

	/* We need to lock interrupts temporarily to prevent race conditions
	 * when accessing pool->uninit_count.
	 */
	key = irq_lock();

	/* If there are uninitialized buffers we're guaranteed to succeed
	 * with the allocation one way or another.
	 */
	if (pool->uninit_count) {
		u16_t uninit_count;

		/* If this is not the first access to the pool, we can
		 * be opportunistic and try to fetch a previously used
		 * buffer from the LIFO with K_NO_WAIT.
		 */
		if (pool->uninit_count < pool->buf_count) {
			buf = k_lifo_get(&pool->free, K_NO_WAIT);
			if (buf) {
				irq_unlock(key);
				goto success;
			}
		}

		uninit_count = pool->uninit_count--;
		irq_unlock(key);

		buf = pool_get_uninit(pool, uninit_count);
		goto success;
	}

	irq_unlock(key);

#if defined(CONFIG_NET_BUF_LOG) && SYS_LOG_LEVEL >= SYS_LOG_LEVEL_WARNING
	if (timeout == K_FOREVER) {
		u32_t ref = k_uptime_get_32();
		buf = k_lifo_get(&pool->free, K_NO_WAIT);
		while (!buf) {
#if defined(CONFIG_NET_BUF_POOL_USAGE)
			NET_BUF_WARN("%s():%d: Pool %s low on buffers.",
				     func, line, pool->name);
#else
			NET_BUF_WARN("%s():%d: Pool %p low on buffers.",
				     func, line, pool);
#endif
			buf = k_lifo_get(&pool->free, WARN_ALLOC_INTERVAL);
#if defined(CONFIG_NET_BUF_POOL_USAGE)
			NET_BUF_WARN("%s():%d: Pool %s blocked for %u secs",
				     func, line, pool->name,
				     (k_uptime_get_32() - ref) / MSEC_PER_SEC);
#else
			NET_BUF_WARN("%s():%d: Pool %p blocked for %u secs",
				     func, line, pool,
				     (k_uptime_get_32() - ref) / MSEC_PER_SEC);
#endif
		}
	} else {
		buf = k_lifo_get(&pool->free, timeout);
	}
#else
	buf = k_lifo_get(&pool->free, timeout);
#endif
	if (!buf) {
		NET_BUF_ERR("%s():%d: Failed to get free buffer", func, line);
		return NULL;
	}

success:
	NET_BUF_DBG("allocated buf %p", buf);

	if (size) {
		if (timeout != K_NO_WAIT && timeout != K_FOREVER) {
			u32_t diff = k_uptime_get_32() - alloc_start;

			timeout -= MIN(timeout, diff);
		}

		buf->__buf = data_alloc(buf, &size, timeout);
		if (!buf->__buf) {
			NET_BUF_ERR("%s():%d: Failed to allocate data",
				    func, line);
			net_buf_destroy(buf);
			return NULL;
		}

		//NET_BUF_ASSERT(req_size <= size);
	} else {
		buf->__buf = NULL;
	}

	buf->ref   = 1U;
	buf->flags = 0U;
	buf->frags = NULL;
	buf->size  = size;
	net_buf_reset(buf);

#if defined(CONFIG_NET_BUF_POOL_USAGE)
	pool->avail_count--;
	__ASSERT_NO_MSG(pool->avail_count >= 0);
#endif

	return buf;
}

#if defined(CONFIG_NET_BUF_LOG)
struct net_buf *net_buf_alloc_fixed_debug(struct net_buf_pool *pool,
					  k_timeout_t timeout, const char *func,
					  int line)
{
	const struct net_buf_pool_fixed *fixed = pool->alloc->alloc_data;

	return net_buf_alloc_len_debug(pool, fixed->data_size, timeout, func,
				       line);
}
#else
struct net_buf *net_buf_alloc_fixed(struct net_buf_pool *pool,
				    k_timeout_t timeout)
{
	const struct net_buf_pool_fixed *fixed = pool->alloc->alloc_data;

	return net_buf_alloc_len(pool, fixed->data_size, timeout);
}
#endif

#if defined(CONFIG_NET_BUF_LOG)
struct net_buf *net_buf_alloc_with_data_debug(struct net_buf_pool *pool,
					      void *data, size_t size,
					      k_timeout_t timeout,
					      const char *func, int line)
#else
struct net_buf *net_buf_alloc_with_data(struct net_buf_pool *pool,
					void *data, size_t size,
					k_timeout_t timeout)
#endif
{
	struct net_buf *buf;

#if defined(CONFIG_NET_BUF_LOG)
	buf = net_buf_alloc_len_debug(pool, 0, timeout, func, line);
#else
	buf = net_buf_alloc_len(pool, 0, timeout);
#endif
	if (!buf) {
		return NULL;
	}

	net_buf_simple_init_with_data(&buf->b, data, size);
	buf->flags = NET_BUF_EXTERNAL_DATA;

	return buf;
}

#if defined(CONFIG_NET_BUF_LOG)
struct net_buf *net_buf_get_debug(struct kfifo *fifo, k_timeout_t timeout,
				  const char *func, int line)
#else
struct net_buf *net_buf_get(struct kfifo *fifo, k_timeout_t timeout)
#endif
{
	struct net_buf *buf, *frag;

	NET_BUF_DBG("%s():%d: fifo %p", func, line, fifo);

	buf = k_fifo_get(fifo, timeout);
	if (!buf) {
		return NULL;
	}

	NET_BUF_DBG("%s():%d: buf %p fifo %p", func, line, buf, fifo);

	/* Get any fragments belonging to this buffer */
	for (frag = buf; (frag->flags & NET_BUF_FRAGS); frag = frag->frags) {
		frag->frags = k_fifo_get(fifo, K_NO_WAIT);
		__ASSERT_NO_MSG(frag->frags);

		/* The fragments flag is only for FIFO-internal usage */
		frag->flags &= ~NET_BUF_FRAGS;
	}

	/* Mark the end of the fragment list */
	frag->frags = NULL;

	return buf;
}

void net_buf_simple_init_with_data(struct net_buf_simple *buf,
				   void *data, size_t size)
{
	buf->__buf = data;
	buf->data  = data;
	buf->size  = size;
	buf->len   = size;
}

void net_buf_simple_reserve(struct net_buf_simple *buf, size_t reserve)
{
	__ASSERT_NO_MSG(buf);
	__ASSERT_NO_MSG(buf->len == 0U);
	NET_BUF_DBG("buf %p reserve %zu", buf, reserve);

	buf->data = buf->__buf + reserve;
}

void net_buf_slist_put(sys_slist_t *list, struct net_buf *buf)
{
	struct net_buf *tail;
	unsigned int key;

	__ASSERT_NO_MSG(list);
	__ASSERT_NO_MSG(buf);

	for (tail = buf; tail->frags; tail = tail->frags) {
		tail->flags |= NET_BUF_FRAGS;
	}

	key = irq_lock();
	sys_slist_append_list(list, &buf->node, &tail->node);
	irq_unlock(key);
}

struct net_buf *net_buf_slist_get(sys_slist_t *list)
{
	struct net_buf *buf, *frag;
	unsigned int key;

	__ASSERT_NO_MSG(list);

	key = irq_lock();
	buf = (void *)sys_slist_get(list);
	irq_unlock(key);

	if (!buf) {
		return NULL;
	}

	/* Get any fragments belonging to this buffer */
	for (frag = buf; (frag->flags & NET_BUF_FRAGS); frag = frag->frags) {
		key = irq_lock();
		frag->frags = (void *)sys_slist_get(list);
		irq_unlock(key);

		__ASSERT_NO_MSG(frag->frags);

		/* The fragments flag is only for list-internal usage */
		frag->flags &= ~NET_BUF_FRAGS;
	}

	/* Mark the end of the fragment list */
	frag->frags = NULL;

	return buf;
}

void net_buf_put(struct kfifo *fifo, struct net_buf *buf)
{
	struct net_buf *tail;
	if(NULL == fifo) {
		BT_WARN("fifo is NULL");
		return;
	}
	if(NULL == buf) {
		BT_WARN("buf is NULL");
		return;
	}

	if(NULL == fifo || NULL == buf){
		BT_WARN("fifo is NULL");
		return;
	}

	__ASSERT_NO_MSG(fifo);
	__ASSERT_NO_MSG(buf);

	for (tail = buf; tail->frags; tail = tail->frags) {
		tail->flags |= NET_BUF_FRAGS;
	}

	k_fifo_put_list(fifo, buf, tail);

}

#if defined(CONFIG_NET_BUF_LOG)
void net_buf_unref_debug(struct net_buf *buf, const char *func, int line)
#else
void net_buf_unref(struct net_buf *buf)
#endif
{
	__ASSERT_NO_MSG(buf);

	while (buf) {
		struct net_buf *frags = buf->frags;
		struct net_buf_pool *pool;
		u8_t flags = buf->flags;
#if 1
		if (!buf->ref) {
			BT_WARN("buf %p double free", buf);
			return;
		}
#endif
		NET_BUF_DBG("buf %p ref %u pool_id %u frags %p", buf, buf->ref,
			    buf->pool_id, buf->frags);

		if (--buf->ref > 0) {
			return;
		}

		if (buf->__buf) {
			data_unref(buf, buf->__buf);
			buf->__buf = NULL;
		}

		buf->data = NULL;
		buf->frags = NULL;

		pool = net_buf_pool_get(buf->pool_id);

#if defined(CONFIG_NET_BUF_POOL_USAGE)
		pool->avail_count++;
		__ASSERT_NO_MSG(pool->avail_count <= pool->buf_count);
#endif

		if (pool->destroy) {
			pool->destroy(buf);
		} else {
			net_buf_destroy(buf);
		}

		if (!flags)
		{
			return;
		}

		buf = frags;
	}
}

struct net_buf *net_buf_ref(struct net_buf *buf)
{
	__ASSERT_NO_MSG(buf);

	NET_BUF_DBG("buf %p (old) ref %u pool_id %u",
		    buf, buf->ref, buf->pool_id);
	buf->ref++;
	return buf;
}

struct net_buf *net_buf_clone(struct net_buf *buf, k_timeout_t timeout)
{
	u32_t alloc_start = k_uptime_get_32();
	struct net_buf_pool *pool;
	struct net_buf *clone;

	__ASSERT_NO_MSG(buf);

	pool = net_buf_pool_get(buf->pool_id);

	clone = net_buf_alloc_len(pool, 0, timeout);
	if (!clone) {
		return NULL;
	}

	/* If the pool supports data referencing use that. Otherwise
	 * we need to allocate new data and make a copy.
	 */
	if (pool->alloc->cb->ref && !(buf->flags & NET_BUF_EXTERNAL_DATA)) {
		clone->__buf = data_ref(buf, buf->__buf);
		clone->data = buf->data;
		clone->len = buf->len;
		clone->size = buf->size;
	} else {
		size_t size = buf->size;

		if (timeout != K_NO_WAIT && timeout != K_FOREVER) {
			u32_t diff = k_uptime_get_32() - alloc_start;

			timeout -= MIN(timeout, diff);
		}

		clone->__buf = data_alloc(clone, &size, timeout);
		if (!clone->__buf || size < buf->size) {
			net_buf_destroy(clone);
			return NULL;
		}

		clone->size = size;
		clone->data = clone->__buf + net_buf_headroom(buf);
		net_buf_add_mem(clone, buf->data, buf->len);
	}

	return clone;
}

struct net_buf *net_buf_frag_last(struct net_buf *buf)
{
	__ASSERT_NO_MSG(buf);

	while (buf->frags) {
		buf = buf->frags;
	}

	return buf;
}

void net_buf_frag_insert(struct net_buf *parent, struct net_buf *frag)
{
	__ASSERT_NO_MSG(parent);
	__ASSERT_NO_MSG(frag);

	if (parent->frags) {
		net_buf_frag_last(frag)->frags = parent->frags;
	}
	/* Take ownership of the fragment reference */
	parent->frags = frag;
}

struct net_buf *net_buf_frag_add(struct net_buf *head, struct net_buf *frag)
{
	__ASSERT_NO_MSG(frag);

	if (!head) {
		return net_buf_ref(frag);
	}

	net_buf_frag_insert(net_buf_frag_last(head), frag);

	return head;
}

struct net_buf *net_buf_frag_add_with_flags(struct net_buf *head, struct net_buf *frag)
{
	__ASSERT_NO_MSG(frag);

	if (!head) {
		return net_buf_ref(frag);
	}

	head->flags |= NET_BUF_FRAGS;
	frag->flags |= NET_BUF_FRAGS;

	net_buf_frag_insert(net_buf_frag_last(head), frag);

	return head;
}


#if defined(CONFIG_NET_BUF_LOG)
struct net_buf *net_buf_frag_del_debug(struct net_buf *parent,
				       struct net_buf *frag,
				       const char *func, int line)
#else
struct net_buf *net_buf_frag_del(struct net_buf *parent, struct net_buf *frag)
#endif
{
	struct net_buf *next_frag;

	__ASSERT_NO_MSG(frag);

	if (parent) {
		__ASSERT_NO_MSG(parent->frags);
		__ASSERT_NO_MSG(parent->frags == frag);
		parent->frags = frag->frags;
	}

	next_frag = frag->frags;

	frag->frags = NULL;

#if defined(CONFIG_NET_BUF_LOG)
	net_buf_unref_debug(frag, func, line);
#else
	net_buf_unref(frag);
#endif

	return next_frag;
}

#if defined(CONFIG_NET_BUF_LOG)
void net_buf_frag_del_all_debug(struct net_buf *parent,
				       const char *func, int line)
#else
void net_buf_frag_del_all(struct net_buf *parent)
#endif
{
	struct net_buf *frag = parent;
	struct net_buf *next_frag;

	if (!parent)
	{
		return;
	}

	while(frag)
	{
		next_frag = frag->frags;
		frag->frags = NULL;

	#if defined(CONFIG_NET_BUF_LOG)
		net_buf_unref_debug(frag, func, line);
	#else
		net_buf_unref(frag);
	#endif
		frag = next_frag;
	}
	return;
}

size_t net_buf_linearize(void *dst, size_t dst_len, struct net_buf *src,
			 size_t offset, size_t len)
{
	struct net_buf *frag;
	size_t to_copy;
	size_t copied;

	len = MIN(len, dst_len);

	frag = src;

	/* find the right fragment to start copying from */
	while (frag && offset >= frag->len) {
		offset -= frag->len;
		frag = frag->frags;
	}

	/* traverse the fragment chain until len bytes are copied */
	copied = 0;
	while (frag && len > 0) {
		to_copy = MIN(len, frag->len - offset);
		memcpy((u8_t *)dst + copied, frag->data + offset, to_copy);

		copied += to_copy;

		/* to_copy is always <= len */
		len -= to_copy;
		frag = frag->frags;

		/* after the first iteration, this value will be 0 */
		offset = 0;
	}

	return copied;
}

/* This helper routine will append multiple bytes, if there is no place for
 * the data in current fragment then create new fragment and add it to
 * the buffer. It assumes that the buffer has at least one fragment.
 */
size_t net_buf_append_bytes(struct net_buf *buf, size_t len,
			    const void *value, k_timeout_t timeout,
			    net_buf_allocator_cb allocate_cb, void *user_data)
{
	struct net_buf *frag = net_buf_frag_last(buf);
	size_t added_len = 0;
	const u8_t *value8 = value;

	do {
		u16_t count = MIN(len, net_buf_tailroom(frag));

		net_buf_add_mem(frag, value8, count);
		len -= count;
		added_len += count;
		value8 += count;

		if (len == 0) {
			return added_len;
		}

		frag = allocate_cb(timeout, user_data);
		if (!frag) {
			return added_len;
		}

		net_buf_frag_add(buf, frag);
	} while (1);

	/* Unreachable */
	return 0;
}

#if defined(CONFIG_NET_BUF_SIMPLE_LOG)
#define NET_BUF_SIMPLE_DBG(fmt, ...) NET_BUF_DBG(fmt, ##__VA_ARGS__)
#define NET_BUF_SIMPLE_ERR(fmt, ...) NET_BUF_ERR(fmt, ##__VA_ARGS__)
#define NET_BUF_SIMPLE_WARN(fmt, ...) NET_BUF_WARN(fmt, ##__VA_ARGS__)
#define NET_BUF_SIMPLE_INFO(fmt, ...) NET_BUF_INFO(fmt, ##__VA_ARGS__)
#else
#define NET_BUF_SIMPLE_DBG(fmt, ...)
#define NET_BUF_SIMPLE_ERR(fmt, ...)
#define NET_BUF_SIMPLE_WARN(fmt, ...)
#define NET_BUF_SIMPLE_INFO(fmt, ...)
#endif /* CONFIG_NET_BUF_SIMPLE_LOG */

void net_buf_simple_clone(const struct net_buf_simple *original,
			  struct net_buf_simple *clone)
{
	memcpy(clone, original, sizeof(struct net_buf_simple));
}

void *net_buf_simple_add(struct net_buf_simple *buf, size_t len)
{
	u8_t *tail = net_buf_simple_tail(buf);

	NET_BUF_SIMPLE_DBG("buf %p len %zu", buf, len);

	__ASSERT_NO_MSG(net_buf_simple_tailroom(buf) >= len);

	buf->len += len;
	return tail;
}

void *net_buf_simple_add_mem(struct net_buf_simple *buf, const void *mem,
			     size_t len)
{
	NET_BUF_SIMPLE_DBG("buf %p len %zu", buf, len);

	return memcpy(net_buf_simple_add(buf, len), mem, len);
}

u8_t *net_buf_simple_add_u8(struct net_buf_simple *buf, u8_t val)
{
	u8_t *u8;

	NET_BUF_SIMPLE_DBG("buf %p val 0x%02x", buf, val);

	u8 = net_buf_simple_add(buf, 1);
	*u8 = val;

	return u8;
}

void net_buf_simple_add_le16(struct net_buf_simple *buf, u16_t val)
{
	NET_BUF_SIMPLE_DBG("buf %p val %u", buf, val);

	sys_put_le16(val, net_buf_simple_add(buf, sizeof(val)));
}

void net_buf_simple_add_be16(struct net_buf_simple *buf, u16_t val)
{
	NET_BUF_SIMPLE_DBG("buf %p val %u", buf, val);

	sys_put_be16(val, net_buf_simple_add(buf, sizeof(val)));
}

void net_buf_simple_add_le24(struct net_buf_simple *buf, u32_t val)
{
	NET_BUF_SIMPLE_DBG("buf %p val %u", buf, val);

	sys_put_le24(val, net_buf_simple_add(buf, 3));
}

void net_buf_simple_add_be24(struct net_buf_simple *buf, u32_t val)
{
	NET_BUF_SIMPLE_DBG("buf %p val %u", buf, val);

	sys_put_be24(val, net_buf_simple_add(buf, 3));
}

void net_buf_simple_add_le32(struct net_buf_simple *buf, u32_t val)
{
	NET_BUF_SIMPLE_DBG("buf %p val %u", buf, val);

	sys_put_le32(val, net_buf_simple_add(buf, sizeof(val)));
}

void net_buf_simple_add_be32(struct net_buf_simple *buf, u32_t val)
{
	NET_BUF_SIMPLE_DBG("buf %p val %u", buf, val);

	sys_put_be32(val, net_buf_simple_add(buf, sizeof(val)));
}

void net_buf_simple_add_le48(struct net_buf_simple *buf, u64_t val)
{
	NET_BUF_SIMPLE_DBG("buf %p val %" PRIu64, buf, val);

	sys_put_le48(val, net_buf_simple_add(buf, 6));
}

void net_buf_simple_add_be48(struct net_buf_simple *buf, u64_t val)
{
	NET_BUF_SIMPLE_DBG("buf %p val %" PRIu64, buf, val);

	sys_put_be48(val, net_buf_simple_add(buf, 6));
}

void net_buf_simple_add_le64(struct net_buf_simple *buf, u64_t val)
{
	NET_BUF_SIMPLE_DBG("buf %p val %" PRIu64, buf, val);

	sys_put_le64(val, net_buf_simple_add(buf, sizeof(val)));
}

void net_buf_simple_add_be64(struct net_buf_simple *buf, u64_t val)
{
	NET_BUF_SIMPLE_DBG("buf %p val %" PRIu64, buf, val);

	sys_put_be64(val, net_buf_simple_add(buf, sizeof(val)));
}

void *net_buf_simple_push(struct net_buf_simple *buf, size_t len)
{
	NET_BUF_SIMPLE_DBG("buf %p len %zu", buf, len);

	__ASSERT_NO_MSG(net_buf_simple_headroom(buf) >= len);

	buf->data -= len;
	buf->len += len;
	return buf->data;
}

void net_buf_simple_push_le16(struct net_buf_simple *buf, u16_t val)
{
	NET_BUF_SIMPLE_DBG("buf %p val %u", buf, val);

	sys_put_le16(val, net_buf_simple_push(buf, sizeof(val)));
}

void net_buf_simple_push_be16(struct net_buf_simple *buf, u16_t val)
{
	NET_BUF_SIMPLE_DBG("buf %p val %u", buf, val);

	sys_put_be16(val, net_buf_simple_push(buf, sizeof(val)));
}

void net_buf_simple_push_u8(struct net_buf_simple *buf, u8_t val)
{
	u8_t *data = net_buf_simple_push(buf, 1);

	*data = val;
}

void net_buf_simple_push_le24(struct net_buf_simple *buf, u32_t val)
{
	NET_BUF_SIMPLE_DBG("buf %p val %u", buf, val);

	sys_put_le24(val, net_buf_simple_push(buf, 3));
}

void net_buf_simple_push_be24(struct net_buf_simple *buf, u32_t val)
{
	NET_BUF_SIMPLE_DBG("buf %p val %u", buf, val);

	sys_put_be24(val, net_buf_simple_push(buf, 3));
}

void net_buf_simple_push_le32(struct net_buf_simple *buf, u32_t val)
{
	NET_BUF_SIMPLE_DBG("buf %p val %u", buf, val);

	sys_put_le32(val, net_buf_simple_push(buf, sizeof(val)));
}

void net_buf_simple_push_be32(struct net_buf_simple *buf, u32_t val)
{
	NET_BUF_SIMPLE_DBG("buf %p val %u", buf, val);

	sys_put_be32(val, net_buf_simple_push(buf, sizeof(val)));
}

void net_buf_simple_push_le48(struct net_buf_simple *buf, u64_t val)
{
	NET_BUF_SIMPLE_DBG("buf %p val %" PRIu64, buf, val);

	sys_put_le48(val, net_buf_simple_push(buf, 6));
}

void net_buf_simple_push_be48(struct net_buf_simple *buf, u64_t val)
{
	NET_BUF_SIMPLE_DBG("buf %p val %" PRIu64, buf, val);

	sys_put_be48(val, net_buf_simple_push(buf, 6));
}

void net_buf_simple_push_le64(struct net_buf_simple *buf, u64_t val)
{
	NET_BUF_SIMPLE_DBG("buf %p val %" PRIu64, buf, val);

	sys_put_le64(val, net_buf_simple_push(buf, sizeof(val)));
}

void net_buf_simple_push_be64(struct net_buf_simple *buf, u64_t val)
{
	NET_BUF_SIMPLE_DBG("buf %p val %" PRIu64, buf, val);

	sys_put_be64(val, net_buf_simple_push(buf, sizeof(val)));
}

void *net_buf_simple_pull(struct net_buf_simple *buf, size_t len)
{
	NET_BUF_SIMPLE_DBG("buf %p len %zu", buf, len);

	__ASSERT_NO_MSG(buf->len >= len);

	buf->len -= len;
	return buf->data += len;
}

void *net_buf_simple_pull_mem(struct net_buf_simple *buf, size_t len)
{
	void *data = buf->data;

	NET_BUF_SIMPLE_DBG("buf %p len %zu", buf, len);

	__ASSERT_NO_MSG(buf->len >= len);

	buf->len -= len;
	buf->data += len;

	return data;
}

u8_t net_buf_simple_pull_u8(struct net_buf_simple *buf)
{
	u8_t val;

	val = buf->data[0];
	net_buf_simple_pull(buf, 1);

	return val;
}

u16_t net_buf_simple_pull_le16(struct net_buf_simple *buf)
{
	u16_t val;

	val = UNALIGNED_GET((u16_t *)buf->data);
	net_buf_simple_pull(buf, sizeof(val));

	return sys_le16_to_cpu(val);
}

u16_t net_buf_simple_pull_be16(struct net_buf_simple *buf)
{
	u16_t val;

	val = UNALIGNED_GET((u16_t *)buf->data);
	net_buf_simple_pull(buf, sizeof(val));

	return sys_be16_to_cpu(val);
}

u32_t net_buf_simple_pull_le24(struct net_buf_simple *buf)
{
	struct uint24 {
		u32_t u24:24;
	} __packed val;

	val = UNALIGNED_GET((struct uint24 *)buf->data);
	net_buf_simple_pull(buf, sizeof(val));

	return sys_le24_to_cpu(val.u24);
}

u32_t net_buf_simple_pull_be24(struct net_buf_simple *buf)
{
	struct uint24 {
		u32_t u24:24;
	} __packed val;

	val = UNALIGNED_GET((struct uint24 *)buf->data);
	net_buf_simple_pull(buf, sizeof(val));

	return sys_be24_to_cpu(val.u24);
}

u32_t net_buf_simple_pull_le32(struct net_buf_simple *buf)
{
	u32_t val;

	val = UNALIGNED_GET((u32_t *)buf->data);
	net_buf_simple_pull(buf, sizeof(val));

	return sys_le32_to_cpu(val);
}

u32_t net_buf_simple_pull_be32(struct net_buf_simple *buf)
{
	u32_t val;

	val = UNALIGNED_GET((u32_t *)buf->data);
	net_buf_simple_pull(buf, sizeof(val));

	return sys_be32_to_cpu(val);
}

u64_t net_buf_simple_pull_le48(struct net_buf_simple *buf)
{
	struct uint48 {
		u64_t u48:48;
	} __packed val;

	val = UNALIGNED_GET((struct uint48 *)buf->data);
	net_buf_simple_pull(buf, sizeof(val));

	return sys_le48_to_cpu(val.u48);
}

u64_t net_buf_simple_pull_be48(struct net_buf_simple *buf)
{
	struct uint48 {
		u64_t u48:48;
	} __packed val;

	val = UNALIGNED_GET((struct uint48 *)buf->data);
	net_buf_simple_pull(buf, sizeof(val));

	return sys_be48_to_cpu(val.u48);
}

u64_t net_buf_simple_pull_le64(struct net_buf_simple *buf)
{
	u64_t val;

	val = UNALIGNED_GET((u64_t *)buf->data);
	net_buf_simple_pull(buf, sizeof(val));

	return sys_le64_to_cpu(val);
}

u64_t net_buf_simple_pull_be64(struct net_buf_simple *buf)
{
	u64_t val;

	val = UNALIGNED_GET((u64_t *)buf->data);
	net_buf_simple_pull(buf, sizeof(val));

	return sys_be64_to_cpu(val);
}

size_t net_buf_simple_headroom(struct net_buf_simple *buf)
{
	return buf->data - buf->__buf;
}

size_t net_buf_simple_tailroom(struct net_buf_simple *buf)
{
	return buf->size - net_buf_simple_headroom(buf) - buf->len;
}
