/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include <linux/bpf.h>

#include "ctx/ctx.h"
#include "compiler.h"

#ifndef BPF_FUNC
# define BPF_FUNC(NAME, ...)						\
	(* NAME)(__VA_ARGS__) __maybe_unused = (void *)BPF_FUNC_##NAME
#endif

#ifndef BPF_STUB
# define BPF_STUB(NAME, ...)						\
	(* NAME##__stub)(__VA_ARGS__) __maybe_unused = (void *)((__u32)-1)
#endif

#ifndef BPF_FUNC_REMAP
# define BPF_FUNC_REMAP(NAME, ...)					\
	(* NAME)(__VA_ARGS__) __maybe_unused
#endif

#if __ctx_is == __ctx_skb
# include "helpers_skb.h"
#else
# include "helpers_xdp.h"
#endif

/* Map access/manipulation */
// JB: inline map lookup elem operations when fair nativev backend needs fair output
#if defined(__JB_x86_64__) && defined(__JB_inline_helpers__)
static void *(* real_map_lookup_elem)(const void *map, const void *key) __maybe_unused = (void *)BPF_FUNC_map_lookup_elem;

#define access_ptr_void(ptr, offset) (void *)((char *)ptr + offset)
#define access_ptr_at_u64(ptr, offset) *(__u64*)((char *)ptr + offset)

// For percpu ops
#define _KS_THIS_CPU_OFF 0xcccc0000
#define add_percpu_off(var) \
	asm volatile (	\
		"add %%gs:%1, %0"	\
		: "+r"(var)	\
		: "m"(*(__u64*) _KS_THIS_CPU_OFF)	\
		: "cc", "memory"	\
	)

// For accessing contiguous array values
#define BPF_ARR_VAL_OFF 0xaaaa0000
#define indexed_elem_offset(index, elem_size)	(BPF_ARR_VAL_OFF + (__u64)index * elem_size)

#define sizeof_member(map, member) sizeof(*((map)->member))
// Smartly check attributes at compile time so sizes and offsets can be calculated and propagated
#define inlined_map_lookup_elem(map, key) ({	\
	void *__elem = NULL;	\
	\
	const int type = sizeof_member(map, type) / sizeof(int); \
	if (type == BPF_MAP_TYPE_ARRAY) {	\
		__u32 idx = *(__u32 *) key;	\
		const __u32 max_entries = sizeof_member(map, max_entries) / sizeof(int);	\
		const __u32 elem_size = __builtin_align_up(sizeof_member(map, value), 8);	\
		\
		if (idx < max_entries) __elem = access_ptr_void(map, indexed_elem_offset(idx, elem_size));	\
	} else if (type == BPF_MAP_TYPE_ARRAY_OF_MAPS) {	\
		__u32 idx = *(__u32 *) key;	\
		const __u32 max_entries = sizeof_member(map, max_entries) / sizeof(int);	\
		const __u32 elem_size = sizeof(__u64);	\
		\
		if (idx < max_entries) __elem = (void *) access_ptr_at_u64(map, indexed_elem_offset(idx, elem_size));	\
	} else if (type == BPF_MAP_TYPE_PERCPU_ARRAY) {	\
		__u32 idx = *(__u32 *) key;	\
		const __u32 max_entries = sizeof_member(map, max_entries) / sizeof(int);	\
		const __u32 elem_size = sizeof(__u64);	\
		\
		if (idx < max_entries) {	\
			__elem = (void *) access_ptr_at_u64(map, indexed_elem_offset(idx, elem_size));	\
			/* adjust the offset to the correct percpu memory area */	\
			add_percpu_off(__elem);	\
		}	\
	} else {	\
		__elem = real_map_lookup_elem(map, key);	\
	}	\
	__elem;	\
})

// JB: Even if we use __builtin_choose_expr, the compiler still evaluates and parses void* to the inline branch, causing
// errors. For this, we define a fake map so that void* can be casted to struct __fake_map__* for this evaluation
struct __fake_map__ {
	unsigned int *type;
	unsigned int *max_entries;
	unsigned int *value;
};

#define is_void_ptr_type(ptr)	\
	(__builtin_types_compatible_p(typeof(ptr), void*) || \
	__builtin_types_compatible_p(typeof(ptr), const void*))

#define __cast_fake(ptr) __builtin_choose_expr(	\
	is_void_ptr_type(ptr),	\
	(struct __fake_map__*) ptr,	\
	ptr	\
)

#define map_lookup_elem(map, key) __builtin_choose_expr(	\
	is_void_ptr_type(map),	\
	real_map_lookup_elem(map, key),	\
	inlined_map_lookup_elem(__cast_fake(map), key)	\
)

#else
static void *BPF_FUNC(map_lookup_elem, const void *map, const void *key);
#endif
// JB: skip inlining for now as it adds more bytes
static int BPF_FUNC(map_update_elem, const void *map, const void *key,
		    const void *value, __u32 flags);
static int BPF_FUNC(map_delete_elem, const void *map, const void *key);

static void *BPF_FUNC(map_lookup_percpu_elem, void *map, const void *key,
				unsigned int cpu);
static long BPF_FUNC(for_each_map_elem, void *map, void *callback_fn,
		     void *callback_ctx, __u64 flags);

/* Time access */
static __u64 BPF_FUNC(ktime_get_ns);
static __u64 BPF_FUNC(ktime_get_boot_ns);
static __u64 BPF_FUNC(jiffies64);

/* We have cookies! ;-) */
static __sock_cookie BPF_FUNC(get_socket_cookie, void *ctx);
static __net_cookie BPF_FUNC(get_netns_cookie, void *ctx);

/* Legacy cgroups */
static __u32 BPF_FUNC(get_cgroup_classid);

/* Debugging */
static __printf(1, 3) void
BPF_FUNC(trace_printk, const char *fmt, int fmt_size, ...);

/* Random numbers */
static __u32 BPF_FUNC(get_prandom_u32);

/* Checksumming */
static int BPF_FUNC_REMAP(csum_diff_external, const void *from, __u32 size_from,
			  const void *to, __u32 size_to, __u32 seed) =
	(void *)BPF_FUNC_csum_diff;

/* Tail calls */
static void BPF_FUNC(tail_call, void *ctx, const void *map, __u32 index);

/* System helpers */
static __u32 BPF_FUNC(get_smp_processor_id);

/* Padded struct so the dmac at the end can be passed to another helper
 * e.g. as a map value buffer. Otherwise verifier will trip over it with
 * 'invalid indirect read from stack off'.
 */
struct bpf_fib_lookup_padded {
	struct bpf_fib_lookup l;
	__u8 pad[2];
};

/* Routing helpers */
static int BPF_FUNC(fib_lookup, void *ctx, struct bpf_fib_lookup *params,
		    __u32 plen, __u32 flags);

/* Socket lookup helpers */
static struct bpf_sock *BPF_FUNC(sk_lookup_tcp, void *ctx,
				 struct bpf_sock_tuple *tuple, __u32 tuple_size,
				 __u64 netns, __u64 flags);
static struct bpf_sock *BPF_FUNC(sk_lookup_udp, void *ctx,
				 struct bpf_sock_tuple *tuple, __u32 tuple_size,
				 __u64 netns, __u64 flags);

/* Socket helpers, misc */
/* Remapped name to avoid clash with getsockopt(2) when included from
 * regular applications.
 */
static int BPF_FUNC_REMAP(get_socket_opt, void *ctx, int level, int optname,
			  void *optval, int optlen) =
	(void *)BPF_FUNC_getsockopt;

static __u64 BPF_FUNC(get_current_cgroup_id);

static int BPF_FUNC(set_retval, int retval);

static inline int try_set_retval(int retval __maybe_unused)
{
#ifdef HAVE_SET_RETVAL
	return set_retval(retval);
#else
	return 0;
#endif
}

static long BPF_FUNC(loop, __u32 nr_loops, void *callback_fn, void *callback_ctx, __u64 flags);

static void *BPF_FUNC(ringbuf_reserve, void *ringbuf, __u64 size, __u64 flags);
static void BPF_FUNC(ringbuf_submit, void *data, __u64 flags);
static void BPF_FUNC(ringbuf_discard, void *data, __u64 flags);
