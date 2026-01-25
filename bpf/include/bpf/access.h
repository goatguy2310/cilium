/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include "compiler.h"

#if defined(__bpf__) || defined(__ARCH_X86_64)
static __always_inline __maybe_unused __u32
map_array_get_32(const __u32 *array, __u32 index, const __u32 limit)
{
	__u32 datum = 0;

	if (__builtin_constant_p(index) ||
	    !__builtin_constant_p(limit))
		__throw_build_bug();

	/* LLVM tends to optimize code away that is needed for the verifier to
	 * understand dynamic map access. Input constraint is that index < limit
	 * for this util function, so we never fail here, and returned datum is
	 * always valid.
	 */
	// JB: native compilation
#if defined(__ARCH_X86_64)
	__u64 index_64 = index;
	__u64 limit_64 = limit;

	asm volatile("shlq $2, %[index]\n\t"
		     "cmpq %[limit], %[index]\n\t"
		     "ja 1f\n\t"
		     "addq %[index], %[array]\n\t"
		     "1:\n\t"
		     "movl (%[array]), %k[datum]\n\t"
		     : [datum]"=r"(datum)
		     : [limit]"i"(limit_64), [array]"r"(array), [index]"r"(index_64)
		     : "cc" );
#else
	asm volatile("%[index] <<= 2\n\t"
		     "if %[index] > %[limit] goto +1\n\t"
		     "%[array] += %[index]\n\t"
		     "%[datum] = *(u32 *)(%[array] + 0)\n\t"
		     : [datum]"=r"(datum)
		     : [limit]"i"(limit), [array]"r"(array), [index]"r"(index)
		     : /* no clobbers */ );
#endif
	return datum;
}
#else
# define map_array_get_32(array, index, limit)	__throw_build_bug()
#endif /* __bpf__ */
