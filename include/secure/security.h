/*-
 * Copyright (c) 2015 Olivér Pintér
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD$
 */

#ifndef _SECURE_SECURITY_
#define	_SECURE_SECURITY_

#include <sys/cdefs.h>
#include <sys/types.h>

#ifndef __clang__
#if __GNUC_PREREQ__(4, 3)
#define	__errordecl(name, msg)	extern void name(void) __error_attr(msg)
#else
#define	__errordecl(name, msg)		\
static void name(void) __dead2;		\
static void name(void)			\
{					\
					\
	__fortify_chk_fail(msg);	\
}
#endif	/* __GNUC_PREREQ(4, 3) */
#else	/* !__clang__ */
#define	__errordecl(name, msg)
#endif	/* !__clang__ */

#define	__RENAME(x)	__asm__(#x)

#if __has_builtin(__builtin_umul_overflow) || __GNUC_PREREQ__(5, 0)
#if __LP64__
#define	__size_mul_overflow(a, b, result)	__builtin_umull_overflow(a, b, result)
#else
#define	__size_mul_overflow(a, b, result)	__builtin_umul_overflow(a, b, result)
#endif
#else
static __inline __always_inline int
__size_mul_overflow(__SIZE_TYPE__ a, __SIZE_TYPE__ b, __SIZE_TYPE__ *result)
{
    static const __SIZE_TYPE__ mul_no_overflow = 1UL << (sizeof(__SIZE_TYPE__) * 4);

    *result = a * b;

    return (a >= mul_no_overflow || b >= mul_no_overflow) && a > 0 && (__SIZE_TYPE__)-1 / a < b;
}
#endif

static __inline __always_inline int
__fortify_chk_overlap(const char *a, const char *b, size_t len)
{

	return ((uintptr_t)(a) < (uintptr_t)(b + len) &&
	    (uintptr_t)(a + len) > (uintptr_t)(b));
}

__BEGIN_DECLS

/* Common fail function. */
void	__secure_fail(const char *msg) __dead2 __nonnull(1);

/* SSP related fail functions. */
void	__chk_fail(void) __dead2;
void	__stack_chk_fail(void) __dead2;

/* FORTIFY_SOURCE related fail function. */
void	__fortify_chk_fail(const char* msg) __dead2 __nonnull(1);

__END_DECLS

#endif /* !_SECURE_SECURITY_ */
