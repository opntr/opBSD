/*-
 * Copyright (C) 2015 Olivér Pintér
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD$
 */

#ifndef _STRINGS_H_
#error "You should not use <secure/_strings.h> directly; include <sys/strings.h> instead."
#endif

#ifndef _SECURE_STRINGS_H_
#define _SECURE_STRINGS_H_

#include <secure/security.h>

__BEGIN_DECLS

extern void	*__bcopy_chk(void *, const void *, size_t, size_t) __RENAME(__memmove_chk);
extern void	 __bcopy_real(const void *, void *, size_t) __RENAME(bcopy);
extern void	*__bzero_chk(void *, int, size_t, size_t) __RENAME(__memset_chk);
extern void	 __bzero_real(void *, size_t) __RENAME(bzero);
extern char	*__rindex_chk(const char *, int, size_t);
extern char	*__rindex_real(const char *, int) __RENAME(rindex);

#ifdef __BSD_FORTIFY
#if __BSD_VISIBLE || __POSIX_VISIBLE <= 200112
__FORTIFY_INLINE void
bcopy(const void *_s, void *_d, size_t _l)
{
	size_t _bos = __bos0(_d);

#ifndef __clang__
	if (_bos == __FORTIFY_UNKNOWN_SIZE)
		__bcopy_real(_s, _d, _l);
#endif

	(void)(__bcopy_chk(_d, _s, _l, _bos));
}
#endif


#if __BSD_VISIBLE || __POSIX_VISIBLE <= 200112
__FORTIFY_INLINE void
bzero(void *_s, size_t _n)
{
	size_t _bos = __bos(_s);

#ifndef __clang__
	if (_bos == __FORTIFY_UNKNOWN_SIZE)
		__bzero_real(_s, _n);
#endif

	(void)(__bzero_chk(_s, '\0', _n, _bos));
}
#endif


#if __BSD_VISIBLE || __POSIX_VISIBLE <= 200112
__FORTIFY_INLINE char *
rindex(const char *_s, int _c)
{
	size_t _bos = __bos(_s);
#ifndef __clang__
	size_t _slen;

	/* Compiler doesn't know destination size. Don't call __strrchr_chk. */
	if (_bos == __FORTIFY_UNKNOWN_SIZE)
		return (__rindex_real(_s, _c));

	/*
	 * Compiler can prove, at compile time, that the passed in size
	 * is always <= the actual object size. Don't call __rindex_chk.
	 */
	_slen = __builtin_strlen(_s);
	if (__builtin_constant_p(_slen) && (_slen < _bos))
		return (__rindex_real(_s, _c));
#endif

	return (__rindex_chk(_s, _c, _bos));
}
#endif


#endif /* !__BSD_FORTIFY */

__END_DECLS

#endif /* !defined(_SECURE_STRINGS_H_) */
