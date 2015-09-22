/*-
 * Copyright (c) 2015 Olivér Pintér
 * Copyright (C) 2008 The Android Open Source Project
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
 * bionic rev: 9ef26a3c4cd2e6d469f771815a07cb820800beb6
 *
 * $FreeBSD$
 */

#ifndef _STRING_H_
#error "You should not use <secure/_string.h> directly; include <string.h> instead."
#endif

#ifndef _SECURE_STRING_H_
#define	_SECURE_STRING_H_

#include <secure/security.h>

__BEGIN_DECLS

extern void 	*__memccpy_chk(void *, const void *, int, size_t, size_t);
extern void	*__memccpy_real(void *, const void *, int, size_t) __RENAME(memccpy);
extern void	*__memchr_chk(const void *, int, size_t, size_t);
extern void	*__memchr_real(const void *, int, size_t) __RENAME(memchr);
extern void	*__memcpy_chk(void *, const void *, size_t, size_t);
extern void	*__memcpy_real(void *, const void *, size_t) __RENAME(memcpy);
__errordecl(__memchr_buf_size_error, "memchr called with size bigger than buffer");
extern void	*__memmove_chk(void *, const void *, size_t, size_t);
extern void	*__memmove_real(void *, const void *, size_t) __RENAME(memmove);
extern void	*__memrchr_chk(const void *, int, size_t, size_t);
extern void	*__memrchr_real(const void *, int, size_t) __RENAME(memrchr);
__errordecl(__memrchr_buf_size_error, "memrchr called with size bigger than buffer");
extern void	*__memset_chk(void *, int, size_t, size_t);
extern void	*__memset_real(void *, int, size_t) __RENAME(memset);
extern char	*__strcat_chk(char *__restrict, const char *__restrict, size_t);
extern char	*__strcat_real(char *__restrict, const char *__restrict) __RENAME(strcat);
extern char	*__strncat_chk(char *__restrict, const char *__restrict, size_t, size_t);
extern char	*__strncat_real(char *__restrict, const char *__restrict, size_t) __RENAME(strncat);
extern char	*__stpcpy_chk(char *, const char *, size_t);
extern char	*__stpcpy_real(char *, const char *) __RENAME(stpcpy);
extern char	*__stpncpy_chk(char * __restrict, const char * __restrict, size_t, size_t);
extern char	*__stpncpy_chk2(char * __restrict, const char * __restrict, size_t, size_t, size_t);
extern char	*__stpncpy_real(char * __restrict, const char * __restrict, size_t) __RENAME(stpncpy);
extern char	*__strcpy_chk(char *, const char *, size_t);
extern char	*__strcpy_real(char *, const char *) __RENAME(strcpy);
extern char	*__strncpy_chk(char *, const char *, size_t, size_t);
extern char	*__strncpy_chk2(char * __restrict, const char * __restrict, size_t, size_t, size_t);
extern char	*__strncpy_real(char *, const char *, size_t) __RENAME(strncpy);
extern size_t	 __strlcpy_chk(char *, const char *, size_t, size_t);
extern size_t	 __strlcpy_real(char * __restrict, const char * __restrict, size_t) __RENAME(strlcpy);
extern size_t	 __strlcat_chk(char * __restrict, const char * __restrict, size_t, size_t);
extern size_t	 __strlcat_real(char * __restrict, const char * __restrict, size_t) __RENAME(strlcat);
extern size_t	 __strlen_chk(const char *, size_t);
extern size_t	 __strlen_real(const char *) __RENAME(strlen);
extern char	*__strchr_chk(const char *, int, size_t);
extern char	*__strchr_real(const char *, int) __RENAME(strchr);
extern char	*__strchrnul_chk(const char *, int, size_t);
extern char	*__strchrnul_real(const char *, int) __RENAME(strchrnul);
extern char	*__strrchr_chk(const char *, int, size_t);
extern char	*__strrchr_real(const char *, int) __RENAME(strrchr);

#ifdef __BSD_FORTIFY

#if __XSI_VISIBLE >= 600
__FORTIFY_INLINE void *
memccpy(void * __restrict _d, const void * __restrict _s, int _c, size_t _n)
{
	size_t _bos = __bos0(_d);

#ifndef __clang__
	if (_bos == __FORTIFY_UNKNOWN_SIZE)
		return (__memccpy_real(_d, _s, _c, _n));
#endif

	return (__memccpy_chk(_d, _s, _c, _n, _bos));
}
#endif /* __XSI_VISIBLE */


__FORTIFY_INLINE void *
memchr(const void *_s, int _c, size_t _n)
{
	size_t _bos = __bos(_s);

#ifndef __clang__
	if (_bos == __FORTIFY_UNKNOWN_SIZE)
		return (__memchr_real(_s, _c, _n));

	if (__builtin_constant_p(_n) && (_n > _bos))
		__memchr_buf_size_error();

	/*
	 * Compiler can prove, at compile time, that the passed in size
	 * is always <= the actual object size. Don't call __memchr_chk.
	 */
	if (__builtin_constant_p(_n) && (_n <= _bos))
		return (__memchr_real(_s, _c, _n));
#endif

	return (__memchr_chk(_s, _c, _n, _bos));
}


#if __BSD_VISIBLE
__FORTIFY_INLINE void *
memrchr(const void *_s, int _c, size_t _n)
{
	size_t _bos = __bos(_s);

#ifndef __clang__
	if (_bos == __FORTIFY_UNKNOWN_SIZE)
		return (__memrchr_real(_s, _c, _n));

	if (__builtin_constant_p(_n) && (_n > _bos))
		(__memrchr_buf_size_error());

	if (__builtin_constant_p(_n) && (_n <= _bos))
		return __memrchr_real(_s, _c, _n);
#endif

	return (__memrchr_chk(_s, _c, _n, _bos));
}
#endif /* __BSD_VISIBLE */


__FORTIFY_INLINE void *
memcpy(void * __restrict _d, const void * __restrict _s, size_t _n)
{
	size_t _bos = __bos0(_d);

#ifndef __clang__
	if (_bos == __FORTIFY_UNKNOWN_SIZE)
		return (__memcpy_real(_d, _s, _n));
#endif

	return (__memcpy_chk(_d, _s, _n, _bos));
}


__FORTIFY_INLINE void *
memmove(void *_d, const void *_s, size_t _n)
{
	size_t _bos = __bos0(_d);

#ifndef __clang__
	if (_bos == __FORTIFY_UNKNOWN_SIZE)
		return (__memmove_real(_d, _s, _n));
#endif

	return (__memmove_chk(_d, _s, _n, _bos));
}


#if __POSIX_VISIBLE >= 200809
__FORTIFY_INLINE char *
stpcpy(char * __restrict _d, const char * __restrict _s)
{
	size_t _bos = __bos(_d);

#ifndef __clang__
	if (_bos == __FORTIFY_UNKNOWN_SIZE)
		return (__stpcpy_real(_d, _s));
#endif

	return (__stpcpy_chk(_d, _s, _bos));
}
#endif /* __POSIX_VISIBLE */


__FORTIFY_INLINE char *
strcpy(char * __restrict _d, const char * __restrict _s)
{
	size_t _bos = __bos(_d);

#ifndef __clang__
	if (_bos == __FORTIFY_UNKNOWN_SIZE)
		return (__strcpy_real(_d, _s));
#endif

	return (__strcpy_chk(_d, _s, _bos));
}


#if __POSIX_VISIBLE >= 200809
__FORTIFY_INLINE char *
stpncpy(char * __restrict _d, const char * __restrict _s, size_t _n)
{
	size_t _d_bos = __bos(_d);
	size_t _s_bos = __bos(_s);
#ifndef __clang__
	size_t _slen;

	if (_d_bos == __FORTIFY_UNKNOWN_SIZE)
		return (__stpncpy_real(_d, _s, _n));

	if (_s_bos == __FORTIFY_UNKNOWN_SIZE)
		return (__stpncpy_chk(_d, _s, _n, _d_bos));

	if (__builtin_constant_p(_n) && (_n <= _s_bos))
		return (__stpncpy_chk(_d, _s, _n, _d_bos));

	_slen = __builtin_strlen(_s);
	if (__builtin_constant_p(_slen))
		return (__stpncpy_chk(_d, _s, _n, _d_bos));
#endif

	return (__stpncpy_chk2(_d, _s, _n, _d_bos, _s_bos));
}
#endif /* __POSIX_VISIBLE */


__FORTIFY_INLINE char *
strncpy(char * __restrict _d, const char * __restrict _s, size_t _n)
{
	size_t _d_bos = __bos(_d);
	size_t _s_bos = __bos(_s);
#ifndef __clang__
	size_t _slen;

	if (_d_bos == __FORTIFY_UNKNOWN_SIZE)
		return (__strncpy_real(_d, _s, _n));

	if (_s_bos == __FORTIFY_UNKNOWN_SIZE)
		return (__strncpy_chk(_d, _s, _n, _d_bos));

	if (__builtin_constant_p(_n) && (_n <= _s_bos))
		return (__strncpy_chk(_d, _s, _n, _d_bos));

	_slen = __builtin_strlen(_s);
	if (__builtin_constant_p(_slen))
		return (__strncpy_chk(_d, _s, _n, _d_bos));
#endif

	return (__strncpy_chk2(_d, _s, _n, _d_bos, _s_bos));
}


__FORTIFY_INLINE char *
strcat(char * __restrict _d, const char * __restrict _s)
{
	size_t _bos = __bos(_d);

#ifndef __clang__
	if (_bos == __FORTIFY_UNKNOWN_SIZE)
		return (__strcat_real(_d, _s));
#endif

	return (__strcat_chk(_d, _s, _bos));
}


__FORTIFY_INLINE char *
strncat(char * __restrict _d, const char * __restrict _s, size_t _n)
{
	size_t _bos = __bos(_d);

#ifndef __clang__
	if (_bos == __FORTIFY_UNKNOWN_SIZE)
		return (__strncat_real(_d, _s, _n));
#endif

	return (__strncat_chk(_d, _s, _n, _bos));
}


__FORTIFY_INLINE void *
memset(void *_s, int _c, size_t _n)
{
	size_t _bos = __bos(_s);

#ifndef __clang__
	if (_bos == __FORTIFY_UNKNOWN_SIZE)
		return (__memset_real(_s, _c, _n));
#endif

	return (__memset_chk(_s, _c, _n, _bos));
}


#if __BSD_VISIBLE
__FORTIFY_INLINE size_t
strlcpy(char * __restrict _d, const char * __restrict _s, size_t _n)
{
	size_t _bos = __bos(_d);

#ifndef __clang__
	/* Compiler doesn't know destination size. Don't call __strlcpy_chk. */
	if (_bos == __FORTIFY_UNKNOWN_SIZE)
		return (__strlcpy_real(_d, _s, _n));

	/*
	 * Compiler can prove, at compile time, that the passed in size
	 * is always <= the actual object size. Don't call __strlcpy_chk.
	 */
	if (__builtin_constant_p(_n) && (_n <= _bos))
		return (__strlcpy_real(_d, _s, _n));
#endif

	return (__strlcpy_chk(_d, _s, _n, _bos));
}
#endif /* __BSD_VISIBLE */


#if __BSD_VISIBLE
__FORTIFY_INLINE size_t
strlcat(char * __restrict _d, const char * __restrict _s, size_t _n)
{
	size_t _bos = __bos(_d);

#ifndef __clang__
	/* Compiler doesn't know destination size. Don't call __strlcat_chk. */
	if (_bos == __FORTIFY_UNKNOWN_SIZE)
		return (__strlcat_real(_d, _s, _n));

	/*
	 * Compiler can prove, at compile time, that the passed in size
	 * is always <= the actual object size. Don't call __strlcat_chk.
	 */
	if (__builtin_constant_p(_n) && (_n <= _bos))
		return (__strlcat_real(_d, _s, _n));
#endif

	return (__strlcat_chk(_d, _s, _n, _bos));
}
#endif /* __BSD_VISIBLE */


__FORTIFY_INLINE size_t
strlen(const char *_s)
{
	size_t _bos = __bos(_s);
#ifndef __clang__
	size_t _slen;

	/* Compiler doesn't know destination size. Don't call __strlen_chk. */
	if (_bos == __FORTIFY_UNKNOWN_SIZE)
		return (__strlen_real(_s));

	_slen = __builtin_strlen(_s);
	if (__builtin_constant_p(_slen))
		return (_slen);
#endif

	return (__strlen_chk(_s, _bos));
}

__FORTIFY_INLINE char *
strchr(const char *_s, int _c)
{
	size_t _bos = __bos(_s);
#ifndef __clang__
	size_t _slen;

	/* Compiler doesn't know destination size. Don't call __strchr_chk. */
	if (_bos == __FORTIFY_UNKNOWN_SIZE)
		return (__strchr_real(_s, _c));

	/*
	 * Compiler can prove, at compile time, that the passed in size
	 * is always <= the actual object size. Don't call __strlchr_chk.
	 */
	_slen = __builtin_strlen(_s);
	if (__builtin_constant_p(_slen) && (_slen < _bos))
		return (__strchr_real(_s, _c));
#endif

	return (__strchr_chk(_s, _c, _bos));
}


#if __BSD_VISIBLE
__FORTIFY_INLINE char *
strchrnul(const char *_s, int _c)
{
	size_t _bos = __bos(_s);
#ifndef __clang__
	size_t _slen;

	/* Compiler doesn't know destination size. Don't call __strchr_chk. */
	if (_bos == __FORTIFY_UNKNOWN_SIZE)
		return (__strchrnul_real(_s, _c));
	/*
	 * Compiler can prove, at compile time, that the passed in size
	 * is always <= the actual object size. Don't call __strlchrnul_chk.
	 */
	_slen = __builtin_strlen(_s);
	if (__builtin_constant_p(_slen) && (_slen < _bos))
		return (__strchrnul_real(_s, _c));
#endif

	return (__strchrnul_chk(_s, _c, _bos));
}
#endif


__FORTIFY_INLINE char *
strrchr(const char *_s, int _c)
{
	size_t _bos = __bos(_s);
#ifndef __clang__
	size_t _slen;

	/* Compiler doesn't know destination size. Don't call __strrchr_chk. */
	if (_bos == __FORTIFY_UNKNOWN_SIZE)
		return (__strrchr_real(_s, _c));

	/*
	 * Compiler can prove, at compile time, that the passed in size
	 * is always <= the actual object size. Don't call __strlen_chk.
	 */
	_slen = __strlen_real(_s);
	if (__builtin_constant_p(_slen) && (_slen < _bos))
		return (__strrchr_real(_s, _c));
#endif

	return (__strrchr_chk(_s, _c, _bos));
}


#endif /* defined(__BSD_FORTIFY) */

__END_DECLS

#endif /* !_SECURE_STRING_H */
