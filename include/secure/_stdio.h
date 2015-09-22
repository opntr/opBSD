/*-
 * Copyright (c) 1990 The Regents of the University of California.
 * All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Chris Torek.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)stdio.h	5.17 (Berkeley) 6/3/91
 *	$OpenBSD: stdio.h,v 1.35 2006/01/13 18:10:09 miod Exp $
 *	$NetBSD: stdio.h,v 1.18 1996/04/25 18:29:21 jtc Exp $
 *	bionic rev: 6cc98af72b0c48c58b2ab5fdb5f7abb842175299
 *	$FreeBSD$
 */

#ifndef _STDIO_H_
#error "You should not use <secure/_stdio.h> directly; include <stdio.h> instead."
#endif

#ifndef	_SECURE_STDIO_H_
#define	_SECURE_STDIO_H_

#include <secure/security.h>
#include <stdarg.h>

__BEGIN_DECLS

extern char	*__fgets_chk(char *, int, FILE *, size_t);
extern char	*__fgets_real(char *, int, FILE *) __RENAME(fgets);
__errordecl(__fgets_too_big_error, "fgets called with size bigger than buffer");
__errordecl(__fgets_too_small_error, "fgets called with size less than zero");
extern size_t	__fread_chk(void * __restrict, size_t, size_t, FILE * __restrict, size_t);
extern size_t	__fread_real(void * __restrict, size_t, size_t, FILE * __restrict) __RENAME(fread);
__errordecl(__fread_too_big_error, "fread called with size * count bigger than buffer");
__errordecl(__fread_overflow, "fread called with overflowing size * count");
extern size_t	__fwrite_chk(const void * __restrict, size_t, size_t, FILE * __restrict, size_t);
extern size_t	__fwrite_real(const void * __restrict, size_t, size_t, FILE * __restrict) __RENAME(fwrite);
__errordecl(__fwrite_too_big_error, "fwrite called with size * count bigger than buffer");
__errordecl(__fwrite_overflow, "fwrite called with overflowing size * count");
extern int	__sprintf_chk(char * __restrict, int, size_t, const char * __restrict, ...);
extern int	__sprintf_real(char * __restrict, const char * __restrict, ...) __RENAME(sprintf);
extern int	__vsprintf_chk(char * __restrict, int, size_t, const char * __restrict, __va_list);
extern int	__vsprintf_real(char * __restrict, const char * __restrict, __va_list) __RENAME(vsprintf);

#if __ISO_C_VISIBLE >= 1999
extern int	__snprintf_chk(char * __restrict, size_t, int, size_t, const char * __restrict, ...);
extern int	__snprintf_real(char * __restrict, size_t, const char * __restrict, ...) __RENAME(snprintf) __printflike(3, 4);
extern int	__vsnprintf_chk(char * __restrict, size_t, int, size_t, const char * __restrict, __va_list);
extern int	__vsnprintf_real(char * __restrict, size_t, const char * __restrict, __va_list) __RENAME(vsnprintf) __printflike(3, 0);
#endif

#ifdef __BSD_FORTIFY

#if __ISO_C_VISIBLE >= 1999
__FORTIFY_INLINE __printflike(3, 0) int
vsnprintf(char *_dest, size_t _size, const char *_format, __va_list _ap)
{
	size_t _bos = __object_size(_dest);

#ifndef __clang__
	if (_bos == __FORTIFY_UNKNOWN_SIZE)
		return (__vsnprintf_real(_dest, _size, _format, _ap));
#endif

	return (__vsnprintf_chk(_dest, _size, 0, _bos, _format, _ap));
}
#endif /* __ISO_C_VISIBLE */

__FORTIFY_INLINE __printflike(2, 0) int
vsprintf(char *_dest, const char *_format, __va_list _ap)
{
	size_t _bos = __object_size(_dest);

#ifndef __clang__
	if (_bos == __FORTIFY_UNKNOWN_SIZE)
		return (__vsprintf_real(_dest, _format, _ap));
#endif

	return (__vsprintf_chk(_dest, 0, _bos, _format, _ap));
}


#if __ISO_C_VISIBLE >= 1999
#if !__has_builtin(__builtin_va_arg_pack) && !__GNUC_PREREQ__(4, 3)	/* defined(__clang__) */
#if !defined(snprintf) && !defined(__cplusplus)
#define	__wrap_snprintf(_dest, _size, ...)	__snprintf_chk(_dest, _size, 0, __object_size(_dest), __VA_ARGS__)
#define	snprintf(...)	__wrap_snprintf(__VA_ARGS__)
#endif /* !snprintf */
#else /* __GNUC_PREREQ__(4, 3) */
__FORTIFY_INLINE __printflike(3, 4) int
snprintf(char *_dest, size_t _size, const char *_format, ...)
{
	size_t _bos = __object_size(_dest);

	if (_bos == __FORTIFY_UNKNOWN_SIZE)
		return (__snprintf_real(_dest, _size, _format,
		    __builtin_va_arg_pack()));

	return (__snprintf_chk(_dest, _size, 0, _bos, _format,
	    __builtin_va_arg_pack()));
}
#endif /* !__GNUC_PREREQ__(4, 3) */
#endif /* __ISO_C_VISIBLE */

#if !__has_builtin(__builtin_va_arg_pack) && !__GNUC_PREREQ__(4, 3)	/* defined(__clang__) */
#if !defined(sprintf) && !defined(__cplusplus)
#define	__wrap_sprintf(_dest, ...)	__sprintf_chk(_dest, 0, __object_size(_dest), __VA_ARGS__)
#define	sprintf(...)	__wrap_sprintf(__VA_ARGS__)
#endif /* !sprintf */
#else /* __GNUC_PREREQ__(4, 3) */
__FORTIFY_INLINE __printflike(2, 3) int
sprintf(char *_dest, const char *_format, ...)
{
	size_t _bos = __object_size(_dest);

	if (_bos == __FORTIFY_UNKNOWN_SIZE)
		return (__sprintf_real(_dest, _format,
		    __builtin_va_arg_pack()));

	return (__sprintf_chk(_dest, 0, _bos, _format,
	    __builtin_va_arg_pack()));
}

#endif /* !__GNUC_PREREQ__(4, 3) */

__FORTIFY_INLINE char *
fgets(char *_buf, int _n, FILE *_stream)
{
	size_t _bos = __object_size(_buf);

#ifndef __clang__
	/*
	 * Compiler can prove, at compile time, that the passed in size
	 * is always negative.
	 * Force a compiler error.
	 */
	if (__builtin_constant_p(_n) && (_n < 0))
		__fgets_too_small_error();
	/*
	 * Compiler doesn 't know destination size.
	 * Don' t call __fgets_chk.
	 */
	if (_bos == __FORTIFY_UNKNOWN_SIZE)
		return (__fgets_real(_buf, _n, _stream));
	/*
	 * Compiler can prove, at compile time, that the passed in size
	 * is always <= the actual object size.
	 * Don 't call __fgets_chk.
	 */
	if (__builtin_constant_p(_n) && (_n <= (int)_bos))
		return (__fgets_real(_buf, _n, _stream));
	/*
	 * Compiler can prove, at compile time, that the passed in size
	 * is always > the actual object size.
	 * Force a compiler error.
	 */
	if (__builtin_constant_p(_n) && (_n > (int)_bos))
		__fgets_too_big_error();
#endif
	return (__fgets_chk(_buf, _n, _stream, _bos));
}


__FORTIFY_INLINE size_t
fread(void * __restrict _ptr, size_t _size, size_t _nmemb, FILE * __restrict _stream)
{
	size_t _bos = __object_size_type0(_ptr);
#ifndef __clang__
	size_t _total;

	if (_bos == __FORTIFY_UNKNOWN_SIZE)
		return (__fread_real(_ptr, _size, _nmemb, _stream));

	if (__builtin_constant_p(_size) && __builtin_constant_p(_nmemb)) {
		if (__size_mul_overflow(_size, _nmemb, &_total))
			__fread_overflow();

		if (_total > _bos)
			__fread_too_big_error();

		return (__fread_real(_ptr, _size, _nmemb, _stream));
	}
#endif

	return (__fread_chk(_ptr, _size, _nmemb, _stream, _bos));
}


__FORTIFY_INLINE size_t
fwrite(const void * __restrict _ptr, size_t _size, size_t _nmemb, FILE * __restrict _stream)
{
	size_t _bos = __object_size_type0(_ptr);
#ifndef __clang__
	size_t _total;

	if (_bos == __FORTIFY_UNKNOWN_SIZE)
		return __fwrite_real(_ptr, _size, _nmemb, _stream);

	if (__builtin_constant_p(_size) && __builtin_constant_p(_nmemb)) {
		if (__size_mul_overflow(_size, _nmemb, &_total))
			__fwrite_overflow();

		if (_total > _bos)
			__fwrite_too_big_error();

		return (__fwrite_real(_ptr, _size, _nmemb, _stream));
	}
#endif

	return (__fwrite_chk(_ptr, _size, _nmemb, _stream, _bos));
}

#endif /* defined(__BSD_FORTIFY) */

__END_DECLS

#endif /* !_SECURE_STDIO_H_ */
