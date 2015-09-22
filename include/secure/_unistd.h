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

#ifndef _UNISTD_H_
#error "You should not use <secure/_unistd.h> directly; include <unistd.h> instead."
#endif

#ifndef _SECURE_UNISTD_H_
#define	_SECURE_UNISTD_H_

#include <sys/limits.h>
#include <secure/security.h>

__BEGIN_DECLS

extern char	*__getcwd_chk(char*, size_t, size_t);
extern char	*__getcwd_real(char*, size_t) __RENAME(getcwd);
__errordecl(__getcwd_dest_size_error, "getcwd called with size bigger than destination");
extern ssize_t	 __pread_chk(int, void *, size_t, off_t, size_t);
extern ssize_t	 __pread_real(int, void *, size_t, off_t) __RENAME(pread);
__errordecl(__pread_dest_size_error, "pread called with size bigger than destination");
__errordecl(__pread_count_toobig_error, "pread called with count > SSIZE_MAX");
extern ssize_t	 __read_chk(int, void *, size_t, size_t);
extern ssize_t	 __read_real(int, void *, size_t) __RENAME(read);
__errordecl(__read_dest_size_error, "read called with size bigger than destination");
__errordecl(__read_count_toobig_error, "read called with count > SSIZE_MAX");
extern ssize_t	 __readlink_chk(const char *, char *, size_t, size_t);
extern ssize_t	 __readlink_real(const char *, char *, size_t) __RENAME(readlink);
__errordecl(__readlink_dest_size_error, "readlink called with size bigger than destination");
__errordecl(__readlink_size_toobig_error, "readlink called with size > SSIZE_MAX");
extern ssize_t	 __readlinkat_chk(int, const char *, char *, size_t, size_t);
extern ssize_t	 __readlinkat_real(int, const char *, char *, size_t) __RENAME(readlinkat);
__errordecl(__readlinkat_dest_size_error, "readlinkat called with size bigger than destination");
__errordecl(__readlinkat_size_toobig_error, "readlinkat called with size > SSIZE_MAX");

#ifdef __BSD_FORTIFY

__FORTIFY_INLINE
char *
getcwd(char *_buf, size_t _size)
{
	size_t	_bos = __object_size(_buf);

#ifdef __clang__
	/*
	 * Work around LLVM's incorrect __builtin_object_size implementation
	 * here to avoid needing the workaround in the __getcwd_chk ABI
	 * forever.
	 * 
	 * https://llvm.org/bugs/show_bug.cgi?id=23277
	 */
	if (_buf == NULL)
		_bos = __FORTIFY_UNKNOWN_SIZE;
#else
	if (_bos == __FORTIFY_UNKNOWN_SIZE)
		return (__getcwd_real(_buf, _size));
	if (__builtin_constant_p(_size) && (_size > _bos))
		__getcwd_dest_size_error();
	if (__builtin_constant_p(_size) && (_size <= _bos))
		return (__getcwd_real(_buf, _size));
#endif

	return (__getcwd_chk(_buf, _size, _bos));
}


/* 1003.1-2008 */
#if __POSIX_VISIBLE >= 200809 || __XSI_VISIBLE
__FORTIFY_INLINE ssize_t
pread(int _fd, void *_buf, size_t _count, off_t _offset)
{
	size_t _bos = __object_size_type0(_buf);

#ifndef __clang__
	if (__builtin_constant_p(_count) && (_count > SSIZE_MAX))
		__pread_count_toobig_error();

	if (_bos == __FORTIFY_UNKNOWN_SIZE)
		return (__pread_real(_fd, _buf, _count, _offset));

	if (__builtin_constant_p(_count) && (_count > _bos))
		__pread_dest_size_error();

	if (__builtin_constant_p(_count) && (_count <= _bos))
		return (__pread_real(_fd, _buf, _count, _offset));
#endif

	return (__pread_chk(_fd, _buf, _count, _offset, _bos));
}
#endif /* __POSIX_VISIBLE >= 200809 || __XSI_VISIBLE */


__FORTIFY_INLINE ssize_t
read(int _fd, void *_buf, size_t _count)
{
	size_t _bos = __object_size_type0(_buf);

#ifndef __clang__
	if (__builtin_constant_p(_count) && (_count > SSIZE_MAX))
		__read_count_toobig_error();

	if (_bos == __FORTIFY_UNKNOWN_SIZE)
		return (__read_real(_fd, _buf, _count));

	if (__builtin_constant_p(_count) && (_count > _bos))
		__read_dest_size_error();

	if (__builtin_constant_p(_count) && (_count <= _bos))
		return (__read_real(_fd, _buf, _count));
#endif

	return (__read_chk(_fd, _buf, _count, _bos));
}


/* 1003.1-2001 */
#if __POSIX_VISIBLE >= 200112 || __XSI_VISIBLE
__FORTIFY_INLINE ssize_t
readlink(const char *_path, char *_buf, size_t _size)
{
	size_t _bos = __object_size(_buf);

#ifndef __clang__
	if (__builtin_constant_p(_size) && (_size > SSIZE_MAX))
		__readlink_size_toobig_error();

	if (_bos == __FORTIFY_UNKNOWN_SIZE)
		return (__readlink_real(_path, _buf, _size));

	if (__builtin_constant_p(_size) && (_size > _bos))
		__readlink_dest_size_error();

	if (__builtin_constant_p(_size) && (_size <= _bos))
		return (__readlink_real(_path, _buf, _size));
#endif

	return (__readlink_chk(_path, _buf, _size, _bos));
}
#endif /* __POSIX_VISIBLE >= 200112 || __XSI_VISIBLE */


#if __POSIX_VISIBLE >= 200809
__FORTIFY_INLINE ssize_t
readlinkat(int _dirfd, const char *_path, char *_buf, size_t _size)
{
	size_t _bos = __object_size(_buf);

#ifndef __clang__
	if (__builtin_constant_p(_size) && (_size > SSIZE_MAX))
		(__readlinkat_size_toobig_error());

	if (_bos == __FORTIFY_UNKNOWN_SIZE)
		return (__readlinkat_real(_dirfd, _path, _buf, _size));

	if (__builtin_constant_p(_size) && (_size > _bos))
		__readlinkat_dest_size_error();

	if (__builtin_constant_p(_size) && (_size <= _bos))
		return (__readlinkat_real(_dirfd, _path, _buf, _size));
#endif

	return (__readlinkat_chk(_dirfd, _path, _buf, _size, _bos));
}
#endif /* __POSIX_VISIBLE >= 200809 */

#endif	/* defined(__BSD_FORTIFY) */

__END_DECLS

#endif	/* !_SECURE_UNISTD_H_ */
