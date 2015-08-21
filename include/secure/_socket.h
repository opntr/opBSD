/*
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
 * bionic rev: a8993c994e45ec2dc00dcef15910560e22d67be9 
 *
 * $FreeBSD$
 */


#ifndef _SYS_SOCKET_H_
#error "You should not use <secure/_socket.h> directly; include <sys/socket.h> instead."
#endif

#ifndef _SECURE_SOCKET_H_
#define _SECURE_SOCKET_H_

#include <sys/_null.h>
#include <secure/security.h>

__BEGIN_DECLS

extern ssize_t	__recvfrom_chk(int, void *, size_t, size_t, int, struct sockaddr * __restrict, socklen_t * __restrict);
extern ssize_t	__recvfrom_real(int, void *, size_t, int, const struct sockaddr *, socklen_t *) __RENAME(recvfrom);
__errordecl(__recvfrom_error, "recvfrom called with size bigger than buffer");

#ifdef __BSD_FORTIFY

__FORTIFY_INLINE ssize_t
recvfrom(int _s, void *_buf, size_t _len, int _flags, struct sockaddr * __restrict _from, socklen_t * __restrict _fromlen)
{
	size_t _bos = __bos0(_buf);

#ifndef __clang__
	if (_bos == __FORTIFY_UNKNOWN_SIZE)
		return (__recvfrom_real(_s, _buf, _len, _flags, _from, _fromlen));

	if (__builtin_constant_p(_len) && (_len <= _bos))
		return (__recvfrom_real(_s, _buf, _len, _flags, _from, _fromlen));

	if (__builtin_constant_p(_len) && (_len > _bos))
		__recvfrom_error();
#endif

	return (__recvfrom_chk(_s, _buf, _len, _bos, _flags, _from, _fromlen));
}


__FORTIFY_INLINE ssize_t
recv(int _s, void *_buf, size_t _len, int _flags)
{

	return recvfrom(_s, _buf, _len, _flags, NULL, 0);
}

#endif /* !__BSD_FORTIFY */

__END_DECLS

#endif /* !_SECURE_SOCKET_H */
