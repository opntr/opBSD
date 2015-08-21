/*-
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
 * bionic rev: d807b9a12d3e49132b095df3d883618452033b51
 *
 * $FreeBSD$
 */

#ifndef _SYS_STAT_H_
#error "You should not use <secure/_stat.h> directly; include <sys/stat.h> instead."
#endif

#ifndef _SECURE_STAT_H_
#define	_SECURE_STAT_H_

#include <secure/security.h>

__BEGIN_DECLS

extern mode_t __umask_chk(mode_t);
#ifndef __FORTIFY_UMASK_REAL
#define	__FORTIFY_UMASK_REAL	1
extern mode_t __umask_real(mode_t) __RENAME(umask);
#endif
__errordecl(__umask_invalid_mode, "umask called with invalid mode");

#ifdef __BSD_FORTIFY

__FORTIFY_INLINE mode_t
umask(mode_t _mode)
{
#ifndef __clang__
	if (__builtin_constant_p(_mode)) {
		if ((_mode & 0777) != _mode)
			__umask_invalid_mode();

		return (__umask_real(_mode));
	}
#endif
	return (__umask_chk(_mode));
}
#endif /* defined(__BSD_FORTIFY) */

__END_DECLS

#endif /* !_SECURE_STAT_H_ */
