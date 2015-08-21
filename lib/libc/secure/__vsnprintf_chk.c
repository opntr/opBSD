/*-
 * Copyright (C) 2012 The Android Open Source Project
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

#undef _FORTIFY_SOURCE

#include <sys/cdefs.h>
#include <secure/security.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include "secure/_stdio.h"

int
__vsnprintf_chk(char *d, size_t n, int flags, size_t bos, const char *fmt, va_list va)
{

	if (__predict_false(bos == __FORTIFY_UNKNOWN_SIZE))
		return (vsnprintf(d, n, fmt, va));

	if (__predict_false(n > bos))
		__fortify_chk_fail(
		    "vsnprintf: prevented write past end of buffer");

	return (vsnprintf(d, n, fmt, va));
}


int
__snprintf_chk(char *d, size_t n, int flags, size_t bos, const char *fmt, ...)
{
	va_list va;
	int result;

	if (bos == __FORTIFY_UNKNOWN_SIZE) {
		va_start(va, fmt);
		result = vsnprintf(d, n, fmt, va);
		va_end(va);

		return (result);
	}

	va_start(va, fmt);
	result = __vsnprintf_chk(d, n, flags, bos, fmt, va);
	va_end(va);

	return (result);
}
