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
#include <string.h>
#include <stdlib.h>
#include "secure/_string.h"

char *
__strncpy_chk(char *__restrict d, const char *__restrict s, size_t n, size_t bos)
{

	if (__predict_false(bos == __FORTIFY_UNKNOWN_SIZE))
		return (strncpy(d, s, n));

	if (__predict_false(n > bos))
		__fortify_chk_fail(
		    "strncpy: prevented write past end of buffer");

	return (strncpy(d, s, n));
}

/*
 * __strncpy_chk2
 *
 * This is a variant of __strncpy_chk, but it also checks to make
 * sure we don't read beyond the end of "src". The code for this is
 * based on the original version of strncpy, but modified to check
 * how much we read from "src" at the end of the copy operation.
 */
char *
__strncpy_chk2(char *__restrict d, const char *__restrict s, size_t n, size_t d_bos, size_t s_bos)
{
	size_t s_copy_len;

	if (__predict_false(d_bos == __FORTIFY_UNKNOWN_SIZE))
		return (strncpy(d, s, n));

	if (__predict_false(s_bos == __FORTIFY_UNKNOWN_SIZE))
		return (__strncpy_chk(d, s, n, d_bos));

	if (__predict_false(n > d_bos))
		__fortify_chk_fail("strncpy: prevented write past end of buffer");

	if (n != 0) {
		char *_d = d;
		const char *_s = s;

		do {
			if ((*_d++ = *_s++) == 0) {
				/* NUL pad the remaining n-1 bytes */
				while (--n != 0)
					*_d++ = 0;
				break;
			}
		} while (--n != 0);

		s_copy_len = (size_t)(_s - s);

		if (__predict_false(s_copy_len > s_bos))
			__fortify_chk_fail("strncpy: prevented read past end of buffer");
	}

	return (d);
}
