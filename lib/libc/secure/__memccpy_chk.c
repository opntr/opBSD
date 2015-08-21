/*-
 * Copyright (C) 2015 Oliver Pinter
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

#undef _FORTIFY_SOURCE

#include <sys/cdefs.h>
#include <secure/security.h>
#include <string.h>
#include <stdlib.h>
#include "secure/_string.h"

void *
__memccpy_chk(void *dest, const void *src, int c, size_t n, size_t bos)
{
	void *ret;
	size_t len;

	if (__predict_false(bos == __FORTIFY_UNKNOWN_SIZE))
		return (memccpy(dest, src, c, n));

	if (__predict_false(n > bos))
		__fortify_chk_fail("memccpy: prevented write past end of buffer");

	/*
	 * If n was copied, then return NULL, otherwise
	 * a pointer to the byte after the copy of c in the string
	 * dest is returned.
	 *
	 * See the memccpy(3) manpage for more details.
	 */
	ret = memccpy(dest, src, c, n);
	if (ret != NULL)
		len = ret - dest;
	else
		len = n;

	/*
	 * The Open Group Base Specifications Issue 7
	 * IEEE Std 1003.1, 2013 Edition:
	 * Overlapping is undefined, check, prevent and inform the
	 * users about them.
	 * http://pubs.opengroup.org/onlinepubs/9699919799//functions/memccpy.html
	 */
	if (__predict_false(__fortify_chk_overlap(dest, src, len)))
		__fortify_chk_fail("memccpy: overlapping strings detected");

	return (ret);
}
