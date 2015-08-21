/*-
 * Copyright (C) 2015 The Android Open Source Project
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
 * bionic rev: fed2659869ec41a93f655be8058568ddab419e01
 *
 * $FreeBSD$
 */

#undef _FORTIFY_SOURCE

#include <sys/cdefs.h>
#include <secure/security.h>
#include <stdio.h>
#include "secure/_stdio.h"

size_t
__fwrite_chk(const void * __restrict ptr, size_t size, size_t nmemb, FILE * __restrict stream, size_t bos)
{
	size_t total;

	if (__predict_false(bos == __FORTIFY_UNKNOWN_SIZE))
		return (fwrite(ptr, size, nmemb, stream));

	if (__predict_false(__size_mul_overflow(size, nmemb, &total))) {
		// overflow: trigger the error path in fwrite
		return (fwrite(ptr, size, nmemb, stream));
	}

	if (__predict_false(total > bos))
		__fortify_chk_fail("fwrite: prevented read past end of buffer");

	return (fwrite(ptr, size, nmemb, stream));
}
