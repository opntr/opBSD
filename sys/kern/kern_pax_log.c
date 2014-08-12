/*-
 * Copyright (c) 2014, by Oliver Pinter <oliver.pntr at gmail.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD$
 */

#include <sys/cdefs.h>

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/types.h>
#include <sys/pax.h>
#include <sys/sbuf.h>
#include <sys/jail.h>
#include <machine/stdarg.h>

#define __PAX_LOG_TEMPLATE(SUBJECT, name)					\
void										\
pax_log_##name(struct prison *pr, const char *caller_name, const char* fmt, ...)\
{										\
	struct sbuf *sb;							\
	va_list args;								\
										\
	if ((pr != NULL) && (pr->pr_pax_log_log == 0))				\
		return;								\
										\
	sb = sbuf_new_auto();							\
	if (sb == NULL)								\
		panic("%s: Could not allocate memory", __func__);		\
	sbuf_printf(sb, "[PAX "#SUBJECT"] ");					\
	if (caller_name != NULL)						\
		sbuf_printf(sb, "%s: ", caller_name);				\
	va_start(args, fmt);							\
	sbuf_vprintf(sb, fmt, args);						\
	va_end(args);								\
	if (sbuf_finish(sb) != 0)						\
		panic("%s: Could not generate message", __func__);		\
										\
	printf("%s", sbuf_data(sb));						\
	sbuf_delete(sb);							\
}										\
										\
void										\
pax_ulog_##name(struct prison *pr, const char *caller_name, const char* fmt, ...)\
{										\
	struct sbuf *sb;							\
	va_list args;								\
										\
	if ((pr != NULL) && (pr->pr_pax_log_ulog == 0))				\
		return;								\
										\
	sb = sbuf_new_auto();							\
	if (sb == NULL)								\
		panic("%s: Could not allocate memory", __func__);		\
	sbuf_printf(sb, "[PAX "#SUBJECT"] ");					\
	if (caller_name != NULL)						\
		sbuf_printf(sb, "%s: ", caller_name);				\
	va_start(args, fmt);							\
	sbuf_vprintf(sb, fmt, args);						\
	va_end(args);								\
	if (sbuf_finish(sb) != 0)						\
		panic("%s: Could not generate message", __func__);		\
										\
	printf("%s", sbuf_data(sb));						\
	sbuf_delete(sb);							\
}

__PAX_LOG_TEMPLATE(ASLR, aslr)
