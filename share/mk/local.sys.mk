# $FreeBSD$

.if defined(.PARSEDIR)
SRCTOP:= ${.PARSEDIR:tA:H:H}
.else
SRCTOP:= ${.MAKE.MAKEFILES:M*/local.sys.mk:H:H:H}
.endif

.if ${.CURDIR} == ${SRCTOP}
RELDIR = .
.elif ${.CURDIR:M${SRCTOP}/*}
RELDIR := ${.CURDIR:S,${SRCTOP}/,,}
.endif
