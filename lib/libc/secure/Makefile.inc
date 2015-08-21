# $FreeBSD$
#
# libc sources related to security

.PATH: ${LIBC_SRCTOP}/secure

# Sources common to both syscall interfaces:
SRCS+=	\
	fortify_source.c \
	secure_common.c \
	stack_protector.c \
	stack_protector_compat.c

# Sources which contains FORTIFY_SOURCE functions:
#SRCS+=	

# Sources which contains FORTIFY_SOURCE functions,
# but live in .h files under sys/sys
SRCS+=	\
	__poll_chk.c

SYM_MAPS+=    ${LIBC_SRCTOP}/secure/Symbol.map
