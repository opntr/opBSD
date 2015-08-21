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
SRCS+=	\
	__fgets_chk.c \
	__fread_chk.c \
	__fwrite_chk.c \
	__getcwd_chk.c \
	__memccpy_chk.c \
	__memchr_chk.c \
	__memcpy_chk.c \
	__memmove_chk.c \
	__memrchr_chk.c \
	__memset_chk.c \
	__pread_chk.c \
	__read_chk.c \
	__readlink_chk.c \
	__readlinkat_chk.c \
	__stpcpy_chk.c \
	__stpncpy_chk.c \
	__strcat_chk.c \
	__strchr_chk.c \
	__strchrnul_chk.c \
	__strcpy_chk.c \
	__strlcat_chk.c \
	__strlcpy_chk.c \
	__strlen_chk.c \
	__strncat_chk.c \
	__strncpy_chk.c \
	__strrchr_chk.c \
	__vsnprintf_chk.c \
	__vsprintf_chk.c

# Sources which contains FORTIFY_SOURCE functions,
# but live in .h files under sys/sys
SRCS+=	\
	__poll_chk.c \
	__recvfrom_chk.c \
	__umask_chk.c

SYM_MAPS+=    ${LIBC_SRCTOP}/secure/Symbol.map
