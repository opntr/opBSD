# $FreeBSD$

.PATH: ${.CURDIR:H}/resolv

TESTSDIR=	${TESTSBASE}/lib/libc/nss

BINDIR=		${TESTSDIR}

ATF_TESTS_C+=	getaddrinfo_test
ATF_TESTS_C+=	getgr_test
ATF_TESTS_C+=	gethostby_test
TEST_METADATA.gethostby_test=	timeout="1200"
ATF_TESTS_C+=	getpw_test
ATF_TESTS_C+=	getproto_test
ATF_TESTS_C+=	getrpc_test
ATF_TESTS_C+=	getserv_test
ATF_TESTS_C+=	getusershell_test

FILES+=		mach

WARNS?=		1

CFLAGS+=	-I${SRCTOP}/tests

.include <bsd.test.mk>
