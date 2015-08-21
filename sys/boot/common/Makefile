# $FreeBSD$

.include <src.opts.mk>

MK_FORTIFY=	no

MAN+=	loader.8
.if ${MK_ZFS} != "no"
MAN+=	zfsloader.8
.endif

.include <bsd.prog.mk>
