PROG=greu
SRCS=greu.c
CFLAGS+=-Wall
LDADD=-levent
DPADD=${LIBEVENT}
MAN=

.include <bsd.prog.mk>
