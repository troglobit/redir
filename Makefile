CC = gcc

# if your system lacks getopt_long, remove the comment from this line
OBJS = redir.o # getopt/getopt.o getopt/getopt1.o

# if your system lacks strrchr() or strdup(), or you want TCP wrappers
# support, edit this line
CFLAGS = -O2 -Wall # -DUSE_TCP_WRAPPERS # -DNEED_STRRCHR -DNEED_STRDUP
LDFLAGS = -s

# solaris, and others, may also need these libraries to link
# also edit here if you're using the TCP wrappers code
LIBS = #-lwrap #-lnsl -lsocket

all: redir

clean:
	rm -f *.o redir core

redir:		${OBJS}
	${CC} ${LDFLAGS} -o redir ${OBJS} ${LIBS}




