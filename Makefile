CC = gcc
# Needed for Sun dev
#CFLAGS = -g -I. -DNEED_STRCHR -DNEED_STRDUP
#LIBS =  ../textutils-1.14/lib/libtu.a
CFLAGS = #-O2
LDFLAGS = #-s

all: redir

redir:		redir.o
	${CC} ${LDFLAGS} -o redir redir.o ${LIBS}

redir.o:	redir.c

