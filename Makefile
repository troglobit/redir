### user configuration section

# if your system lacks getopt_long(), remove the comment from this line
GETOPT_OBJS = # getopt/getopt.o getopt/getopt1.o

# if your system lacks strrchr() or strdup(), edit this line
STR_CFLAGS = # -DNEED_STRRCHR -DNEED_STRDUP

# if you would like support for TCP wrappers (and have libwrap.a
# installed), remove these comments.

WRAP_CFLAGS = -DUSE_TCP_WRAPPERS 
WRAP_LIBS = -lwrap

# if your system needs any additional libraries (solaris, for example, 
# needs the ones commented out below), edit this line.

EXTRA_LIBS = #-lnsl -lsocket

# add additional compiler flags here.  Some useful ones are:
#
# -DNO_SHAPER (doesn't compile in traffic shaping code)
# -DNO_FTP (doesn't compile in FTP redirection support)

EXTRA_CFLAGS = # -DNO_SHAPER -DNO_FTP

### end of user configuration section

# redir requires gcc.  if you're lucky, another compiler might work.
CC = gcc

# if your system lacks getopt_long, remove the comment from this line
OBJS = redir.o $(GETOPT_OBJS)

CFLAGS = -O2 -Wall --pedantic $(STR_CFLAGS) $(WRAP_CFLAGS) $(EXTRA_CFLAGS)
LDFLAGS = # -s

# solaris, and others, may also need these libraries to link
# also edit here if you're using the TCP wrappers code
LIBS =  $(WRAP_LIBS) $(EXTRA_LIBS)
# this line should build under os/2 using syslog from
# http://r350.ee.ntu.edu.tw/~hcchu/os2/ports/dev
# submitted by: Doug LaRue (dlarue@nosc.mil)
# LIBS = -lsyslog -lsocket

all: redir

clean:
	rm -f $(OBJS) redir core

redir:		${OBJS}
	${CC} ${LDFLAGS} -o redir ${OBJS} ${LIBS}




