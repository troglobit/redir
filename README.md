A TCP port redirector for UNIX
==============================
[![Travis Status][]][Travis] [![Coverity Status]][Coverity Scan]

This is a TCP port redirector for UNIX.  It can be run under inetd or as
standalone (in which case it handles multiple connections).  It is 8 bit
clean, not limited to line mode, is small and lightweight.  If you want
access control, run it under xinetd, or inetd with TCP wrappers.

Redir listens for TCP connections on a given port, and, when it recieves
a connection, then connects to a given destination `address:port`, and
pass data between them.  It finds most of its applications in traversing
firewalls, but, of course, there are other uses.

For a UDP port redirector, see [uredir](https://github.com/troglobit/uredir/).

Usage
-----

Consult the man page for details.

    Usage: redir [-hinspv] [-b IP]  [-f TYPE] [-I NAME] [-l LEVEL] [-t SEC]
                           [-x STR] [-m BPS] [-o FLAG] [-w MSEC] [-z BYTES]
                           [SRC]:PORT [DST]:PORT
    
    Options:
      -b,--bind=IP            Force specific IP to bind() to when listening for
                              incoming connections.  Not applicable with -p
      -f,--ftp=TYPE           Redirect FTP connections.  Where type is
                              one of: 'port', 'pasv', or 'both'
      -h,--help               Show this help text
      -i,--inetd              Run from inetd, SRC:PORT comes from stdin
                              Usage: redir [OPTIONS] [DST]:PORT
      -I,--ident=NAME         Identity, tag syslog messages with NAME
                              Also used as service name for TCP wrappers
      -l,--loglevel=LEVEL     Set log level: none, err, notice*, info, debug
      -n,--foreground         Run in foreground, do not detach from terminal
      -p,--transproxy         Run in Linux's transparent proxy mode
      -s,--syslog             Log messages to syslog
      -t,--timeout=SEC        Set timeout to SEC seconds, default off (0)
      -v,--version            Show program version
      -x,--connect=STR        CONNECT string passed to proxy server
    
    Traffic Shaping:
      -m,--max-bandwidth=BPS  Limit the bandwidth to BPS bits/second
      -o,--wait-in-out=FLAG   Wait for in(1), out(2), or in&out(3)
      -w,--random-wait=MSEC   Wait MSEC milliseconds before each packet
      -z,--bufsize=BYTES      Size of the traffic shaping buffer
    
    SRC and DST are optional, redir will revert to use 0.0.0.0 (ANY)


### Old Syntax

**Note:** command line options changed in v3.0.  A limited subset of the
          old syntax is available with the `--enable-compat` configure
          option.  This implicitly also enables `-n` by default.


Examples
--------

To redirect port 80 to a webserver listening on loopback port 8080,
remember to use `sudo` when using priviliged ports:

    sudo redir :80 127.0.0.1:8080

This starts `redir` as a standard UNIX daemon in the background, with
all log messages sent to the syslog.  Use `-n` to foreground and see log
messages on `stderr`.

To run `redir` from a process monitor like [Finit][] or systemd, tell it
to not background itself and to only use the syslog for log messages:

    redir -n -s :80 127.0.0.1:8080

An `/etc/inetd.conf` line of the same looks very similar:

    http  stream  tcp  nowait  root  /usr/sbin/tcpd /usr/bin/redir -n -s -i 127.0.0.1:8080

When running multiple redir instances it can be useful to change how
they identify themselves:

    redir -I nntp www:119 netgate:119
    redir -I pop3 ftp:110 netgate:110

This starts an NNTP and a POP3 port redirector, named accordingly.
Previously therere was a `redir-wrapper` script included in the
distribution, but that is no longer maintained.


Building
--------

Redir comes with a  GNU configure script which you can  use to adapt the
build  to your  needs.  If  you would  like to  remove support  for some
extended options (for  the sake of speed, code size,  whatever), try the
following options to configure:

    --enable-compat    Enable limited v2.x command line syntax
    --disable-shaper   Disable traffic shaping code
    --disable-ftp      Disable FTP redirection support

The GNU Configure & Build system use `/usr/local` as the default install
prefix.  For most use-cases this is fine, but if you want to change this
to `/usr` use the `--prefix=/usr` configure option:

    ./configure --prefix=/usr
    make -j5
    sudo make install-strip

Building from GIT sources require you have `automake` and `autoconf`
installed.  Use `./autogen.sh` to create the configure script.


Origin & References
-------------------

Redir was originally created by [Sam Creasey][] and is now developed and
maintained at [GitHub][] by [Joachim Nilsson][].  Use GitHub to file bug
reports, clone, or send pull requests for bug fixes and extensions.

Redir is distributed under the terms of the GNU Public Licence, version
2 or later, distributed with this source archive in the file COPYING.

[Sam Creasey]:     http://sammy.net/~sammy/hacks/
[Joachim Nilsson]: http://troglobit.com
[GitHub]:          https://github.com/troglobit/redir
[Finit]:           https://github.com/troglobit/finit
[Travis]:          https://travis-ci.org/troglobit/redir
[Travis Status]:   https://travis-ci.org/troglobit/redir.png?branch=master
[Coverity Scan]:   https://scan.coverity.com/projects/8740
[Coverity Status]: https://scan.coverity.com/projects/8740/badge.svg
