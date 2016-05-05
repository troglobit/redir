A TCP port redirector for UNIX
==============================
[![Travis Status][]][Travis] [![Coverity Status]][Coverity Scan]

This is a TCP port redirector for UNIX.  It can run under inetd or
standalone (in which case it handles multiple connections).  It is 8 bit
clean, not limited to line mode, is small and lightweight.  If you want
access control, run it under xinetd, or inetd with TCP wrappers.

Redir listens for TCP connections on a given port, and, when it recieves
a connection, then connects to a given destination address:port, and
pass data between them.  It finds most of its applications in traversing
firewalls, but, of course, there are other uses.


Usage
-----

Consult the man page, or call it with `redir -h` for usage help.

    redir [-hidtnsIxbfpzmwov] [SRC]:PORT [DST]:PORT


Examples
--------

To redirect port 80 to a webserver listening on loopback port 8080,
remember to use `sudo` when using priviliged ports:

    sudo redir :80 127.0.0.1:8080

This starts `redir` as a standard UNIX daemon in the background, with
all log messages sent to the syslog.  Use `-n` to foreground and see log
messages on `stderr`.

To run `redir` from a process monitor like Finit or systemd, tell it to
not background itself and to only use the syslog for log messages:

    redir -n -s :80 127.0.0.1:8080

An `/etc/inetd.conf` line of the same may look like this:

    http  stream  tcp  nowait  root  /usr/sbin/tcpd /usr/bin/redir -i 127.0.0.1:8080


Building
--------

Redir comes with a GNU configure script which you can use to adapt the
build to your needs.  If you would like to remove support for some
extended options (for the sake of speed, code size, whatever), try the
following options to configure:

    --disable-shaper   Disable traffic shaping code
    --disable-ftp      Disable FTP redirection support


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
[Travis]:          https://travis-ci.org/troglobit/redir
[Travis Status]:   https://travis-ci.org/troglobit/redir.png?branch=master
[Coverity Scan]:   https://scan.coverity.com/projects/8740
[Coverity Status]: https://scan.coverity.com/projects/8740/badge.svg
