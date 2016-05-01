A TCP port redirector for UNIX
==============================
[![Travis Status][]][Travis] [![Coverity Status]][Coverity Scan]

[Redir][home] is a port redirector for UNIX.  It can run under inetd or
standalone (in which case it handles multiple connections).  It is 8 bit
clean, not limited to line mode, is small and light.  If you want access
control run it under xinetd, or inetd with TCP wrappers.

Redir listens for TCP connections on a given port, and, when it recieves
a connection, then connects to a given destination address/port, and
pass data between them.  It finds most of its applications in traversing
firewalls, but, of course, there are other uses.  Consult the man page,
or run with no options for usage information.

    Usage:
            redir --lport=PORT --cport=PORT [options]
            redir --inetd      --cport=PORT

Redir comes with a GNU configure script which you can use to adapt the
build to your needs.  If you would like to remove support for some
extended options (for the sake of speed, code size, whatever),
try the following options to configure:

    --disable-shaper   Disable traffic shaping code
    --disable-ftp      Disable FTP redirection support

Redir is distributed under the terms of the GNU Public Licence, version
2 or later, distributed with this source archive in the file COPYING.

[home]:            http://sammy.net/~sammy/hacks/
[Travis]:          https://travis-ci.org/troglobit/redir
[Travis Status]:   https://travis-ci.org/troglobit/redir.png?branch=master
[Coverity Scan]:   https://scan.coverity.com/projects/8740
[Coverity Status]: https://scan.coverity.com/projects/8740/badge.svg
