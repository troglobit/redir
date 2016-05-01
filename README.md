A TCP port redirector for UNIX
==============================

Redir is a port redirector for UNIX.  It can run under inetd or
standalone (in which case it handles multiple connections).  It is 8 bit
clean, not limited to line mode, is small and light.  If you want access
control run it under xinetd, or inetd with TCP wrappers.

Redir listens for TCP connections on a given port, and, when it recieves
a connection, then connects to a given destination address/port, and
pass data between them.  It finds most of its applications in traversing
firewalls, but, of course, there are other uses.  Consult the man page,
or run with no options for usage information.

    Usage:
            redir --lport=<n> --cport=<n> [options]
            redir --inetd --cport=<n>

Redir comes with a GNU configure script which you can use to adapt the
build to your needs.  If you would like to remove support for some
extended options (for the sake of speed, code size, whatever),
try the following options to configure:

    --disable-shaper   Disable traffic shaping code
    --disable-ftp      Disable FTP redirection support

Redir is distributed under the terms of the GNU Public Licence, version
2 or later, distributed with this source archive in the file COPYING.

The files in the getopt/ directory are GNU source code distributed under
the same license.  These particular files were copied from the GNU
package gawk-3.0.3, because it happened to be sitting on my drive at the
time.

