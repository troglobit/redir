A TCP port redirector for UNIX
==============================

Redir is a port redirector.  It's functionally basically consists of the
ability to listen for TCP connections on a given port, and, when it
recieves a connection, to then connect to a given destination
address/port, and pass data between them.  It finds most of its
applications in traversing firewalls, but, of course, there are other
uses.  Consult the man page, or run with no options for usage
information.

Please check the Makefile to see if you need to make any changes to
get it to compile correctly on your particular unix flavor.

If you would like to remove support for some extended options (for the
sake of speed, code size, whatever), change the EXTRA_CFLAGS line in
the makefile.  The following are supported:

    -DNO_SHAPER (doesn't compile in traffic shaping code)
    -DNO_FTP (doesn't compile in FTP redirection support)

-----

I'm thinking of eventually doing a version which never forks, but does
one big-honking-select-loop, which probably wouldn't be much of a
bother, and would save a good chunk of ram, but then an FD limit becomes
quite a real possibility.  perhaps an #ifdef selecting the old or new
code would help this...  though, really, this is a known problem with a
lot of proxies, and it doesn't seem to hurt too bad.  depends on the
`MAX_FDS` (or whatever that define is. `FD_MAX`?) on your machine.


Authors
-------

Wow.  The authorship/maintnence for this thing has REALLY gotten mangled.  
Credits should, logically, go to the following people:

Nigel Metheringham <Nigel.Metheringham@ThePLAnet.net>
	For taking the code I wrote and making it into a more stable 
	sensible, and usable package.  
Sam Creasey <sammy@oh.verio.com>
	Original author, but this package would be vastly inferior without 
	Nigel's modifications.
Thomas Osterried <thomas@x-berg.in-berlin.de>
	Added the --bind-addr patch.

redir is distributed under the terms of the GNU Public Licence,
version 2 or later, which was distributed with this source archive in
the file COPYING.

the files in the getopt/ directory are taken from GNU source code
distributed under the same license.  These particular files were
copied from the GNU package gawk-3.0.3, because it happened to be
sitting on my drive at the time.

=======================================================================

Redir v.0.7

redir is a tcp port redirector for unix.
It can run under inetd or stand alone (in which case it handles
multiple connections).  Its 8 bit clean, not limited to line
mode, is small and light.

If you want access control run it under xinetd, or inetd with tcp
wrappers.  Or you could use the tcp wrapper library to extend it and
do fancy access control - if so please let me know.

redir is released under GPL.

	Nigel Metheringham
	Nigel.Metheringham@ThePLAnet.net
	30 June, 1996

=======================================================================

[Original readme from version 0.5]

If you liked daemon, you'll LOVE redir!

Redir, the fully functional (but only in line mode) port redirector for 
unix!  (yeah!  WOOOO!).  Basically, it's like tredir.   But hacked from 
daemon.  And poorly written.   But, hey, it dodges firewalls, and THAT's 
the important part.  I think.  Oh, fuck it.  Look, it's useful.   Good 
for dynamic IP, too.   Trust me, it is.

usage: redir [remote-host] listen_port connect_port

The syntax is a little clumsy, but it works. 

compile with make redir or gcc redir.c -o redir

comments/bugs/flames to sammy@freenet.akron.oh.us

(please, write if you use the program!)



