-----
Changes for 2.2.1
-----

2.2.1 fixes a bug in do_accept() where non-fatal error codes returned
by accept() would cause redir to terminate entirely.  I had recieved
reports of this behavior but was unable to find it until sammy.net had 
to handle the load of the redir 2.2 update using redir. :)  All
non-fatal error codes might not be covered.  But it "got better".

2.2.1 integrates a patch by Emmanuel Chantréau <echant@maretmanu.org>
which provides traffic shaping functionality to redir.  Interesting
stuff.  I've not tested this in detail personally.

2.2.1 adds the ability to compile redir with lesser functionality for
speed.  This is documented in the README.

-----
Changes for 2.2
-----

2.2 adds support for redirecting PORT mode ftp connections in addition 
to PASV mode ftp redirection.  Thus --ftp is now split into
--ftp={port,pasv,both} to determine what should be redirected.  The
original version of this patch was submitted by Harald Holzer
<harald.holzer@eunet.at>.

2.2 adds the --connect option, which is useful if you're bouncing your
connections through an HTTP proxy server.  Use as --connect=host:port, 
and this will be the CONNECT line sent to the proxy.

-----
Changes for 2.1
-----

2.1 is just a bugfix release, fixing a problem with ftp redirection,
and adds/fixes various logging messages.  Also a fix for some of the
TCP wrappers code.

-----
Changes for 2.0
-----

2.0 has changed the command line syntax!  You're going to have to
change how you call redir in order to upgrade, but not by all that
much.  We now use --options for everything, instead of having the
rather wonky "if you've got this thing here, something happens" method
used before.  We apologize for the inconvenience, but this is really a
lot less brain damaged.

2.0 now includes support for using TCP wrappers, thanks to a patch
submitted by Damien Miller <damien@ibs.com.au>.  The --name option now
sets the TCP wrapper service name as well as the syslog program name,
making it possible to run multiple instances of redir with different
access controls.  Edit the Makefile to enable TCP wrappers.

2.0 now actually implements --transproxy when running from inetd.

2.0 has cleaned up the --ftp support, at least a little.  There are
probably still improvements to be made here, but, alas.

-----
Changes for 1.2
-----

1.2 now should compile and run correctly on systems which lack
getopt_long.

1.2 adds the option --transproxy, which, when run as super-user on a
linux system which has had transparent proxying compiled into it's
kernel, will make connections seem as if they had come from their true
origin.  see transproxy.txt for further discussion of this option.

-----
Changes for 1.1
-----

1.1 adds the option --ftp, which, when redirecting a port to an FTP
server, will, when the server wants to initiate a passive connection,
redirect another port for that connection.  

-----
Changes for 1.0
-----

1.0 adds the option --bind-addr, which can force it to bind to a
specific address or interface when making outgoing connections.

