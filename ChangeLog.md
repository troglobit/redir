Change Log
==========

All relevant changes to the project are documented in this file.


[v3.3][UNRELEASED]
---------------------

### Fixes
- Fix #5: Use `stdout`, not `stderr`, for `--version` and `--usage`
- Fix #6: Minor typo in man page
- Fix #9: Major timing bug fix in `--max-bandwidth` and `--random-wait`.
  Delays below one second are off by a factor 1000!


[v3.2][] - 2018-03-10
---------------------

Minor bug fixes.

### Changes
- Add missing `transproxy.txt` file to distribution
- Update usage text and man page for `--bind` option, w.r.t. transproxy

### Fixes
- Issue #4: Service names from `/etc/services` not recognized for compat
  syntax, `--lport` or `--cport`


[v3.1][] - 2017-01-22
---------------------

Restored support for some command line options on behalf of Debian.

### Changes
- New `--enable-compat` option added to configure script.  Enables
  support for command line options from v2.x used by `vagrant-lxc`,
  https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=824698#15
  - `--laddr=SRC`
  - `--lport=PORT`
  - `--caddr=SRC`
  - `--cport=PORT`

### Fixes
- Portability fixes for musl libc


[v3.0][] - 2016-05-06
---------------------

This version changes the command line syntax!  You are going to have to
change how you call `redir` in order to upgrade.

### Changes
- Convert `SRC:PORT` and `DST:PORT` from *options* to *arguments*, using
  a UNIX syntax that is pretty much standard by now.
- Rename `-n,--name=STR` --> `-I,--ident=NAME`
- Simplify argument parsing, move more data to global variables
- Simplify `debug()` statements, use `syslog()`
- Daemonize by default, like a proper UNIX daemon, unless `-n,
  --foreground` is given
- Replace `perror()` and other log messages going to `stderr` in favor
  of `syslog()` for everything, unless running in foreground, in which
  case we use `LOG_PERROR` for log message output to `stderr` as well
  ... unless `-s, --syslog` is given
- Replace `-d, --debug` with `-l, --loglevel=LEVEL` to control the
  `syslog()` default log level.  The default log level is `LOG_NOTICE`
- Convert to GNU Configure & Build System.  With configure switches like
  `--disable-ftp`, `--disable-shaping`, and `--with-libwrap`
- Change distribution to use `.tar.xz` rather than `.tar.gz` from now on
- Convert to Markdown, clean up and simplify `README`
- Remove local versions of `getopt()` and `getopt_long()`.  All relevant
  UNIX distributions should have them by now.
- Massive code cleanup and (Linux KNF) coding style fixes
- Add Coverity Scan support for Travis-CI runs
- Complete rewrite of man page
- Overhaul of `--help` usage help
- Refactor to reduce code duplication:
  - `verify_request()` for TCP wrapper handling
  - `target_init()` for initializing a `struct sockaddr_in`
  - `target_connect()` to handle creating and connecting a target socket
- Refactor to harmonize function and variable names
- Cleanup `redir.c` heading and use proper GNU GPL blurb
- Make sure to credit all known major contributors in `AUTHORS` file
- Removed `redir.lsm` file

### Fixes
- Fix socket leaks found by Coverity Scan
- Fix unterminated strings returned by `read()`, found by Coverity Scan
- Fix ordering bug(s) found by Coverity Scan
- Fix `strcpy()` into fixed size buffer found by Coverity Scan
- Fix uninitialized `struct sockaddr_in`, found by Coverity Scan
- Check `malloc()` return value
- Do `gethostbyname()` before every `connect()`, DNS names may change at
  runtime


[v2.3][] - 2016-05-01
---------------------

This is a checkpoint release by the new maintainer, Joachim Nilsson,
integrating all (most) of Debian's patches.

### Changes
- Rename man page `redir.man` --> `redir.1`
- Rename `CHANGES` --> `ChangeLog.md`
- Update Linux Software Map, v0.7 --> v2.2
- Don't strip binaries by default.  Thanks to Julien Danjou.  
  Closes Debian bug #437898, by Daniel Kahn Gillmor
- Clean up questionable formatting in man page, by Daniel Kahn Gillmor
- Remove overrides in Makefile to enable hardening, by Tobias Frost

### Fixes
- Debian fixes to man page and `--help` text for `--max_bandwidth`  
  by Daniel Kahn Gilmor
- Use `ntohs()` to generate comprehensible `debug()`s and `syslog()`s,  
  by Bernd Eckenfels
- Fix calls to TCP wrappers, by Daniel Kahn Gillmor
- Fix timeouts to only happen after full duration of inactivity, rather
  than absolute.  This patch is a close approximation of Robert de Bath's
  patch for Debian bug #142382, by Daniel Kahn Gillmor
- Build without any warnings from `gcc`, even with `--pedantic`, patch
  by Daniel Kahn Gillmor
- Fix problem with buffer allocation introduced by bandwidth throttling.
  Closes Debian bug #335288, by Daniel Kahn Gillmor
- Cosmetic fixes to man page which could be applied upstream.  
  by Daniel Kahn Gillmor
- Ensure that the server socket has `SO_REUSEADDR` and `SO_LINGER` set
  properly.  Closes Debian bug #508140, by Daniel Kahn Gillmor
- Handle type casting of variables.  Change `size_t` variables to instead
  use `socklen_t`, warning from `gcc`.  Fix by Lucas Kanashiro


[v2.2.1][] - 1999-12-26
-----------------------

Bug fix relase by Sam Creasey.

### Changes
- Support for traffic shaping by Emmanuel Chantréau. Interesting
  stuff.  I've not tested this in detail personally.
- Adds the ability to compile `redir` with lesser functionality for
  speed.  This is documented in the README.

### Fixes
- Fix bug in `do_accept()` where non-fatal error codes returned by
  `accept()` would cause `redir` to terminate entirely.  I had recieved
  reports of this behavior but was unable to find it until sammy.net had
  to handle the load of the `redir` 2.2 update using `redir`  :)  
  All non-fatal error codes might not be covered.  But it "got better".


[v2.2][] - 1999-12-15
---------------------

### Changes
- Support for redirecting PORT mode FTP connections in addition to PASV
  mode FTP redirection.  Thus `--ftp` is now `--ftp={port,pasv,both}` to
  determine what should be redirected.  The original version of this
  patch was submitted by Harald Holzer
- Adds the `--connect` option, which is useful if you're bouncing your
  connections through an HTTP proxy server. Use as `--connect=host:port`
  and this will be the CONNECT line sent to the proxy.


[v2.1][] - 1999-06-22
---------------------

Bugfix release

### Fixes
- Fix a problem with FTP redirection
- Fix (and add) various logging messages
- Fix for some of the TCP wrappers code


[v2.0][] - 1999-02-11
---------------------

This version changes the command line syntax!  You're going to have to
change how you call `redir` in order to upgrade, but not by all that
much.  We now use `--options` for everything, instead of having the
rather wonky "if you've got this thing here, something happens" method
used before.  We apologize for the inconvenience, but this is really a
lot less brain damaged.

### Changes
- Support for TCP wrappers, thanks to Damien Miller
- The `--name` option now sets the TCP wrapper service name as well as
  the syslog program name, making it possible to run multiple instances
  of redir with different access controls.  Edit the Makefile to enable
  TCP wrappers.
- Actually implement `--transproxy` when running from `inetd`.
- Cleaned up `--ftp` support, at least a little.  There are probably
  still improvements to be made here, but, alas.


v1.2 - UNKNOWN
---------------

Like v0.5, this release was not possible to locate on the Internet
anymore.  Even using excellent help from <http://www.archive.org>.
Restoring this change set was not possible, all we have is this change
log entry.  If you know the release date, please contact me --Joachim

### Changes
- Adds the option `--transproxy`, which, when run as super-user on a
  Linux system which has had transparent proxying compiled into it's
  kernel, will make connections seem as if they had come from their true
  origin.  See `transproxy.txt` for further discussion of this option

### Fixes
- `redir` should now compile and run correctly on systems which lack
  `getopt_long()`


[v1.1][] - 1998-10-31
---------------------

### Changes
- Add the option `--ftp`, which, when redirecting a port to an FTP
  server, will, when the server wants to initiate a passive connection,
  redirect another port for that connection


[v1.0][] - 1998-08-08
---------------------

This is the first release by Sam Creasey after picking up from v0.7
by Nigel Metheringham.

### Changes
- Add the option `--bind-addr`, which can force `redir` to bind to a
  specific address or interface when making outgoing connections


v0.7 - 1998-06-30
-----------------

A cleanup and bug fix release by Nigel Metheringham after the initial
v0.5 release by Sam Creasey.


v0.5 - UNKNOWN
--------------

This release was not possible to locate on the Internet anymore, but is
the initial release by Sam Creasey.  In his own words:

> Redir is actually a horrible hack of my other cool network utility,
> daemon, which is actually a horrible hack of ora's using C sample
> code, 12.2.c.  But, hey, they do something.  (and that's the key.)

[UNRELEASED]: https://github.com/troglobit/redir/compare/v3.2...HEAD
[v3.2]: https://github.com/troglobit/redir/compare/v3.1...v3.2
[v3.1]: https://github.com/troglobit/redir/compare/v3.0...v3.1
[v3.0]: https://github.com/troglobit/redir/compare/v2.3...v3.0
[v2.3]: https://github.com/troglobit/redir/compare/v2.2.1...v2.3
[v2.2.1]: https://github.com/troglobit/redir/compare/v2.2...v2.2.1
[v2.2]: https://github.com/troglobit/redir/compare/v2.1...v2.2
[v2.1]: https://github.com/troglobit/redir/compare/v2.0...v2.1
[v2.0]: https://github.com/troglobit/redir/compare/v1.1...v2.0
[v1.1]: https://github.com/troglobit/redir/compare/v1.0...v1.1
[v1.0]: https://github.com/troglobit/redir/compare/v0.7...v1.0
