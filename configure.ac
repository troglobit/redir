AC_INIT([redir], [2.4-dev], [https://github.com/troglobit/redir/issues])
AM_INIT_AUTOMAKE([1.11 foreign])

AC_CONFIG_SRCDIR([redir.c])
AC_CONFIG_HEADER([config.h])
AC_CONFIG_FILES([Makefile])

AC_PROG_CC
AC_PROG_INSTALL
AC_HEADER_STDC

AC_ARG_ENABLE(shaping,
        AS_HELP_STRING([--disable-shaping], [Disable traffic shaping support]))

AC_ARG_WITH(libwrap,
	AS_HELP_STRING([--with-libwrap=DIR], [use libwrap (rooted in DIR), default: yes]),
	[with_libwrap=$withval], [with_libwrap=yes])
AS_IF([test "x$with_libwrap" != "xno"],[
	AS_IF([test -d "$with_libwrap"],[
	    CPPFLAGS="$CPPFLAGS -I${with_libwrap}/include"
	    LDFLAGS="$LDFLAGS -L${with_libwrap}/"
	])
	AC_CHECK_LIB(wrap, request_init,, with_libwrap=no)
	AC_CHECK_HEADER([tcpd.h],, with_libwrap=no)
])

AS_IF([test "x$enable_shaping" != "xno"],enable_shaping="yes",[
	AC_DEFINE(NO_SHAPER, 1, [Disable traffic shaping])])

AC_OUTPUT
