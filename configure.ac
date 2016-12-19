#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.61)

AC_COPYRIGHT([Copyright (c) 2008 Patrick McHardy <kaber@trash.net>, (c) 2013-2016 Pablo Neira Ayuso <pablo@netfilter.org>])
AC_INIT([nftables], [0.7], [netfilter-devel@vger.kernel.org])
AC_DEFINE([RELEASE_NAME], ["Scrooge McDuck"], [Release name])

AC_CONFIG_AUX_DIR([build-aux])
AC_CANONICAL_HOST
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([-Wall foreign subdir-objects
        tar-pax no-dist-gzip dist-bzip2 1.6])

dnl kernel style compile messages
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

AC_CONFIG_SRCDIR([src/rule.c])
AC_CONFIG_HEADER([config.h])

AC_DEFINE([_GNU_SOURCE], [], [Enable various GNU extensions])
AC_DEFINE([_STDC_FORMAT_MACROS], [], [printf-style format macros])

AC_ARG_ENABLE([debug],
	      AS_HELP_STRING([--enable-debug], [Disable debugging]),
	      AS_IF([test "x$enable_debug" = "xno"], [with_debug=no], [with_debug=yes]),
	      [with_debug=yes])
AC_SUBST(with_debug)
AM_CONDITIONAL([BUILD_DEBUG], [test "x$with_debug" != xno])

AC_ARG_ENABLE([pdf-doc],
	      AS_HELP_STRING([--enable-pdf-doc], [Enable PDF documentation]),
	      AS_IF([test "x$enable_pdf_doc" = "xno"], [enable_pdf_doc=no],
	      [enable_pdf_doc=yes]), [enable_pdf_doc=no])
AM_CONDITIONAL([BUILD_PDF], [test "x$enable_pdf_doc" == "xyes" ])

# Checks for programs.
AC_PROG_CC
AC_PROG_MKDIR_P
AC_PROG_INSTALL
AC_PROG_SED
AM_PROG_LEX
AC_PROG_YACC

if test -z "$ac_cv_prog_YACC"
then
        echo "*** Error: No suitable bison/yacc found. ***"
        echo "    Please install the 'bison' package."
        exit 1
fi
if test -z "$ac_cv_prog_LEX"
then
        echo "*** Error: No suitable flex/lex found. ***"
        echo "    Please install the 'flex' package."
        exit 1
fi

AC_CHECK_PROG(DOCBOOK2X_MAN, [docbook2x-man], [docbook2x-man], [no])
AC_CHECK_PROG(DOCBOOK2MAN, [docbook2man], [docbook2man], [no])
AC_CHECK_PROG(DB2X_DOCBOOK2MAN, [db2x_docbook2man], [db2x_docbook2man], [no])
AS_IF([test "$DOCBOOK2X_MAN" != "no"], [DB2MAN="$DOCBOOK2X_MAN"],
	[AS_IF([test "$DOCBOOK2MAN" != "no"], [DB2MAN="$DOCBOOK2MAN"],
		[AS_IF([test "$DB2X_DOCBOOK2MAN" != "no"], [DB2MAN="$DB2X_DOCBOOK2MAN"],
			[AC_MSG_WARN([docbookx2-man/db2x_docbook2man not found, no manpages will be built])]
		)]
	)]
)
AC_SUBST(DB2MAN)
AM_CONDITIONAL([BUILD_MAN], [test -n "$DB2MAN"])

AM_COND_IF([BUILD_PDF], [
	AC_CHECK_PROG(DBLATEX, [dblatex], [found], [no])
	AS_IF([test "$DBLATEX" == "no"],
	      [AC_MSG_ERROR([dblatex not found])])
])

# Checks for libraries.
PKG_CHECK_MODULES([LIBMNL], [libmnl >= 1.0.3])
PKG_CHECK_MODULES([LIBNFTNL], [libnftnl >= 1.0.7])

AC_ARG_WITH([mini-gmp], [AS_HELP_STRING([--with-mini-gmp],
            [Use builtin mini-gmp (for embedded builds)])], [],
            [with_mini_gmp=no])
AS_IF([test "x$with_mini_gmp" != xyes], [
AC_CHECK_LIB([gmp],[__gmpz_init], , AC_MSG_ERROR([No suitable version of libgmp found]))
])
AM_CONDITIONAL([BUILD_MINIGMP], [test "x$with_mini_gmp" == xyes])

AC_ARG_WITH([cli], [AS_HELP_STRING([--without-cli],
            [disable interactive CLI (libreadline support)])],
            [], [with_cli=yes])
AS_IF([test "x$with_cli" != xno], [
AC_CHECK_LIB([readline], [readline], ,
	     AC_MSG_ERROR([No suitable version of libreadline found]))
AC_DEFINE([HAVE_LIBREADLINE], [1], [])
])
AC_SUBST(with_cli)
AM_CONDITIONAL([BUILD_CLI], [test "x$with_cli" != xno])

AC_ARG_WITH([xtables], [AS_HELP_STRING([--with-xtables],
            [Use libxtables for iptables interaction)])],
	    [with_libxtables=yes], [with_libxtables=no])
AS_IF([test "x$with_libxtables" != xno], [
PKG_CHECK_MODULES([XTABLES], [xtables >= 1.6.0])
AC_DEFINE([HAVE_LIBXTABLES], [1], [0])
])
AC_SUBST(with_libxtables)
AM_CONDITIONAL([BUILD_XTABLES], [test "x$with_libxtables" == xyes])

# Checks for header files.
AC_HEADER_STDC
AC_HEADER_ASSERT
AC_CHECK_HEADERS([arpa/inet.h fcntl.h inttypes.h limits.h malloc.h \
		  netdb.h netinet/in.h netinet/ip.h netinet/ip6.h \
		  netinet/tcp.h netinet/udp.h netinet/ip_icmp.h \
		  stddef.h stdint.h stdlib.h string.h unistd.h], ,
		 AC_MSG_ERROR([Header file not found]))

# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL
AC_C_CONST
AC_C_INLINE
AC_TYPE_OFF_T
AC_TYPE_SIZE_T
AC_TYPE_UID_T
AC_TYPE_INT8_T
AC_TYPE_INT16_T
AC_TYPE_INT32_T
AC_TYPE_INT64_T
AC_TYPE_UINT8_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T

# Checks for library functions.
AC_CHECK_FUNCS([memmove memset strchr strdup strerror strtoull])

AC_CONFIG_FILES([					\
		Makefile				\
		src/Makefile				\
		include/Makefile			\
		include/linux/Makefile			\
		include/linux/netfilter/Makefile	\
		include/linux/netfilter_arp/Makefile	\
		include/linux/netfilter_bridge/Makefile	\
		include/linux/netfilter_ipv4/Makefile	\
		include/linux/netfilter_ipv6/Makefile	\
		doc/Makefile				\
		files/Makefile				\
		files/nftables/Makefile			\
		])
AC_OUTPUT

echo "
nft configuration:
  cli support:			${with_cli}
  enable debugging:		${with_debug}
  use mini-gmp:			${with_mini_gmp}
  enable pdf documentation:	${enable_pdf_doc}
  libxtables support:		${with_libxtables}"
