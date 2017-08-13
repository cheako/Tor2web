AC_PREREQ(2.59)
AC_INIT([tor2web], [0.0], [cheako+github_public_tor2web@mikemestnik.net], [tor2web], [https://github.com/cheako/tor2web])
AM_INIT_AUTOMAKE([foreign])
AC_PROG_CC
PKG_CHECK_MODULES([LIBGNUTLS], [gnutls >= 2.12.23])
AC_SUBST([LIBGNUTLS_CFLAGS])
AC_SUBST([LIBGNUTLS_LIBS])
AC_CONFIG_FILES([
		 Makefile
		 src/Makefile
		 data/templates/Makefile
		 t/Makefile
		 t/tx/Makefile
])
AX_CODE_COVERAGE()
AC_REQUIRE_AUX_FILE([.tap-driver.sh])
AC_OUTPUT
