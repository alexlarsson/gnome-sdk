AC_PREREQ([2.63])

AC_INIT([gnome-sdk],[0.0.1])

AC_PROG_CC
AM_PROG_CC_C_O
AC_DISABLE_STATIC

LT_PREREQ([2.2.6])
LT_INIT([disable-static])

AC_CONFIG_SRCDIR([gnome-sdk-helper.c])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([1.11 no-define no-dist-gzip dist-bzip2 tar-ustar foreign])

# Enable silent rules is available
AM_SILENT_RULES([yes])
AM_MAINTAINER_MODE([enable])

if test "x$GCC" = "xyes"; then
  case " $CFLAGS " in
  *[[\ \	]]-Wall[[\ \	]]*) ;;
  *) CFLAGS="$CFLAGS -Wall" ;;
  esac
fi

PKG_CHECK_MODULES(OSTREE, [glib-2.0 ostree-1])
AC_SUBST(OSTREE_CFLAGS)
AC_SUBST(OSTREE_LIBS)

AC_CONFIG_FILES([
Makefile
])
AC_OUTPUT
