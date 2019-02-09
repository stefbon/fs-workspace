#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.68])
AC_INIT([fs-workspace], [1.0a1], [none])
AM_INIT_AUTOMAKE([subdir-objects])
AC_CONFIG_SRCDIR([main.h])
AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_CC
AC_PROG_CXX

# Checks for libraries.

# Checks for header files.
AC_CHECK_HEADERS([fcntl.h inttypes.h stddef.h stdlib.h string.h strings.h sys/stat.h sys/param.h sys/statvfs.h sys/time.h syslog.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL
AC_TYPE_UID_T
AC_C_INLINE
AC_TYPE_MODE_T
AC_TYPE_OFF_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_CHECK_MEMBERS([struct stat.st_blksize])
AC_STRUCT_ST_BLOCKS
AC_CHECK_MEMBERS([struct stat.st_rdev])
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T

# Checks for library functions.
AC_FUNC_CHOWN
AC_FUNC_FORK
AC_FUNC_LSTAT_FOLLOWS_SLASHED_SYMLINK
AC_FUNC_MALLOC
AC_FUNC_REALLOC

AC_CHECK_FUNCS([clock_gettime fdatasync ftruncate memmove memset mkdir realpath rmdir strchr strdup strerror strrchr strstr])
AC_CHECK_FUNCS([inotify_init], [AC_DEFINE([HAVE_INOTIFY], [1], [Check for inotify])])
AC_CHECK_HEADERS(stdio.h sys/param.h linux/fuse.h)
AC_SEARCH_LIBS(pthread_create, pthread,, AC_MSG_ERROR([Please install pthreads library first.]))

PKG_CHECK_MODULES(GLIB, [ glib-2.0 ], [AC_DEFINE([HAVE_GLIB2], [1], [Define if GLIB 2.0 is available])], AC_MSG_ERROR([Error: glib-2.0 not found.]))
PKG_CHECK_MODULES(QT5, [ Qt5Core ], [AC_DEFINE([HAVE_QTCORE5], [1], [Define if QT 5 Core is available])], AC_MSG_ERROR([Error: Qt5Core not found.]))

PKG_CHECK_MODULES([LIBGCRYPT], [gcrypt], [AC_DEFINE([HAVE_LIBGCRYPT], [1], [Check for libgcrypt])], AC_MSG_ERROR([Please install libgcrypt.]))

PKG_CHECK_MODULES([SYSTEMD], [libsystemd], [AC_DEFINE([HAVE_LIBSYSTEMD], [1], [Define libsystemd is available])], AC_MSG_ERROR([Error: libsystemd not found.]))
PKG_CHECK_MODULES([AVAHI_CORE], [avahi-core], [AC_DEFINE([HAVE_AVAHI_CORE], [1], [Define Avahi core is available])], AC_MSG_ERROR([Error: avahi core not found.]))
PKG_CHECK_MODULES([AVAHI_CLIENT], [avahi-client], [AC_DEFINE([HAVE_AVAHI_CLIENT], [1], [Define Avahi client is available])], AC_MSG_ERROR([Error: avahi client not found.]))
PKG_CHECK_MODULES(QT5, [ Qt5Core ], [AC_DEFINE([HAVE_QTCORE5], [1], [Define if QT 5 Core is available])], AC_MSG_ERROR([Error: Qt5Core not found.]))
PKG_CHECK_MODULES(UDT, [ udt ], [AC_DEFINE([HAVE_UDT], [1], [Define if libudt is available])], AC_MSG_WARN([Error: libudt not found.]))

AM_CONDITIONAL([LIBUDT_AVAIL], [ test HAVE_UDT ])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
