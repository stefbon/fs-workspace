/*
  2010, 2011 Stef Bon <stefbon@gmail.com>

  This program is free software; you can redistribute it and/or
  modify it under the terms of the GNU General Public License
  as published by the Free Software Foundation; either version 2
  of the License, or (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program; if not, write to the Free Software
  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.

*/

#ifndef _GLOBAL_DEFINES_H
#define _GLOBAL_DEFINES_H

#define FUSE_USE_VERSION 30
//#define _REENTRANT
#define _GNU_SOURCE
#define _XOPEN_SOURCE 500

#ifdef HAVE_CONFIG_H
#include <config.h>
#else
#define PACKAGE_VERSION "1.0"
#endif

#define LOGGING
#define FS_WORKSPACE_DEBUG

#endif
