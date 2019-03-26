/*
  2010, 2011, 2012, 2103, 2014, 2015, 2016, 2017 Stef Bon <stefbon@gmail.com>

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

#include "global-defines.h"

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <err.h>
#include <sys/time.h>
#include <time.h>
#include <pthread.h>
#include <ctype.h>
#include <inttypes.h>

#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "main.h"
#include "logging.h"
#include "pathinfo.h"
#include "utils.h"

#include "fuse-fs.h"
#include "workspaces.h"
#include "workspace-context.h"
#include "fuse-utils.h"
#include "fuse-interface.h"

#include "path-caching.h"

#include "fuse-fs-common.h"

#include "common-protocol.h"
#include "attr-common.h"
#include "send-common.h"

#include "fuse-sftp-common.h"

extern void *create_sftp_request_ctx(void *ptr, struct sftp_request_s *sftp_r, unsigned int *error);
extern unsigned char wait_sftp_response_ctx(void *ptr, void *r, struct timespec *timeout, unsigned int *error);
extern void get_sftp_request_timeout(struct timespec *timeout);

void _fs_sftp_setxattr(struct service_context_s *context, struct fuse_request_s *f_request, struct pathinfo_s *pathinfo, struct inode_s *inode, const char *name, const char *value, size_t size, int flags)
{
    reply_VFS_error(f_request, ENODATA);
}

void _fs_sftp_getxattr(struct service_context_s *context, struct fuse_request_s *f_request, struct pathinfo_s *pathinfo, struct inode_s *inode, const char *name, size_t size)
{
    reply_VFS_error(f_request, ENODATA);
}

void _fs_sftp_listxattr(struct service_context_s *context, struct fuse_request_s *f_request, struct pathinfo_s *pathinfo, struct inode_s *inode, size_t size)
{
    reply_VFS_error(f_request, ENODATA);
}

void _fs_sftp_removexattr(struct service_context_s *context, struct fuse_request_s *f_request, struct pathinfo_s *pathinfo, struct inode_s *inode, const char *name)
{
    reply_VFS_error(f_request, ENODATA);
}


