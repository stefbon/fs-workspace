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
extern unsigned char wait_sftp_response_ctx(struct context_interface_s *i, void *r, struct timespec *timeout, unsigned int *error);
extern void get_sftp_request_timeout(struct timespec *timeout);

/* REMOVE a file and a directory */

void _fs_sftp_unlink(struct service_context_s *context, struct fuse_request_s *f_request, struct entry_s **pentry, struct pathinfo_s *pathinfo)
{
    struct context_interface_s *interface=&context->interface;
    struct sftp_request_s sftp_r;
    unsigned int error=EIO;
    unsigned int pathlen=(* interface->backend.sftp.get_complete_pathlen)(interface, pathinfo->len);
    char path[pathlen];

    if ((* f_request->is_interrupted)(f_request)) {

	reply_VFS_error(f_request, EINTR);
	return;

    }

    pathinfo->len += (* interface->backend.sftp.complete_path)(interface, path, pathinfo);

    logoutput("_fs_sftp_unlink: remove %.*s", pathinfo->len, pathinfo->path);

    memset(&sftp_r, 0, sizeof(struct sftp_request_s));
    sftp_r.id=0;

    sftp_r.call.remove.path=(unsigned char *) pathinfo->path;
    sftp_r.call.remove.len=pathinfo->len;
    sftp_r.fuse_request=f_request;

    if (send_sftp_remove_ctx(interface->ptr, &sftp_r)==0) {
	void *request=NULL;

	request=create_sftp_request_ctx(interface->ptr, &sftp_r, &error);

	if (request) {
	    struct timespec timeout;

	    get_sftp_request_timeout(&timeout);

	    if (wait_sftp_response_ctx(interface, request, &timeout, &error)==1) {

		if (sftp_r.type==SSH_FXP_STATUS) {

		    logoutput("_fs_sftp_remove: status code %i", sftp_r.response.status.code);

		    if (sftp_r.response.status.code==0) {
			struct entry_s *entry=*pentry;
			struct inode_s *inode=entry->inode;

			queue_inode_2forget(inode->st.st_ino, context->unique, 0, 0);
			*pentry=NULL;

			reply_VFS_error(f_request, 0);
			return;

		    } else {

			error=sftp_r.response.status.linux_error;

		    }

		} else {

		    error=EPROTO;

		}

	    }

	}

    }

    out:
    reply_VFS_error(f_request, error);

}

void _fs_sftp_rmdir(struct service_context_s *context, struct fuse_request_s *f_request, struct entry_s **pentry, struct pathinfo_s *pathinfo)
{
    struct context_interface_s *interface=&context->interface;
    struct sftp_request_s sftp_r;
    unsigned int error=EIO;
    unsigned int pathlen=(* interface->backend.sftp.get_complete_pathlen)(interface, pathinfo->len);
    char path[pathlen];

    if ((* f_request->is_interrupted)(f_request)) {

	reply_VFS_error(f_request, EINTR);
	return;

    }

    pathinfo->len += (* interface->backend.sftp.complete_path)(interface, path, pathinfo);

    memset(&sftp_r, 0, sizeof(struct sftp_request_s));

    sftp_r.id=0;

    sftp_r.call.rmdir.path=(unsigned char *) pathinfo->path;
    sftp_r.call.rmdir.len=pathinfo->len;
    sftp_r.fuse_request=f_request;

    if (send_sftp_rmdir_ctx(interface->ptr, &sftp_r)==0) {
	void *request=NULL;

	request=create_sftp_request_ctx(interface->ptr, &sftp_r, &error);

	if (request) {
	    struct timespec timeout;

	    get_sftp_request_timeout(&timeout);

	    if (wait_sftp_response_ctx(interface, request, &timeout, &error)==1) {

		if (sftp_r.type==SSH_FXP_STATUS) {

		    logoutput("_fs_sftp_rmdir: status code %i", sftp_r.response.status.code);

		    if (sftp_r.response.status.code==0) {
			struct entry_s *entry=*pentry;
			struct inode_s *inode=entry->inode;

			queue_inode_2forget(inode->st.st_ino, context->unique, 0, 0);
			*pentry=NULL;

			reply_VFS_error(f_request, 0);
			return;

		    } else {

			error=sftp_r.response.status.linux_error;

		    }

		} else {

		    error=EPROTO;

		}

	    }

	}

    }

    out:
    reply_VFS_error(f_request, error);

}

void _fs_sftp_unlink_disconnected(struct service_context_s *context, struct fuse_request_s *f_request, struct entry_s **pentry, struct pathinfo_s *pathinfo)
{
    reply_VFS_error(f_request, ENOTCONN);
}

void _fs_sftp_rmdir_disconnected(struct service_context_s *context, struct fuse_request_s *f_request, struct entry_s **pentry, struct pathinfo_s *pathinfo)
{
    reply_VFS_error(f_request, ENOTCONN);
}
