/*
  2010, 2011, 2012, 2103, 2014, 2015, 2016 Stef Bon <stefbon@gmail.com>

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

#include "logging.h"
#include "main.h"
#include "pathinfo.h"
#include "utils.h"

#include "workspace-interface.h"
#include "fuse-fs.h"

#include "workspaces.h"
#include "workspace-context.h"

#include "fuse-fs-common.h"
#include "sftp-common-protocol.h"
#include "sftp-attr-common.h"
#include "sftp-send-common.h"

#include "fuse-sftp-common.h"

extern void *create_sftp_request_ctx(void *ptr, struct sftp_request_s *sftp_r, unsigned int *error);
extern unsigned char wait_sftp_response_ctx(void *ptr, void *r, struct timespec *timeout, unsigned int *error);
extern void get_sftp_request_timeout(struct timespec *timeout);

/* GETATTR */

void _fs_sftp_getattr(struct service_context_s *context, struct fuse_request_s *f_request, struct inode_s *inode, struct pathinfo_s *pathinfo)
{
    struct context_interface_s *interface=&context->interface;
    struct sftp_request_s sftp_r;
    unsigned int error=EIO;
    unsigned int pathlen=(* interface->backend.sftp.get_complete_pathlen)(interface, pathinfo->len);
    char path[pathlen];

    if (f_request->flags & FUSEDATA_FLAG_INTERRUPTED) {

	reply_VFS_error(f_request, EINTR);
	return;

    }

    logoutput("_fs_sftp_getattr: %li %s", inode->ino, pathinfo->path);

    pathinfo->len += (* interface->backend.sftp.complete_path)(interface, path, pathinfo);

    memset(&sftp_r, 0, sizeof(struct sftp_request_s));

    sftp_r.id=0;
    sftp_r.call.lstat.path=(unsigned char *) pathinfo->path;
    sftp_r.call.lstat.len=pathinfo->len;
    sftp_r.fusedata_flags=&f_request->flags;

    /* send lstat cause not interested in target when dealing with symlink */

    if (send_sftp_lstat_ctx(context->interface.ptr, &sftp_r)==0) {
	void *request=NULL;

	request=create_sftp_request_ctx(context->interface.ptr, &sftp_r, &error);

	if (request) {
	    struct timespec timeout;

	    get_sftp_request_timeout(&timeout);
	    error=0;

	    if (wait_sftp_response_ctx(context->interface.ptr, request, &timeout, &error)==1) {

		if (sftp_r.type==SSH_FXP_ATTRS) {
		    struct fuse_sftp_attr_s fuse_attr;

		    memset(&fuse_attr, 0, sizeof(struct fuse_sftp_attr_s));
		    read_attributes_ctx(context->interface.ptr, sftp_r.response.attr.buff, sftp_r.response.attr.size, &fuse_attr);

		    fill_inode_attr_sftp(context->interface.ptr, inode, &fuse_attr);
		    _fs_common_getattr(get_root_context(context), f_request, inode);

		    get_current_time(&inode->stim);

		    free(sftp_r.response.attr.buff);
		    return;

		} else if (sftp_r.type==SSH_FXP_STATUS) {

		    error=sftp_r.response.status.linux_error;

		} else {

		    error=EPROTO;

		}

	    }

	}

    } else {

	error=sftp_r.error;

    }

    out:

    logoutput("_fs_sftp_getattr: error %i (%s)", error, strerror(error));
    reply_VFS_error(f_request, error);

}

/* FGETATTR */

void _fs_sftp_fgetattr(struct fuse_openfile_s *openfile, struct fuse_request_s *f_request)
{
    struct service_context_s *context=(struct service_context_s *) openfile->context;
    struct sftp_request_s sftp_r;
    unsigned int error=EIO;

    if (f_request->flags & FUSEDATA_FLAG_INTERRUPTED) {

	error=EINTR;
	goto out;

    }

    memset(&sftp_r, 0, sizeof(struct sftp_request_s));

    sftp_r.id=0;
    sftp_r.call.fstat.handle=(unsigned char *) openfile->handle.name.name;
    sftp_r.call.fstat.len=openfile->handle.name.len;
    sftp_r.fusedata_flags=&f_request->flags;

    /* send fstat cause a handle is available */

    if (send_sftp_fstat_ctx(context->interface.ptr, &sftp_r)==0) {
	void *request=NULL;

	request=create_sftp_request_ctx(context->interface.ptr, &sftp_r, &error);

	if (request) {
	    struct timespec timeout;

	    get_sftp_request_timeout(&timeout);
	    error=0;

	    if (wait_sftp_response_ctx(context->interface.ptr, request, &timeout, &error)==1) {

		if (sftp_r.type==SSH_FXP_ATTRS) {
		    struct fuse_sftp_attr_s fuse_attr;
		    struct inode_s *inode=openfile->inode;

		    memset(&fuse_attr, 0, sizeof(struct fuse_sftp_attr_s));
		    read_attributes_ctx(context->interface.ptr, sftp_r.response.attr.buff, sftp_r.response.attr.size, &fuse_attr);

		    fill_inode_attr_sftp(context->interface.ptr, inode, &fuse_attr);
		    _fs_common_getattr(get_root_context(context), f_request, inode);

		    get_current_time(&inode->stim);

		    free(sftp_r.response.attr.buff);
		    return;

		} else if (sftp_r.type==SSH_FXP_STATUS) {

		    error=sftp_r.response.status.linux_error;

		} else {

		    error=EPROTO;

		}

	    }

	}

    } else {

	error=sftp_r.error;

    }

    out:

    reply_VFS_error(f_request, error);

}
