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

#include "logging.h"
#include "main.h"
#include "pathinfo.h"
#include "utils.h"

#include "fuse-fs.h"
#include "workspace-interface.h"
#include "workspaces.h"
#include "workspace-context.h"

#include "fuse-fs-common.h"

#include "common-protocol.h"
#include "attr-common.h"
#include "send-common.h"

#include "fuse-sftp-common.h"

extern void *create_sftp_request_ctx(void *ptr, struct sftp_request_s *sftp_r, unsigned int *error);
extern unsigned char wait_sftp_response_ctx(struct context_interface_s *i, void *r, struct timespec *timeout, unsigned int *error);
extern void get_sftp_request_timeout(struct timespec *timeout);

static void set_local_attributes(struct inode_s *inode, struct fuse_sftp_attr_s *fuse_attr)
{

    if (fuse_attr->valid[FUSE_SFTP_INDEX_SIZE]==1) inode->st.st_size=fuse_attr->size;
    if (fuse_attr->valid[FUSE_SFTP_INDEX_USER]==1) inode->st.st_uid=fuse_attr->user.uid;
    if (fuse_attr->valid[FUSE_SFTP_INDEX_GROUP]==1) inode->st.st_gid=fuse_attr->group.gid;
    if (fuse_attr->valid[FUSE_SFTP_INDEX_PERMISSIONS]==1) inode->st.st_mode=fuse_attr->permissions & fuse_attr->type;

    if (fuse_attr->valid[FUSE_SFTP_INDEX_ATIME]==1) {

	inode->st.st_atim.tv_sec=fuse_attr->atime;
	inode->st.st_atim.tv_nsec=fuse_attr->atime_n;

    }

    if (fuse_attr->valid[FUSE_SFTP_INDEX_MTIME]==1) {

	inode->st.st_mtim.tv_sec=fuse_attr->mtime;
	inode->st.st_mtim.tv_nsec=fuse_attr->mtime_n;

    }

    if (fuse_attr->valid[FUSE_SFTP_INDEX_CTIME]==1) {

	inode->st.st_ctim.tv_sec=fuse_attr->ctime;
	inode->st.st_ctim.tv_nsec=fuse_attr->ctime_n;

    }

}

/* SETATTR */

void _fs_sftp_setattr(struct service_context_s *context, struct fuse_request_s *f_request, struct inode_s *inode, struct pathinfo_s *pathinfo, struct stat *st, unsigned int set)
{
    struct context_interface_s *interface=&context->interface;
    struct sftp_request_s sftp_r;
    unsigned int error=EIO;
    struct fuse_sftp_attr_s fuse_attr;
    unsigned int size=get_attr_buffer_size(context->interface.ptr, st, set, &fuse_attr, 0);
    char buffer[size];
    unsigned int pathlen=(* interface->backend.sftp.get_complete_pathlen)(interface, pathinfo->len);
    char path[pathlen];

    pathinfo->len += (* interface->backend.sftp.complete_path)(interface, path, pathinfo);
    size=write_attributes_ctx(context->interface.ptr, buffer, size, &fuse_attr);

    memset(&sftp_r, 0, sizeof(struct sftp_request_s));
    sftp_r.id=0;
    sftp_r.call.setstat.path=(unsigned char *)pathinfo->path;
    sftp_r.call.setstat.len=pathinfo->len;
    sftp_r.call.setstat.size=size;
    sftp_r.call.setstat.buff=(unsigned char *)buffer;
    sftp_r.status=SFTP_REQUEST_STATUS_WAITING;

    set_sftp_request_fuse(&sftp_r, f_request);

    if (f_request->flags & FUSEDATA_FLAG_INTERRUPTED) {

	reply_VFS_error(f_request, EINTR);
	return;

    }

    if (send_sftp_setstat_ctx(context->interface.ptr, &sftp_r)==0) {
	void *request=NULL;

	request=create_sftp_request_ctx(context->interface.ptr, &sftp_r, &error);

	if (request) {
	    struct timespec timeout;

	    get_sftp_request_timeout(&timeout);

	    if (wait_sftp_response_ctx(interface, request, &timeout, &error)==1) {
		struct sftp_reply_s *reply=&sftp_r.reply;

		if (reply->type==SSH_FXP_STATUS) {

		    logoutput("_fs_sftp_setattr: reply %i", reply->response.status.code);

		    if (reply->response.status.code==0) {

			set_local_attributes(inode, &fuse_attr);
			_fs_common_getattr(get_root_context(context), f_request, inode);
			return;

		    } else {

			error=reply->response.status.linux_error;

		    }

		} else {

		    error=EPROTO;

		}

	    }

	}

    } else {

	error=sftp_r.reply.error;

    }

    out:
    reply_VFS_error(f_request, error);

}

/* FSETATTR */

void _fs_sftp_fsetattr(struct fuse_openfile_s *openfile, struct fuse_request_s *f_request, struct stat *st, unsigned int set)
{
    struct service_context_s *context=(struct service_context_s *) openfile->context;
    struct sftp_request_s sftp_r;
    unsigned int error=EIO;
    struct fuse_sftp_attr_s fuse_attr;
    unsigned int size=get_attr_buffer_size(context->interface.ptr, st, set, &fuse_attr, 0);
    char buffer[size];

    size=write_attributes_ctx(context->interface.ptr, buffer, size, &fuse_attr);

    memset(&sftp_r, 0, sizeof(struct sftp_request_s));
    sftp_r.id=0;
    sftp_r.call.fsetstat.handle=(unsigned char *) openfile->handle.name.name;
    sftp_r.call.fsetstat.len=openfile->handle.name.len;
    sftp_r.call.fsetstat.size=size;
    sftp_r.call.fsetstat.buff=(unsigned char *)buffer;
    sftp_r.status=SFTP_REQUEST_STATUS_WAITING;

    set_sftp_request_fuse(&sftp_r, f_request);

    if (f_request->flags & FUSEDATA_FLAG_INTERRUPTED) {

	reply_VFS_error(f_request, EINTR);
	return;

    }

    /* send fsetstat cause a handle is available */

    if (send_sftp_fsetstat_ctx(context->interface.ptr, &sftp_r)==0) {
	void *request=NULL;

	request=create_sftp_request_ctx(context->interface.ptr, &sftp_r, &error);

	if (request) {
	    struct timespec timeout;

	    get_sftp_request_timeout(&timeout);

	    if (wait_sftp_response_ctx(&context->interface, request, &timeout, &error)==1) {
		struct sftp_reply_s *reply=&sftp_r.reply;

		if (reply->type==SSH_FXP_STATUS) {

		    if (reply->response.status.code==0) {

			set_local_attributes(openfile->inode, &fuse_attr);
			_fs_common_getattr(get_root_context(context), f_request, openfile->inode);
			return;

		    } else {

			error=reply->response.status.linux_error;

		    }

		    logoutput("_fs_sftp_fsetattr: reply %i", reply->response.status.code);

		} else {

		    error=EPROTO;

		}

	    }

	}

    } else {

	error=sftp_r.reply.error;

    }

    out:
    reply_VFS_error(f_request, error);

}

void _fs_sftp_setattr_disconnected(struct service_context_s *context, struct fuse_request_s *f_request, struct inode_s *inode, struct pathinfo_s *pathinfo, struct stat *st, unsigned int set)
{
    reply_VFS_error(f_request, ENOTCONN);
}

void _fs_sftp_fsetattr_disconnected(struct fuse_openfile_s *openfile, struct fuse_request_s *f_request, struct stat *st, unsigned int set)
{
    reply_VFS_error(f_request, ENOTCONN);
}

