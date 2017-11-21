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

#include "utils.h"
#include "pathinfo.h"

#include "fuse-fs.h"
#include "workspaces.h"
#include "workspace-context.h"
#include "entry-utils.h"
#include "fuse-interface.h"

#include "path-caching.h"

#include "fuse-fs-common.h"

#include "sftp-common-protocol.h"
#include "sftp-attr-common.h"
#include "sftp-send-common.h"

#include "fuse-sftp-common.h"

extern void *create_sftp_request_ctx(void *ptr, struct sftp_request_s *sftp_r, unsigned int *error);
extern unsigned char wait_sftp_response_ctx(void *ptr, void *r, struct timespec *timeout, unsigned int *error);
extern void get_sftp_request_timeout(struct timespec *timeout);

/* OPEN a file */

void _fs_sftp_open(struct fuse_openfile_s *openfile, struct fuse_request_s *f_request, struct pathinfo_s *pathinfo, unsigned int flags)
{
    struct service_context_s *context=(struct service_context_s *) openfile->context;
    struct context_interface_s *interface=&context->interface;
    struct sftp_request_s sftp_r;
    unsigned int error=EIO;
    unsigned int pathlen=(* interface->backend.sftp.get_complete_pathlen)(interface, pathinfo->len);
    char path[pathlen];

    logoutput("_fs_sftp_open");

    if (f_request->flags & FUSEDATA_FLAG_INTERRUPTED) {

	reply_VFS_error(f_request, EINTR);
	return;

    }

    pathinfo->len += (* interface->backend.sftp.complete_path)(interface, path, pathinfo);

    memset(&sftp_r, 0, sizeof(struct sftp_request_s));

    sftp_r.id=0;
    sftp_r.call.open.path=(unsigned char *) pathinfo->path;
    sftp_r.call.open.len=pathinfo->len;
    sftp_r.call.open.posix_flags=flags;
    sftp_r.fusedata_flags=&f_request->flags;

    if (send_sftp_open_ctx(context->interface.ptr, &sftp_r)==0) {
	void *request=NULL;

	request=create_sftp_request_ctx(context->interface.ptr, &sftp_r, &error);

	if (request) {
	    struct timespec timeout;

	    get_sftp_request_timeout(&timeout);

	    if (wait_sftp_response_ctx(context->interface.ptr, request, &timeout, &error)==1) {

		if (sftp_r.type==SSH_FXP_HANDLE) {
		    struct fuse_open_out open_out;
		    struct entry_s *entry=openfile->inode->alias;

		    /* handle name is defined in sftp_r.response.handle.name: take it "over" */

		    openfile->handle.name.name=(char *) sftp_r.response.handle.name;
		    openfile->handle.name.len=sftp_r.response.handle.len;

		    open_out.fh=(uint64_t) openfile;

		    if (entry->flags & _ENTRY_FLAG_REMOTECHANGED) {

			/* VFS will free any cached data for this file */

			open_out.open_flags=0;
			entry->flags -= _ENTRY_FLAG_REMOTECHANGED;

		    } else {

			/* if there is a local cache it's uptodate */

			// open_out.open_flags=FOPEN_KEEP_CACHE;
			open_out.open_flags=0;

		    }

		    open_out.padding=0;
		    reply_VFS_data(f_request, (char *) &open_out, sizeof(open_out));
		    return;

		} else if (sftp_r.type==SSH_FXP_STATUS) {

		    error=sftp_r.response.status.linux_error;
		    logoutput("_fs_sftp_open: status reply %i", error);

		} else {

		    error=EPROTO;

		}

	    }

	}

    }

    out:

    openfile->error=error;
    reply_VFS_error(f_request, error);

}

/* CREATE a file */

void _fs_sftp_create(struct fuse_openfile_s *openfile, struct fuse_request_s *f_request, struct pathinfo_s *pathinfo, struct stat *st, unsigned int flags)
{
    struct service_context_s *context=(struct service_context_s *) openfile->context;
    struct context_interface_s *interface=&context->interface;
    struct sftp_request_s sftp_r;
    unsigned int error=EIO;
    struct fuse_sftp_attr_s fuse_attr;
    unsigned int size=get_attr_buffer_size(context->interface.ptr, st, FATTR_MODE | FATTR_SIZE | FATTR_UID | FATTR_GID, &fuse_attr); /* uid and gid by server ?*/
    unsigned char buffer[size];
    unsigned int pathlen=(* interface->backend.sftp.get_complete_pathlen)(interface, pathinfo->len);
    char path[pathlen];

    if (f_request->flags & FUSEDATA_FLAG_INTERRUPTED) {

	reply_VFS_error(f_request, EINTR);
	return;

    }

    pathinfo->len += (* interface->backend.sftp.complete_path)(interface, path, pathinfo);

    logoutput("_fs_sftp_create: path %s len %i", pathinfo->path, pathinfo->len);

    size=write_attributes_ctx(context->interface.ptr, buffer, size, &fuse_attr);
    memset(&sftp_r, 0, sizeof(struct sftp_request_s));

    sftp_r.id=0;
    sftp_r.call.create.path=(unsigned char *) pathinfo->path;
    sftp_r.call.create.len=pathinfo->len;
    sftp_r.call.create.posix_flags=flags;
    sftp_r.call.create.size=size;
    sftp_r.call.create.buff=buffer; /* buffer should be filled with attr by calling process */
    sftp_r.fusedata_flags=&f_request->flags;

    if (send_sftp_create_ctx(context->interface.ptr, &sftp_r)==0) {
	void *request=NULL;

	request=create_sftp_request_ctx(context->interface.ptr, &sftp_r, &error);

	if (request) {
	    struct timespec timeout;

	    get_sftp_request_timeout(&timeout);

	    if (wait_sftp_response_ctx(context->interface.ptr, request, &timeout, &error)==1) {

		if (sftp_r.type==SSH_FXP_HANDLE) {

		    /* handle name is defined in sftp_r.response.handle.name: take it "over" */

		    openfile->handle.name.name=(char *) sftp_r.response.handle.name;
		    openfile->handle.name.len=sftp_r.response.handle.len;
		    fill_inode_attr_sftp(context->interface.ptr, openfile->inode, &fuse_attr);
		    add_inode_context(context, openfile->inode);

		    /* note: how the entry is created on the remote server does not have to be the same .... */

		    _fs_common_cached_create(context, f_request, openfile);

		    return;

		} else if (sftp_r.type==SSH_FXP_STATUS) {

		    error=sftp_r.response.status.linux_error;
		    logoutput("_fs_sftp_create: status reply %i", error);

		    /* set an error open/create understands */

		    error=EINVAL;

		} else {

		    error=EINVAL;

		}

	    }

	}

    }

    out:
    openfile->error=error;
    reply_VFS_error(f_request, error);

}

/* READ a file */

void _fs_sftp_read(struct fuse_openfile_s *openfile, struct fuse_request_s *f_request, size_t size, off_t off, unsigned int flags, uint64_t lock_owner)
{
    struct service_context_s *context=(struct service_context_s *) openfile->context;
    struct sftp_request_s sftp_r;
    unsigned int error=EIO;

    if (f_request->flags & FUSEDATA_FLAG_INTERRUPTED) {

	reply_VFS_error(f_request, EINTR);
	return;

    }

    memset(&sftp_r, 0, sizeof(struct sftp_request_s));

    sftp_r.id=0;
    sftp_r.call.read.handle=(unsigned char *) openfile->handle.name.name;
    sftp_r.call.read.len=openfile->handle.name.len;
    sftp_r.call.read.offset=(uint64_t) off;
    sftp_r.fusedata_flags=&f_request->flags;
    sftp_r.call.read.size=(uint64_t) size;

    /* ignore flags and lockowner */

    if (send_sftp_read_ctx(context->interface.ptr, &sftp_r)==0) {
	void *request=NULL;

	request=create_sftp_request_ctx(context->interface.ptr, &sftp_r, &error);

	if (request) {
	    struct timespec timeout;

	    get_sftp_request_timeout(&timeout);
	    error=0;

	    if (wait_sftp_response_ctx(context->interface.ptr, request, &timeout, &error)==1) {

		if (sftp_r.type==SSH_FXP_DATA) {

		    logoutput("_fs_sftp_read: received %i bytes", sftp_r.response.data.size);

		    reply_VFS_data(f_request, sftp_r.response.data.data, sftp_r.response.data.size);

		    free(sftp_r.response.data.data);
		    sftp_r.response.data.data=NULL;
		    return;

		} else if (sftp_r.type==SSH_FXP_STATUS) {

		    if (sftp_r.response.status.linux_error==ENODATA) {
			char dummy='\0';

			reply_VFS_data(f_request, &dummy, 0);
			return;

		    }

		    error=sftp_r.response.status.linux_error;
		    logoutput("_fs_sftp_read: status reply %i", error);

		} else {

		    error=EPROTO;

		}

	    }

	}

    }

    out:

    reply_VFS_error(f_request, error);

}

/* WRITE to a file */

void _fs_sftp_write(struct fuse_openfile_s *openfile, struct fuse_request_s *f_request, const char *buff, size_t size, off_t off, unsigned int flags, uint64_t lock_owner)
{
    struct service_context_s *context=(struct service_context_s *) openfile->context;
    struct sftp_request_s sftp_r;
    unsigned int error=EIO;

    if (f_request->flags & FUSEDATA_FLAG_INTERRUPTED) {

	reply_VFS_error(f_request, EINTR);
	return;

    }

    memset(&sftp_r, 0, sizeof(struct sftp_request_s));

    sftp_r.id=0;
    sftp_r.call.write.handle=(unsigned char *) openfile->handle.name.name;
    sftp_r.call.write.len=openfile->handle.name.len;
    sftp_r.call.write.offset=(uint64_t) off;
    sftp_r.call.write.size=(uint64_t) size;
    sftp_r.call.write.data=buff;
    sftp_r.fusedata_flags=&f_request->flags;

    if (send_sftp_write_ctx(context->interface.ptr, &sftp_r)==0) {
	void *request=NULL;

	request=create_sftp_request_ctx(context->interface.ptr, &sftp_r, &error);

	if (request) {
	    struct timespec timeout;

	    get_sftp_request_timeout(&timeout);

	    if (wait_sftp_response_ctx(context->interface.ptr, request, &timeout, &error)==1) {

		if (sftp_r.type==SSH_FXP_STATUS) {

		    if (sftp_r.response.status.code==0) {
			struct fuse_write_out write_out;

			write_out.size=size;
			write_out.padding=0;

			reply_VFS_data(f_request, (char *) &write_out, sizeof(struct fuse_write_out));
			return;

		    } else {

			error=sftp_r.response.status.linux_error;
			logoutput("_fs_sftp_write: status reply %i", error);

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

/* FSYNC a file */

void _fs_sftp_fsync(struct fuse_openfile_s *openfile, struct fuse_request_s *f_request, unsigned char datasync)
{
    struct service_context_s *context=(struct service_context_s *) openfile->context;
    struct sftp_request_s sftp_r;
    unsigned int error=EIO;

    if (f_request->flags & FUSEDATA_FLAG_INTERRUPTED) {

	reply_VFS_error(f_request, EINTR);
	return;

    }

    if (get_support_sftp_ctx(context->interface.ptr, "fsync@openssh.com")==-1) {

	error=0;
	goto out;

    }

    memset(&sftp_r, 0, sizeof(struct sftp_request_s));

    sftp_r.id=0;
    sftp_r.call.fsync.handle=(unsigned char *) openfile->handle.name.name;
    sftp_r.call.fsync.len=openfile->handle.name.len;
    sftp_r.fusedata_flags=&f_request->flags;

    if (send_sftp_fsync_ctx(context->interface.ptr, &sftp_r)==0) {
	void *request=NULL;

	request=create_sftp_request_ctx(context->interface.ptr, &sftp_r, &error);

	if (request) {
	    struct timespec timeout;

	    get_sftp_request_timeout(&timeout);

	    if (wait_sftp_response_ctx(context->interface.ptr, request, &timeout, &error)==1) {

		if (sftp_r.type==SSH_FXP_STATUS) {

		    /*
			send ok reply to VFS no matter what the ssh server reports
		    */

		    reply_VFS_error(f_request, 0);

		    if (sftp_r.response.status.linux_error==EOPNOTSUPP) {

			set_support_sftp_ctx(context->interface.ptr, "fsync@openssh.com", -1);

		    } else if (sftp_r.response.status.code>0) {

			error=sftp_r.response.status.linux_error;
			logoutput_notice("_fs_sftp_fsync: status reply %i:%s", error, strerror(error));

		    }

		    return;

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

/* FLUSH a file */

void _fs_sftp_flush(struct fuse_openfile_s *openfile, struct fuse_request_s *f_request, uint64_t lockowner)
{
    struct service_context_s *context=(struct service_context_s *) openfile->context;

    /* no support for flush */

    reply_VFS_error(f_request, 0);
}

/* CLOSE a file */

void _fs_sftp_release(struct fuse_openfile_s *openfile, struct fuse_request_s *f_request, unsigned int flags, uint64_t lock_owner)
{
    struct service_context_s *context=(struct service_context_s *) openfile->context;
    struct sftp_request_s sftp_r;
    unsigned int error=EIO;

    if (f_request->flags & FUSEDATA_FLAG_INTERRUPTED) {

	reply_VFS_error(f_request, EINTR);
	return;

    }

    memset(&sftp_r, 0, sizeof(struct sftp_request_s));

    sftp_r.id=0;
    sftp_r.call.close.handle=(unsigned char *) openfile->handle.name.name;
    sftp_r.call.close.len=openfile->handle.name.len;
    sftp_r.fusedata_flags=&f_request->flags;

    /*
	TODO:
	- handle flush?
	- unlock when lock set (flock)
    */

    if (send_sftp_close_ctx(context->interface.ptr, &sftp_r)==0) {
	void *request=NULL;

	request=create_sftp_request_ctx(context->interface.ptr, &sftp_r, &error);

	if (request) {
	    struct timespec timeout;

	    get_sftp_request_timeout(&timeout);

	    if (wait_sftp_response_ctx(context->interface.ptr, request, &timeout, &error)==1) {

		if (sftp_r.type==SSH_FXP_STATUS) {
		    struct entry_s *entry=openfile->inode->alias;

		    /*
			send ok reply to VFS no matter what the ssh server reports
		    */

		    reply_VFS_error(f_request, 0);

		    free(openfile->handle.name.name);
		    openfile->handle.name.name=NULL;
		    openfile->handle.name.len=0;

		    if (sftp_r.response.status.code!=0) {

			error=sftp_r.response.status.linux_error;
			logoutput_notice("_fs_sftp_release: status reply %i:%s", error, strerror(error));

		    }

		    return;

		} else {

		    error=EPROTO;

		}

	    }

	}

    }

    out:

    reply_VFS_error(f_request, error);

    free(openfile->handle.name.name);
    openfile->handle.name.name=NULL;
    openfile->handle.name.len=0;

}
