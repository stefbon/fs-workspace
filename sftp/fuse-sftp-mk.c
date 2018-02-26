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

/* CREATE a directory */

void _fs_sftp_mkdir(struct service_context_s *context, struct fuse_request_s *f_request, struct entry_s *entry, struct pathinfo_s *pathinfo, struct stat *st)
{
    struct context_interface_s *interface=&context->interface;
    struct sftp_request_s sftp_r;
    struct fuse_sftp_attr_s fuse_attr;
    unsigned int size=get_attr_buffer_size(context->interface.ptr, st, FATTR_MODE | FATTR_UID | FATTR_GID, &fuse_attr); /* uid and gid by server ?*/
    unsigned char buffer[size];
    unsigned int error=EIO;
    unsigned int pathlen=(* interface->backend.sftp.get_complete_pathlen)(interface, pathinfo->len);
    char path[pathlen];

    if (f_request->flags & FUSEDATA_FLAG_INTERRUPTED) {

	reply_VFS_error(f_request, EINTR);
	return;

    }

    pathinfo->len += (* interface->backend.sftp.complete_path)(interface, path, pathinfo);

    size=write_attributes_ctx(context->interface.ptr, buffer, size, &fuse_attr);
    init_sftp_request(&sftp_r);

    sftp_r.id=0;
    sftp_r.call.mkdir.path=(unsigned char *) pathinfo->path;
    sftp_r.call.mkdir.len=pathinfo->len;
    sftp_r.call.mkdir.size=size;
    sftp_r.call.mkdir.buff=buffer;
    sftp_r.fusedata_flags=&f_request->flags;

    if (send_sftp_mkdir_ctx(context->interface.ptr, &sftp_r)==0) {
	void *request=NULL;

	request=create_sftp_request_ctx(context->interface.ptr, &sftp_r, &error);

	if (request) {
	    struct timespec timeout;

	    get_sftp_request_timeout(&timeout);

	    if (wait_sftp_response_ctx(context->interface.ptr, request, &timeout, &error)==1) {

		if (sftp_r.type==SSH_FXP_STATUS) {

		    if (sftp_r.response.status.code==0) {
			struct inode_s *inode=entry->inode;
			struct entry_s *parent=entry->parent;

			inode->nlookup++;
			inode->nlink=2;

			get_current_time(&inode->stim);
			add_inode_context(context, inode);
			_fs_common_cached_lookup(context, f_request, inode);
			adjust_pathmax(context->workspace, pathinfo->len);

			return;

		    }

		    error=sftp_r.response.status.linux_error;
		    logoutput("_fs_sftp_create: status reply %i", error);

		} else {

		    error=EINVAL;

		}

	    }

	}

    }

    struct inode_s *inode=entry->inode;
    unsigned int tmp_error=0;

    remove_entry(entry, &tmp_error);
    entry->inode=NULL;
    destroy_entry(entry);

    remove_inode(inode);

    out:

    reply_VFS_error(f_request, error);

}

/* mknod not supported in sftp; emulate with create? */

void _fs_sftp_mknod(struct service_context_s *context, struct fuse_request_s *f_request, struct entry_s *entry, struct pathinfo_s *pathinfo, struct stat *st)
{
    reply_VFS_error(f_request, ENOSYS);
}
