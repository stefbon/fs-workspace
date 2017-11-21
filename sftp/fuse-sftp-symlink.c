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

extern unsigned int get_uint32(unsigned char *buf);

/* READLINK */

void _fs_sftp_readlink(struct service_context_s *context, struct fuse_request_s *f_request, struct inode_s *inode, struct pathinfo_s *pathinfo)
{
    struct sftp_request_s sftp_r;
    unsigned int error=EIO;

    if (f_request->flags & FUSEDATA_FLAG_INTERRUPTED) {

	reply_VFS_error(f_request, EINTR);
	return;

    }

    memset(&sftp_r, 0, sizeof(struct sftp_request_s));

    sftp_r.id=0;
    sftp_r.call.readlink.path=(unsigned char *) pathinfo->path;
    sftp_r.call.readlink.len=pathinfo->len;
    sftp_r.fusedata_flags=&f_request->flags;

    if (send_sftp_readlink_ctx(context->interface.ptr, &sftp_r)==0) {
	void *request=NULL;

	request=create_sftp_request_ctx(context->interface.ptr, &sftp_r, &error);

	if (request) {
	    struct timespec timeout;

	    get_sftp_request_timeout(&timeout);

	    if (wait_sftp_response_ctx(context->interface.ptr, request, &timeout, &error)==1) {

		if (sftp_r.type==SSH_FXP_NAME) {
		    unsigned int len=get_uint32((unsigned char *) sftp_r.response.names.buff);
		    char path[len+1];

		    /* TODO: check the target is also inside the shared map */

		    memcpy(path, sftp_r.response.names.buff + 4, len);
		    path[len]='\0';

		    logoutput("_fs_sftp_readlink_common: %s target %s", pathinfo->path, path);

		    reply_VFS_data(f_request, path, len);

		    free(sftp_r.response.names.buff);
		    return;

		} else if (sftp_r.type==SSH_FXP_STATUS) {

		    error=sftp_r.response.status.linux_error;

		} else {

		    error=EPROTO;

		}

	    }

	}

    }

    out:
    reply_VFS_error(f_request, error);

}

/* SYMLINK */

void _fs_sftp_symlink(struct service_context_s *context, struct fuse_request_s *f_request, struct entry_s *entry, struct pathinfo_s *pathinfo, const char *target)
{
    struct sftp_request_s sftp_r;
    unsigned int error=EIO;

    if (f_request->flags & FUSEDATA_FLAG_INTERRUPTED) {

	reply_VFS_error(f_request, EINTR);
	return;

    }

    memset(&sftp_r, 0, sizeof(struct sftp_request_s));

    sftp_r.id=0;
    sftp_r.call.symlink.path=(unsigned char *) pathinfo->path;
    sftp_r.call.symlink.len=pathinfo->len;
    sftp_r.call.symlink.target_path=(unsigned char *) target;
    sftp_r.call.symlink.target_len=strlen(target);
    sftp_r.fusedata_flags=&f_request->flags;

    if (send_sftp_symlink_ctx(context->interface.ptr, &sftp_r)==0) {
	void *request=NULL;

	request=create_sftp_request_ctx(context->interface.ptr, &sftp_r, &error);

	if (request) {
	    struct timespec timeout;

	    get_sftp_request_timeout(&timeout);

	    if (wait_sftp_response_ctx(context->interface.ptr, request, &timeout, &error)==1) {

		if (sftp_r.type==SSH_FXP_STATUS) {

		    if (sftp_r.response.status.code==0) {

			reply_VFS_error(f_request, 0);
			return;

		    }

		    error=sftp_r.response.status.linux_error;

		} else {

		    error=EIO;

		}

	    }

	}

    }

    out:

    {

	struct inode_s *inode=entry->inode;
	unsigned int tmp_error=0;

	remove_entry(entry, &tmp_error);
	entry->inode=NULL;
	destroy_entry(entry);

	remove_inode(inode);

    }

    reply_VFS_error(f_request, error);

}

/*
    test the symlink pointing to target is valid
    - a symlink is valid when it stays inside the "root" directory of the shared map: target is a subdirectory of the root
*/

int _fs_sftp_symlink_validate(struct service_context_s *context, struct pathinfo_s *pathinfo, char *target, char **remote_target)
{

    if (target[0]=='/') {
	char *resolved_path=realpath(target, NULL);
	unsigned int len=0;

	if (! resolved_path) return -1;

	/* get the path relative to the directory for this context */

	len=symlink_generic_validate(context, resolved_path);

	if (len>0) {
	    char *target_sftp=&resolved_path[len];

	    logoutput("_fs_sftp_symlink_validate: found path %s relative to service", target_sftp);

	    if (check_realpath_sftp(&context->interface, target_sftp, remote_target)==0) {

		free(resolved_path);
		return 0;

	    }

	}

	free(resolved_path);

    } else {
	unsigned int len=strlen(target);
	char target_sftp[pathinfo->len + 2 + len];
	char *sep=NULL;

	sep=memrchr(pathinfo->path, '/', pathinfo->len);

	if (sep) {
	    unsigned int part=(unsigned int)(sep + 1 - pathinfo->path);

	    memcpy(target_sftp, pathinfo->path, part);
	    memcpy(target_sftp + part, target, len);
	    target_sftp[part + len]='\0';

	} else {

	    snprintf(target_sftp, pathinfo->len + len + 2, "%s", target);

	}

	logoutput("_fs_sftp_symlink_validate: found path %s relative to service", target_sftp);

	if (check_realpath_sftp(&context->interface, target_sftp, remote_target)==0) return 0;

    }

    return -1;

}
