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
#include <stdint.h>
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
#include <sys/vfs.h>

#include "main.h"
#include "logging.h"
#include "utils.h"
#include "pathinfo.h"

#include "fuse-fs.h"
#include "workspaces.h"
#include "workspace-context.h"
#include "fuse-utils.h"
#include "fuse-interface.h"

#include "path-caching.h"

#include "fuse-fs-common.h"

#include "sftp-common-protocol.h"
#include "sftp-attr-common.h"
#include "sftp-send-common.h"

#include "fuse-sftp-common.h"

#define UINT32_T_MAX		0xFFFFFFFF

extern void *create_sftp_request_ctx(void *ptr, struct sftp_request_s *sftp_r, unsigned int *error);
extern unsigned char wait_sftp_response_ctx(struct context_interface_s *i, void *r, struct timespec *timeout, unsigned int *error);
extern void get_sftp_request_timeout(struct timespec *timeout);

extern unsigned int get_uint32(unsigned char *buf);
extern uint64_t get_uint64(unsigned char *buf);

static struct statfs fallback_statfs;

static void _fs_sftp_statfs_unsupp(struct service_context_s *context, struct fuse_request_s *f_request, struct pathinfo_s *pathinfo)
{
    struct fuse_statfs_out statfs_out;

    memset(&statfs_out, 0, sizeof(struct fuse_statfs_out));

    statfs_out.st.blocks=fallback_statfs.f_blocks;
    statfs_out.st.bfree=fallback_statfs.f_bfree;
    statfs_out.st.bavail=fallback_statfs.f_bavail;
    statfs_out.st.bsize=fallback_statfs.f_bsize;

    statfs_out.st.frsize=fallback_statfs.f_bsize;

    statfs_out.st.files=(uint64_t) context->workspace->nrinodes;
    // statfs_out.st.ffree=(uint64_t) (UINT64_MAX - statfs_out.st.files);
    statfs_out.st.ffree=(uint64_t) (UINT32_T_MAX - statfs_out.st.files);

    statfs_out.st.namelen=255;
    statfs_out.st.padding=0;

    reply_VFS_data(f_request, (char *) &statfs_out, sizeof(struct fuse_statfs_out));

}

/* STATVFS */

void _fs_sftp_statfs(struct service_context_s *context, struct fuse_request_s *f_request, struct pathinfo_s *pathinfo)
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

    if (get_support_sftp_ctx(context->interface.ptr, "statvfs@openssh.com")==-1) {

	_fs_sftp_statfs_unsupp(context, f_request, pathinfo);
	return;

    }

    pathinfo->len += (* interface->backend.sftp.complete_path)(interface, path, pathinfo);

    memset(&sftp_r, 0, sizeof(struct sftp_request_s));

    sftp_r.id=0;
    sftp_r.call.statvfs.path=(unsigned char *) pathinfo->path;
    sftp_r.call.statvfs.len=pathinfo->len;
    sftp_r.fuse_request=f_request;

    if (send_sftp_statvfs_ctx(context->interface.ptr, &sftp_r)==0) {
	void *request=NULL;

	request=create_sftp_request_ctx(context->interface.ptr, &sftp_r, &error);

	if (request) {
	    struct timespec timeout;

	    get_sftp_request_timeout(&timeout);

	    if (wait_sftp_response_ctx(interface, request, &timeout, &error)==1) {

		if (sftp_r.type==SSH_FXP_EXTENDED_REPLY) {
		    struct fuse_statfs_out statfs_out;
		    unsigned char *pos=sftp_r.response.extension.buff;
		    uint64_t f_flag=0;

		    /*
			reply looks like

			8 f_bsize
			8 f_frsize
			8 f_blocks
			8 f_bfree
			8 f_bavail
			8 f_files
			8 f_ffree
			8 f_favail
			8 f_fsid
			8 f_flag
			8 f_namemax

		    */

		    memset(&statfs_out, 0, sizeof(struct fuse_statfs_out));

		    statfs_out.st.bsize=get_uint64(pos);
		    pos+=8;

		    statfs_out.st.frsize=get_uint64(pos);
		    pos+=8;

		    statfs_out.st.blocks=get_uint64(pos);
		    pos+=8;

		    statfs_out.st.bfree=get_uint64(pos);
		    pos+=8;

		    statfs_out.st.bavail=get_uint64(pos);
		    pos+=8;

		    statfs_out.st.files=(uint64_t) context->workspace->nrinodes;
		    pos+=8;

		    // statfs_out.st.ffree=(uint64_t) ((uint64_t) -1) - statfs_out.st.files;
		    statfs_out.st.ffree=(uint64_t) (UINT32_T_MAX - statfs_out.st.files);
		    pos+=8;

		    /* ignore favail */
		    pos+=8;

		    /* ignore fsid */
		    pos+=8;

		    /* ignore flag */
		    f_flag=get_uint64(pos);
		    pos+=8;

		    /* namelen as uint64??? sftp can handle very very long filenames; uint16 would be enough */
		    statfs_out.st.namelen=get_uint64(pos);
		    pos+=8;

		    logoutput("_fs_sftp_statfs: f_flag %li namelen %i size %i pos %i", f_flag, (unsigned int) statfs_out.st.namelen, sftp_r.response.extension.size, (unsigned int)(pos - sftp_r.response.extension.buff));

		    statfs_out.st.padding=0;

		    reply_VFS_data(f_request, (char *) &statfs_out, sizeof(struct fuse_statfs_out));

		    free(sftp_r.response.extension.buff);

		    return;

		} else if (sftp_r.type==SSH_FXP_STATUS) {

		    if (sftp_r.response.status.linux_error==EOPNOTSUPP) {

			set_support_sftp_ctx(context->interface.ptr, "statvfs@openssh.com", -1);
			_fs_sftp_statfs_unsupp(context, f_request, pathinfo);
			return;

		    }

		    error=sftp_r.response.status.linux_error;

		    /* here: if error: not supported */

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

void set_fallback_statfs_sftp(struct statfs *fallback)
{
    memcpy(&fallback_statfs, fallback, sizeof(struct statfs));
}

void _fs_sftp_statfs_disconnected(struct service_context_s *context, struct fuse_request_s *f_request, struct pathinfo_s *pathinfo)
{
    _fs_sftp_statfs_unsupp(context, f_request, pathinfo);
}
