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
#include "entry-utils.h"
#include "fuse-interface.h"

#include "path-caching.h"

#include "fuse-fs-common.h"

#include "sftp-common-protocol.h"
#include "sftp-attr-common.h"
#include "sftp-send-common.h"

#include "fuse-sftp-common.h"

extern void *create_sftp_request_ctx(void *ptr, struct sftp_request_s *sftp_r, unsigned int *error);
extern unsigned char wait_sftp_response_ctx(struct context_interface_s *i, void *r, struct timespec *timeout, unsigned int *error);
extern void get_sftp_request_timeout(struct timespec *timeout);

extern unsigned int get_uint32(unsigned char *buf);
extern uint64_t get_uint64(unsigned char *buf);

/* FSNOTIFY (note: no reply to fuse)
*/

void _fs_sftp_fsnotify(struct service_context_s *context, struct fuse_request_s *f_request, struct pathinfo_s *pathinfo, uint64_t unique, uint32_t mask)
{
    struct context_interface_s *interface=&context->interface;
    struct sftp_request_s sftp_r;
    unsigned int error=EIO;
    unsigned int pathlen=(* interface->backend.sftp.get_complete_pathlen)(interface, pathinfo->len);
    char path[pathlen];

    if (get_support_sftp_ctx(context->interface.ptr, "fsnotify@bononline.nl")==-1) return;

    pathinfo->len += (* interface->backend.sftp.complete_path)(interface, path, pathinfo);
    init_sftp_request(&sftp_r);

    sftp_r.id=0;
    sftp_r.call.fsnotify.path=(unsigned char *) pathinfo->path;
    sftp_r.call.fsnotify.len=pathinfo->len;
    sftp_r.call.fsnotify.unique=unique;
    sftp_r.call.fsnotify.mask=mask;
    sftp_r.fusedata_flags=&f_request->flags;

    if (send_sftp_fsnotify_ctx(context->interface.ptr, &sftp_r)==0) {
	void *request=NULL;

	request=create_sftp_request_ctx(context->interface.ptr, &sftp_r, &error);

	if (request) {
	    struct timespec timeout;

	    get_sftp_request_timeout(&timeout);

	    if (wait_sftp_response_ctx(interface, request, &timeout, &error)==1) {

		if (sftp_r.type==SSH_FXP_EXTENDED_REPLY) {
		    unsigned char *pos=sftp_r.response.extension.buff;
		    unsigned int reply_mask=get_uint32(pos);

		    // set_fsnotify_mask_sftp(unique, reply_mask);

		    free(sftp_r.response.extension.buff);
		    return;

		} else if (sftp_r.type==SSH_FXP_STATUS) {

		    if (sftp_r.response.status.linux_error==EOPNOTSUPP) {

			set_support_sftp_ctx(context->interface.ptr, "fsnotify@bononline.nl", -1);
			return;

		    }

		    error=sftp_r.response.status.linux_error;

		} else {

		    error=EPROTO;

		}

	    }

	}

    } else {

	error=sftp_r.error;

    }

    logoutput("_fs_sftp_fsnotify: error %i fsnotify (%s)", error, strerror(error));

}

void _fs_sftp_fsnotify_disconnected(struct service_context_s *context, struct fuse_request_s *f_request, struct pathinfo_s *pathinfo, uint64_t unique, uint32_t mask)
{
}