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
#include "options.h"

#include "fuse-fs.h"
#include "workspaces.h"
#include "workspace-context.h"
#include "workspace-interface.h"
#include "fuse-utils.h"
#include "fuse-interface.h"

#include "path-caching.h"
#include "fuse-fs-common.h"

#include "ssh-common.h"
#include "sftp-common-protocol.h"
#include "sftp-common.h"
#include "sftp-attr-common.h"
#include "sftp-send-common.h"

#include "fuse-sftp-common.h"
#include "fuse-sftp-realpath.h"
#include "sftp-common-utils.h"

extern void *create_sftp_request_ctx(void *ptr, struct sftp_request_s *sftp_r, unsigned int *error);
extern unsigned char wait_sftp_response_ctx(struct context_interface_s *i, void *r, struct timespec *timeout, unsigned int *error);
extern void get_sftp_request_timeout(struct timespec *timeout);
extern struct fs_options_s fs_options;

static char *nullpath='\0';
static unsigned int get_sftp_prefix(struct service_context_s *context, struct ssh_string_s *prefix)
{
    struct context_interface_s *interface=&context->interface;
    unsigned int tmp=0;

    if (interface->backend.sftp.prefix.type==CONTEXT_INTERFACE_BACKEND_SFTP_PREFIX_HOME) {

	tmp=get_sftp_remote_home(interface->ptr, prefix);

    } else if (interface->backend.sftp.prefix.type==CONTEXT_INTERFACE_BACKEND_SFTP_PREFIX_CUSTOM) {

	tmp=interface->backend.sftp.prefix.len;
	prefix->ptr=interface->backend.sftp.prefix.path;
	prefix->len=interface->backend.sftp.prefix.len;

    } else if (interface->backend.sftp.prefix.type==CONTEXT_INTERFACE_BACKEND_SFTP_PREFIX_ROOT) {

	prefix->ptr=nullpath;
	prefix->len=0;
	tmp=0;

    }

    return tmp;
}

/* construct the full path:
    - mountpoint
    - path to the sftp context == shared folder in this fuse fs
    - actual symlink as reported by the remote system

    and

    send this to the VFS
*/

static void reply_sftp_readlink(struct service_context_s *context, struct fuse_request_s *f_request, char *path, unsigned int len)
{
    struct workspace_mount_s *workspace=context->workspace;
    unsigned int written=0;
    unsigned int pathmax=workspace->pathmax; /* should we use PATH_MAX here ?? */
    unsigned int fullpathlen=workspace->mountpoint.len + pathmax + len + 1;
    char fullpath[fullpathlen];
    char fusepath[pathmax];
    struct fuse_path_s fpath;

    /* fuse path from mountpoint to the entry where this remote directory is ""mounted"*/

    init_fuse_path(&fpath, fusepath, pathmax);
    fpath.len=get_path_root(context->service.filesystem.inode, &fpath);

    written=snprintf(fullpath, fullpathlen, "%.*s%.*s%.*s", workspace->mountpoint.len, workspace->mountpoint.path, fpath.len, fpath.pathstart, len, path);
    reply_VFS_data(f_request, fullpath, written);
}

static void create_reply_sftp_readlink(struct service_context_s *context, struct fuse_request_s *f_request, char *path, unsigned int len)
{
    struct context_interface_s *interface=&context->interface;
    unsigned int tmp=0;
    struct ssh_string_s prefix;
    char *result=NULL;

    logoutput("create_reply_sftp_readlink: path %.*s", len, path);

    if (fs_options.sftp.flags & _OPTIONS_SFTP_FLAG_SYMLINK_ALLOW_PREFIX) {

	tmp=get_sftp_prefix(context, &prefix);

	logoutput("create_reply_sftp_readlink: get prefix (len=%i) %.*s", tmp, tmp, (tmp>0) ? prefix.ptr : "");

	if (tmp==0 || (tmp>0 && tmp<len && strncmp(path, prefix.ptr, tmp)==0 && path[tmp]=='/')) {

	    result=path+tmp;
	    len-=tmp;
	    goto reply;

	}

	goto error;

    } else if (fs_options.sftp.flags & _OPTIONS_SFTP_FLAG_SYMLINK_ALLOW_CROSS_INTERFACE) {
	struct service_context_s *c=get_next_service_context(NULL, "sftp");

	/* walk every sftp context, but take only those with the parent == ssh connection */

	while (c) {

	    if (c->workspace==context->workspace && c->parent==context->parent) {

		tmp=get_sftp_prefix(c, &prefix);

		if (tmp==0 || (tmp>0 && tmp<len && strncmp(path, prefix.ptr, tmp)==0 && path[tmp]=='/')) {

		    result=path+tmp;
		    len-=tmp;
		    goto reply;

		}

	    }

	    c=get_next_service_context(c, "sftp");

	}

	goto error;

    } else {

	goto error;

    }

    reply:

    reply_sftp_readlink(context, f_request, result, len);
    return;

    error:

    reply_VFS_error(f_request, ENOENT);

}


/* READLINK */

void _fs_sftp_readlink(struct service_context_s *context, struct fuse_request_s *f_request, struct inode_s *inode, struct pathinfo_s *pathinfo)
{
    struct context_interface_s *interface=&context->interface;
    struct sftp_request_s sftp_r;
    unsigned int error=EIO;
    unsigned int pathlen=(* interface->backend.sftp.get_complete_pathlen)(interface, pathinfo->len);
    char completepath[pathlen];

    logoutput("_fs_sftp_readlink_common");

    if ((* f_request->is_interrupted)(f_request)) {

	reply_VFS_error(f_request, EINTR);
	return;

    }

    pathinfo->len += (* interface->backend.sftp.complete_path)(interface, completepath, pathinfo);

    memset(&sftp_r, 0, sizeof(struct sftp_request_s));

    logoutput("_fs_sftp_readlink_common: path %.*s", pathinfo->len, pathinfo->path);
    memset(completepath, '\0', pathlen);

    if (fs_options.sftp.flags & _OPTIONS_SFTP_FLAG_SYMLINKS_DISABLE) {

	reply_VFS_error(f_request, ENOENT);
	return;

    }

    sftp_r.id=0;
    sftp_r.call.readlink.path=(unsigned char *) pathinfo->path;
    sftp_r.call.readlink.len=pathinfo->len;
    sftp_r.fuse_request=f_request;

    if (send_sftp_readlink_ctx(context->interface.ptr, &sftp_r)==0) {
	void *request=NULL;

	request=create_sftp_request_ctx(context->interface.ptr, &sftp_r, &error);

	if (request) {
	    struct timespec timeout;

	    get_sftp_request_timeout(&timeout);

	    if (wait_sftp_response_ctx(&context->interface, request, &timeout, &error)==1) {

		logoutput("_fs_sftp_readlink_common: reply %i", sftp_r.type);

		if (sftp_r.type==SSH_FXP_NAME) {
		    unsigned int len=get_uint32(sftp_r.response.names.buff);
		    char path[len+1];

		    /* TODO: check the target is also inside the shared map */
		    /* TODO: if not starting with a slash (==not absolute) get the realpath from server */

		    memcpy(path, sftp_r.response.names.buff + 4, len);
		    path[len]='\0';

		    logoutput("_fs_sftp_readlink_common: %s target %s", pathinfo->path, path);

		    if (!(path[0] == '/')) {
			char fullpath[len + pathinfo->len];
			char *sep=memrchr(pathinfo->path, '/', pathinfo->len);
			unsigned int fullpathlen;

			logoutput("_fs_sftp_readlink_common: A1");

			if (sep) {

			    pathinfo->len=(unsigned int) (sep + 1 - pathinfo->path);
			    memcpy(fullpath, pathinfo->path, pathinfo->len);
			    memcpy(&fullpath[pathinfo->len], path, len);

			    fullpathlen=pathinfo->len + len;

			} else {

			    memcpy(fullpath, path, len);
			    fullpathlen=len;

			}

			free(sftp_r.response.names.buff);

			/* TODO: reuse request to be used for the sending and waiting for the realpath */

			sftp_r.id=0;
			sftp_r.call.realpath.path=(unsigned char *)fullpath;
			sftp_r.call.realpath.len=fullpathlen;

			logoutput("_fs_sftp_readlink_common: composed path %.*s", fullpathlen, fullpath);

			if (send_sftp_realpath_ctx(context->interface.ptr, &sftp_r)==0) {

			    request=create_sftp_request_ctx(context->interface.ptr, &sftp_r, &error);

			    if (request && wait_sftp_response_ctx(&context->interface, request, &timeout, &error)==1) {

				if (sftp_r.type==SSH_FXP_NAME) {
				    unsigned int realpathlen=get_uint32(sftp_r.response.names.buff);
				    char realpath[realpathlen];

				    memcpy(realpath, sftp_r.response.names.buff + 4, realpathlen);
				    create_reply_sftp_readlink(context, f_request, realpath, realpathlen);
				    free(sftp_r.response.names.buff);
				    return;

				} else if (sftp_r.type==SSH_FXP_STATUS) {

				    error=sftp_r.response.status.linux_error;
				    goto out;

				}

			    }

			}

		    }

		    /* get the prefix:
		    - with root its ready
		    - with custom prefix it in interface->backend.sftp.prefix
		    - with hone its in ?? */

		    logoutput("_fs_sftp_readlink_common: A2");

		    create_reply_sftp_readlink(context, f_request, path, len);
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
    struct service_context_s *rootcontext=get_root_context(context);
    struct sftp_request_s sftp_r;
    unsigned int error=EIO;

    if ((* f_request->is_interrupted)(f_request)) {

	reply_VFS_error(f_request, EINTR);
	return;

    }

    memset(&sftp_r, 0, sizeof(struct sftp_request_s));

    sftp_r.id=0;
    sftp_r.call.symlink.path=(unsigned char *) pathinfo->path;
    sftp_r.call.symlink.len=pathinfo->len;
    sftp_r.call.symlink.target_path=(unsigned char *) target;
    sftp_r.call.symlink.target_len=strlen(target);
    sftp_r.fuse_request=f_request;

    if (send_sftp_symlink_ctx(context->interface.ptr, &sftp_r)==0) {
	void *request=NULL;

	request=create_sftp_request_ctx(context->interface.ptr, &sftp_r, &error);

	if (request) {
	    struct timespec timeout;

	    get_sftp_request_timeout(&timeout);

	    if (wait_sftp_response_ctx(&context->interface, request, &timeout, &error)==1) {

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

    queue_inode_2forget(entry->inode->st.st_ino, context->unique, 0, 0);
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

void _fs_sftp_readlink_disconnected(struct service_context_s *context, struct fuse_request_s *f_request, struct inode_s *inode, struct pathinfo_s *pathinfo)
{
    reply_VFS_error(f_request, ENOTCONN);
}

void _fs_sftp_symlink_disconnected(struct service_context_s *context, struct fuse_request_s *f_request, struct entry_s *entry, struct pathinfo_s *pathinfo, const char *target)
{
    reply_VFS_error(f_request, ENOTCONN);
}

int _fs_sftp_symlink_validate_disconnected(struct service_context_s *context, struct pathinfo_s *pathinfo, char *target, char **remote_target)
{
    return -1;
}
