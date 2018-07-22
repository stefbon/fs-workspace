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
#include "workspace-interface.h"
#include "entry-utils.h"
#include "fuse-interface.h"

#include "path-caching.h"
#include "fuse-fs-common.h"

#include "ssh-common.h"
#include "sftp-common-protocol.h"
#include "sftp-common.h"
#include "sftp-attr-common.h"
#include "sftp-send-common.h"

#include "fuse-sftp-common.h"

extern void *create_sftp_request_ctx(void *ptr, struct sftp_request_s *sftp_r, unsigned int *error);
extern unsigned char wait_sftp_response_ctx(struct context_interface_s *i, void *r, struct timespec *timeout, unsigned int *error);
extern void get_sftp_request_timeout(struct timespec *timeout);

/* path is absolute on the remote system, but has no meaning on this host:
    - when making a path absolute by prepending the mount path
    - path a absolute to the prefic on the remote host: prepend the prefix */

static void reply_VFS_symlink(struct service_context_s *context, struct fuse_request_s *f_request, char *path, unsigned int len)
{
    struct service_context_s *search=NULL;
    struct list_element_s *list=NULL;
    struct context_interface_s *interface=&context->interface;
    struct workspace_mount_s *workspace=context->workspace;
    unsigned int written=0;
    unsigned int pathmax=workspace->pathmax; /* should we use PATH_MAX here ?? */
    unsigned int fullpathlen=workspace->mountpoint.len + pathmax + len + 1;
    char fullpath[fullpathlen];
    char fusepath[pathmax];
    struct fuse_path_s fpath;

    /* fuse path from mountpoint to the entry where this remote directory is ""mounted"*/

    init_fuse_path(&fpath, fusepath, pathmax);
    fpath.len=get_path_root(context->inode, &fpath);

    if (interface->backend.sftp.prefix.type==CONTEXT_INTERFACE_BACKEND_SFTP_PREFIX_HOME) {
	struct sftp_subsystem_s *sftp=(struct sftp_subsystem_s *) interface->ptr;

	/* when subdir of remote home take that (when not what then???) */

	if (sftp->remote_home.len>0 && len > sftp->remote_home.len && strncmp(path, sftp->remote_home.ptr, sftp->remote_home.len)==0) {

	    written=snprintf(fullpath, fullpathlen, "%.*s%.*s%.*s", workspace->mountpoint.len, workspace->mountpoint.path, fpath.len, fpath.pathstart, len - sftp->remote_home.len, &path[sftp->remote_home.len]);

	} else {

	    goto searchcontext;

	}

    } else if (interface->backend.sftp.prefix.type==CONTEXT_INTERFACE_BACKEND_SFTP_PREFIX_ROOT) {

	written=snprintf(fullpath, fullpathlen, "%.*s%.*s%.*s", workspace->mountpoint.len, workspace->mountpoint.path, fpath.len, fpath.pathstart, len, path);

    } else if (interface->backend.sftp.prefix.type==CONTEXT_INTERFACE_BACKEND_SFTP_PREFIX_CUSTOM) {

	if (len > interface->backend.sftp.prefix.len && strncmp(path, interface->backend.sftp.prefix.path, interface->backend.sftp.prefix.len)==0) {

	    written=snprintf(fullpath, fullpathlen, "%.*s%.*s%.*s", workspace->mountpoint.len, workspace->mountpoint.path, fpath.len, fpath.pathstart, len - interface->backend.sftp.prefix.len, &path[interface->backend.sftp.prefix.len]);

	} else {

	    goto searchcontext;

	}

    }

    reply_VFS_data(f_request, fullpath, written);
    return;

    searchcontext:

    pthread_mutex_lock(&workspace->mutex);

    list=workspace->contexes.head;

    while (list) {

	search=get_container_context(list);
	if (search==context) goto next;

	if (search->type==SERVICE_CTX_TYPE_SERVICE) {

	     if (strcmp(search->name, "sftp")==0) {

		/* sftp service: is this the same host? */

		if (search->parent && search->parent == context->parent) {

		    if (search->interface.backend.sftp.prefix.type==CONTEXT_INTERFACE_BACKEND_SFTP_PREFIX_HOME) {
			struct sftp_subsystem_s *sftp=(struct sftp_subsystem_s *) search->interface.ptr;

			if (sftp->remote_home.len>0 && len > sftp->remote_home.len && strncmp(path, sftp->remote_home.ptr, sftp->remote_home.len)==0) {

			    written=snprintf(fullpath, fullpathlen, "%.*s%.*s%.*s", workspace->mountpoint.len, workspace->mountpoint.path, fpath.len, fpath.pathstart, len - sftp->remote_home.len, &path[sftp->remote_home.len]);
			    break;

			}

		    } else if (search->interface.backend.sftp.prefix.type==CONTEXT_INTERFACE_BACKEND_SFTP_PREFIX_ROOT) {

			written=snprintf(fullpath, fullpathlen, "%.*s%.*s%.*s", workspace->mountpoint.len, workspace->mountpoint.path, fpath.len, fpath.pathstart, len, path);

		    } else if (search->interface.backend.sftp.prefix.type==CONTEXT_INTERFACE_BACKEND_SFTP_PREFIX_CUSTOM) {

			if (len > search->interface.backend.sftp.prefix.len && strncmp(path, search->interface.backend.sftp.prefix.path, search->interface.backend.sftp.prefix.len)==0) {

			    written=snprintf(fullpath, fullpathlen, "%.*s%.*s%.*s", workspace->mountpoint.len, workspace->mountpoint.path, fpath.len, fpath.pathstart, len - search->interface.backend.sftp.prefix.len, &path[search->interface.backend.sftp.prefix.len]);

			}

		    }

		}

	    }

	}

	next:

	list=list->next;
	search=NULL;

    }

    pthread_mutex_unlock(&workspace->mutex);

    if (written>0) {

	reply_VFS_data(f_request, fullpath, written);
	return;

    }

    /* cannot resolve it futher ... leave it this way */

    written=snprintf(fullpath, fullpathlen, "%.*s%.*s%.*s", workspace->mountpoint.len, workspace->mountpoint.path, fpath.len, fpath.pathstart, len, path);
    reply_VFS_data(f_request, fullpath, written);

}


/* READLINK */

void _fs_sftp_readlink(struct service_context_s *context, struct fuse_request_s *f_request, struct inode_s *inode, struct pathinfo_s *pathinfo)
{
    struct context_interface_s *interface=&context->interface;
    struct sftp_request_s sftp_r;
    unsigned int error=EIO;
    unsigned int pathlen=(* interface->backend.sftp.get_complete_pathlen)(interface, pathinfo->len);
    char completepath[pathlen];

    if (f_request->flags & FUSEDATA_FLAG_INTERRUPTED) {

	reply_VFS_error(f_request, EINTR);
	return;

    }

    pathinfo->len += (* interface->backend.sftp.complete_path)(interface, completepath, pathinfo);

    memset(&sftp_r, 0, sizeof(struct sftp_request_s));

    logoutput("_fs_sftp_readlink_common: path %.*s", pathinfo->len, pathinfo->path);

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

	    if (wait_sftp_response_ctx(&context->interface, request, &timeout, &error)==1) {

		logoutput("_fs_sftp_readlink_common: reply %i", sftp_r.type);

		if (sftp_r.type==SSH_FXP_NAME) {
		    unsigned int len=get_uint32((unsigned char *) sftp_r.response.names.buff);
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
			sftp_r.call.realpath.path=fullpath;
			sftp_r.call.realpath.len=fullpathlen;

			logoutput("_fs_sftp_readlink_common: composed path %.*s", fullpathlen, fullpath);

			if (send_sftp_realpath_ctx(context->interface.ptr, &sftp_r)==0) {

			    request=create_sftp_request_ctx(context->interface.ptr, &sftp_r, &error);

			    if (request && wait_sftp_response_ctx(&context->interface, request, &timeout, &error)==1) {

				if (sftp_r.type==SSH_FXP_NAME) {
				    unsigned int realpathlen=get_uint32((unsigned char *) sftp_r.response.names.buff);
				    char realpath[realpathlen];

				    memcpy(realpath, sftp_r.response.names.buff + 4, realpathlen);

				    reply_VFS_symlink(context, f_request, realpath, realpathlen);
				    free(sftp_r.response.names.buff);
				    return;

				} else if (sftp_r.type==SSH_FXP_STATUS) {

				    error=sftp_r.response.status.linux_error;
				    goto out;

				}

			    }

			}

		    }

		    reply_VFS_symlink(context, f_request, path, len);

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
