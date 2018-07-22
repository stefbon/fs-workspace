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
#include "pathinfo.h"
#include "main.h"
#include "utils.h"

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

/*
    common functions to do a
    LOOKUP
    of a name on sftp map
*/

struct _sftp_lookup_s {
    struct service_context_s	*context;
    struct fuse_sftp_attr_s 	*fuse_attr;
    struct fuse_request_s  	*f_request;
    struct pathinfo_s 		*pathinfo;
    unsigned int 		error;
};

static void _sftp_lookup_cb_created(struct entry_s *entry, void *data)
{
    struct _sftp_lookup_s *_sftp_lookup=(struct _sftp_lookup_s *) data;
    struct service_context_s *context=_sftp_lookup->context;
    struct fuse_sftp_attr_s *fuse_attr=_sftp_lookup->fuse_attr;
    struct inode_s *inode=entry->inode;

    logoutput("_sftp_lookup_cb_created: name %s", entry->name.name);

    fill_inode_attr_sftp(context->interface.ptr, inode, fuse_attr);
    inode->nlookup=1;
    inode->nlink=1;

    add_inode_context(context, inode);

    get_current_time(&inode->stim);

    if (S_ISDIR(inode->mode)) {
	struct entry_s *parent=entry->parent;

	inode->nlink++;
	parent->inode->nlink++;
	memcpy(&parent->inode->ctim, &inode->stim, sizeof(struct timespec));

     } else {
	struct entry_s *parent=entry->parent;

	memcpy(&parent->inode->mtim, &inode->stim, sizeof(struct timespec));

    }

    _fs_common_cached_lookup(context, _sftp_lookup->f_request, inode);
    adjust_pathmax(context->workspace, _sftp_lookup->pathinfo->len);

}

static void _sftp_lookup_cb_found(struct entry_s *entry, void *data)
{
    struct _sftp_lookup_s *_sftp_lookup=(struct _sftp_lookup_s *) data;
    struct service_context_s *context=_sftp_lookup->context;
    struct fuse_sftp_attr_s *fuse_attr=_sftp_lookup->fuse_attr;
    struct inode_s *inode=entry->inode;

    logoutput("_sftp_lookup_cb_found: name %s", entry->name.name);

    fill_inode_attr_sftp(context->interface.ptr, inode, fuse_attr);
    inode->nlookup++;
    get_current_time(&inode->stim);
    _fs_common_cached_lookup(context, _sftp_lookup->f_request, inode);

    /* when just created (for example by readdir) adjust the pathcache */

    if (inode->nlookup==1) {

	adjust_pathmax(context->workspace, _sftp_lookup->pathinfo->len);

    }

}

static void _sftp_lookup_cb_error(struct entry_s *parent, struct name_s *xname, void *data, unsigned int error)
{
    struct _sftp_lookup_s *_sftp_lookup=(struct _sftp_lookup_s *) data;
    struct service_context_s *context=_sftp_lookup->context;
    if (error==0) error=EIO;
    reply_VFS_error(_sftp_lookup->f_request, error);
}

void _fs_sftp_lookup_new(struct service_context_s *context, struct fuse_request_s *f_request, struct inode_s *inode, struct name_s *xname, struct pathinfo_s *pathinfo)
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

    pathinfo->len += (* interface->backend.sftp.complete_path)(interface, path, pathinfo);

    logoutput("_fs_sftp_lookup_new: %i %s", pathinfo->len, pathinfo->path);

    init_sftp_request(&sftp_r);

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

	    if (wait_sftp_response_ctx(interface, request, &timeout, &error)==1) {

		if (sftp_r.type==SSH_FXP_ATTRS) {
		    struct fuse_sftp_attr_s fuse_attr;
		    struct entry_s *entry=NULL;
		    struct _sftp_lookup_s _sftp_lookup;

		    memset(&fuse_attr, 0, sizeof(struct fuse_sftp_attr_s));
		    read_attributes_ctx(context->interface.ptr, sftp_r.response.attr.buff, sftp_r.response.attr.size, &fuse_attr);

		    _sftp_lookup.context=context;
		    _sftp_lookup.fuse_attr=&fuse_attr;
		    _sftp_lookup.f_request=f_request;
		    _sftp_lookup.pathinfo=pathinfo;
		    _sftp_lookup.error=0;

		    entry=create_entry_extended(inode->alias, xname, _sftp_lookup_cb_created, _sftp_lookup_cb_found, _sftp_lookup_cb_error, (void *) &_sftp_lookup);

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

void _fs_sftp_lookup_existing(struct service_context_s *context, struct fuse_request_s *f_request, struct entry_s *entry, struct pathinfo_s *pathinfo)
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

    pathinfo->len += (* interface->backend.sftp.complete_path)(interface, path, pathinfo);

    logoutput("_fs_sftp_lookup_existing: %i %s", pathinfo->len, pathinfo->path);

    init_sftp_request(&sftp_r);

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

	    if (wait_sftp_response_ctx(interface, request, &timeout, &error)==1) {

		if (sftp_r.type==SSH_FXP_ATTRS) {
		    struct fuse_sftp_attr_s fuse_attr;
		    struct _sftp_lookup_s _sftp_lookup;

		    memset(&fuse_attr, 0, sizeof(struct fuse_sftp_attr_s));

		    read_attributes_ctx(context->interface.ptr, sftp_r.response.attr.buff, sftp_r.response.attr.size, &fuse_attr);

		    _sftp_lookup.context=context;
		    _sftp_lookup.fuse_attr=&fuse_attr;
		    _sftp_lookup.f_request=f_request;
		    _sftp_lookup.pathinfo=pathinfo;
		    _sftp_lookup.error=0;

		    _sftp_lookup_cb_found(entry, (void *) &_sftp_lookup);

		    free(sftp_r.response.attr.buff);
		    return;

		} else if (sftp_r.type==SSH_FXP_STATUS) {

		    error=sftp_r.response.status.linux_error;

		    if (error==ENOENT) {
			struct inode_s *inode=entry->inode;

			remove_entry(entry, &error);
			entry->inode=NULL;
			destroy_entry(entry);

			remove_inode(inode);
			free(inode);

		    }

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

void _fs_sftp_lookup_existing_disconnected(struct service_context_s *context, struct fuse_request_s *f_request, struct entry_s *entry, struct pathinfo_s *pathinfo)
{
    struct inode_s *inode=entry->inode;

    inode->nlookup++;
    get_current_time(&inode->stim);
    _fs_common_cached_lookup(context, f_request, inode);
}

void _fs_sftp_lookup_new_disconnected(struct service_context_s *context, struct fuse_request_s *f_request, struct inode_s *inode, struct name_s *xname, struct pathinfo_s *pathinfo)
{
    reply_VFS_error(f_request, ENOENT);
}
