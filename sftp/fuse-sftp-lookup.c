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
#include "fuse-utils.h"
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

static unsigned int _sftp_cb_cache_size(struct create_entry_s *ce)
{
    struct attr_response_s *attr=(struct attr_response_s *) ce->cache.link.link.ptr;
    return attr->size;
}

static void _sftp_lookup_cb_created(struct entry_s *entry, struct create_entry_s *ce)
{
    struct service_context_s *context=ce->context;
    struct attr_response_s *attr=(struct attr_response_s *) ce->cache.link.link.ptr;
    struct fuse_sftp_attr_s fuse_attr;
    struct fuse_request_s *r=(struct fuse_request_s *) ce->ptr;
    struct inode_s *inode=entry->inode;
    struct entry_s *parent=entry->parent;

    logoutput("_sftp_lookup_cb_created: name %s ino %li", entry->name.name, inode->st.st_ino);

    /* do something here with comparing the cached values in inode->cache (inode->cache_size bytes) with
	fuse_attr */

    memset(&fuse_attr, 0, sizeof(struct fuse_sftp_attr_s));
    read_attributes_ctx(context->interface.ptr, (char *) attr->buff, attr->size, &fuse_attr);

    fill_inode_attr_sftp(context->interface.ptr, &inode->st, &fuse_attr);
    inode->nlookup=1;
    inode->st.st_nlink=1;

    add_inode_context(context, inode);
    get_current_time(&inode->stim);

    if (S_ISDIR(inode->st.st_mode)) {

	inode->st.st_nlink++;
	parent->inode->st.st_nlink++;

    }

    memcpy(&parent->inode->st.st_ctim, &inode->stim, sizeof(struct timespec));
    memcpy(&parent->inode->st.st_mtim, &inode->stim, sizeof(struct timespec));

    _fs_common_cached_lookup(context, r, inode); /* reply FUSE/VFS */
    adjust_pathmax(context->workspace, ce->pathlen);
    memcpy(inode->cache, attr->buff, attr->size);
    inode->flags|=INODE_FLAG_CACHED;

}

static void _sftp_lookup_cb_found(struct entry_s *entry, struct create_entry_s *ce)
{
    struct service_context_s *context=ce->context;
    struct attr_response_s *attr=(struct attr_response_s *) ce->cache.link.link.ptr;
    struct fuse_request_s *r=(struct fuse_request_s *) ce->ptr;
    struct inode_s *inode=entry->inode;

    logoutput("_sftp_lookup_cb_found: name %s ino %li", entry->name.name, inode->st.st_ino);

    if (attr->size !=  inode->cache_size || memcmp(inode->cache, attr->buff, attr->size)!=0) {
	struct fuse_sftp_attr_s fuse_attr;
	struct timespec mtim;

	/* do this only when there is a difference, it's quite an intensive task */

	memset(&fuse_attr, 0, sizeof(struct fuse_sftp_attr_s));
	read_attributes_ctx(context->interface.ptr, (char *) attr->buff, attr->size, &fuse_attr);
	memcpy(&mtim, &inode->st.st_mtim, sizeof(struct timespec));
	fill_inode_attr_sftp(context->interface.ptr, &inode->st, &fuse_attr);

	/*
	    keep track the remote entry has a newer mtim
	    - file: the remote file is changed
	    - directory: an entry is added and/or removed
	*/

	if (inode->st.st_mtim.tv_sec>mtim.tv_sec || (inode->st.st_mtim.tv_sec==mtim.tv_sec && inode->st.st_mtim.tv_nsec>mtim.tv_nsec)) {

	    inode->alias->flags |= _ENTRY_FLAG_REMOTECHANGED;

	}

	memcpy(inode->cache, attr->buff, attr->size);
	inode->flags|=INODE_FLAG_CACHED;

    }

    inode->nlookup++;
    get_current_time(&inode->stim);
    _fs_common_cached_lookup(context, r, inode); /* reply FUSE/VFS*/
    if (inode->nlookup==1) adjust_pathmax(context->workspace, ce->pathlen);

}

static void _sftp_lookup_cb_error(struct entry_s *parent, struct name_s *xname, struct create_entry_s *ce, unsigned int error)
{
    struct fuse_request_s *r=(struct fuse_request_s *) ce->ptr;
    reply_VFS_error(r, error); /* reply FUSE/VFS */
}

void _fs_sftp_lookup_new(struct service_context_s *context, struct fuse_request_s *f_request, struct inode_s *inode, struct name_s *xname, struct pathinfo_s *pathinfo)
{
    struct context_interface_s *interface=&context->interface;
    struct sftp_request_s sftp_r;
    unsigned int error=EIO;
    unsigned int pathlen=(* interface->backend.sftp.get_complete_pathlen)(interface, pathinfo->len);
    char path[pathlen];

    logoutput("_fs_sftp_lookup_new");

    // if (get_sftp_version_ctx(context->interface.ptr)<=3) {

	/* versions up to 3 do not support full lookup */

	// reply_VFS_error(f_request, ENOENT);
	// return;

    //}

    if ((* f_request->is_interrupted)(f_request)) {

	reply_VFS_error(f_request, EINTR);
	return;

    }

    pathinfo->len += (* interface->backend.sftp.complete_path)(interface, path, pathinfo);

    logoutput("_fs_sftp_lookup_new: %i %s", pathinfo->len, pathinfo->path);

    init_sftp_request(&sftp_r);

    sftp_r.id=0;
    sftp_r.call.lstat.path=(unsigned char *) pathinfo->path;
    sftp_r.call.lstat.len=pathinfo->len;
    sftp_r.fuse_request=f_request;

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
		    struct create_entry_s ce;

		    init_create_entry(&ce, xname, inode->alias, NULL, NULL, context, NULL, (void *) f_request);
		    ce.cache.link.link.ptr=(void *) &sftp_r.response.attr;
		    ce.cache.link.type=INODE_LINK_TYPE_CACHE; /* not really required */
		    ce.pathlen=pathinfo->len;
		    ce.cb_created=_sftp_lookup_cb_created;
		    ce.cb_found=_sftp_lookup_cb_found;
		    ce.cb_error=_sftp_lookup_cb_error;
		    ce.cb_cache_size=_sftp_cb_cache_size;

		    entry=create_entry_extended(&ce);

		    logoutput("_fs_sftp_lookup_new: %i %s", pathinfo->len, pathinfo->path);

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
    struct service_context_s *rootcontext=get_root_context(context);
    struct sftp_request_s sftp_r;
    unsigned int error=EIO;
    unsigned int pathlen=(* interface->backend.sftp.get_complete_pathlen)(interface, pathinfo->len);
    char path[pathlen];

    if ((* f_request->is_interrupted)(f_request)) {

	reply_VFS_error(f_request, EINTR);
	return;

    }

    pathinfo->len += (* interface->backend.sftp.complete_path)(interface, path, pathinfo);

    logoutput("_fs_sftp_lookup_existing: %i %s ino %li", pathinfo->len, pathinfo->path, entry->inode->st.st_ino);

    init_sftp_request(&sftp_r);

    sftp_r.id=0;
    sftp_r.call.lstat.path=(unsigned char *) pathinfo->path;
    sftp_r.call.lstat.len=pathinfo->len;
    sftp_r.fuse_request=f_request;

    /* send lstat cause not interested in target when dealing with symlink */

    if (send_sftp_lstat_ctx(context->interface.ptr, &sftp_r)==0) {
	void *request=NULL;

	request=create_sftp_request_ctx(context->interface.ptr, &sftp_r, &error);

	if (request) {
	    struct timespec timeout;

	    get_sftp_request_timeout(&timeout);
	    error=0;

	    // logoutput("_fs_sftp_lookup_existing: id %i", sftp_r.id);

	    if (wait_sftp_response_ctx(interface, request, &timeout, &error)==1) {

		if (sftp_r.type==SSH_FXP_ATTRS) {
		    struct attr_response_s *attr=&sftp_r.response.attr;
		    struct inode_s *inode=entry->inode;

		    /* do this different: let this to the cb's */

		    if (attr->size != inode->cache_size || memcmp(inode->cache, attr->buff, attr->size)!=0) {
			struct fuse_sftp_attr_s fuse_attr;

			logoutput("_fs_sftp_lookup_existing: sftp attr size %i : cache %i", attr->size, inode->cache_size);

			memset(&fuse_attr, 0, sizeof(struct fuse_sftp_attr_s));
			read_attributes_ctx(context->interface.ptr, (char *)sftp_r.response.attr.buff, sftp_r.response.attr.size, &fuse_attr);

			if (attr->size != inode->cache_size) {

			    inode=realloc_inode(inode, attr->size); /* assume always good */
			    if (inode==NULL) {

				error=ENOMEM;
				goto out;

			    }

			}

			fill_inode_attr_sftp(context->interface.ptr, &inode->st, &fuse_attr);
			memcpy(inode->cache, attr->buff, attr->size);
			inode->flags|=INODE_FLAG_CACHED;

		    }

		    get_current_time(&inode->stim);

		    if (inode->nlookup==0) {

			inode->nlookup=1;

			adjust_pathmax(context->workspace, pathinfo->len);
			add_inode_context(context, inode);

		    } else {

			inode->nlookup++;

		    }

		    _fs_common_cached_lookup(context, f_request, inode); /* reply FUSE/VFS*/

		    // logoutput("_fs_sftp_lookup_existing: %i %s", pathinfo->len, pathinfo->path);
		    free(sftp_r.response.attr.buff);
		    return;

		} else if (sftp_r.type==SSH_FXP_STATUS) {

		    error=sftp_r.response.status.linux_error;
		    if (error==ENOENT) {
			struct inode_s *inode=entry->inode;

			queue_inode_2forget(inode->st.st_ino, context->unique, 0, 0);

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
