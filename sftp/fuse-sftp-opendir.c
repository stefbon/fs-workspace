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
#include "pathinfo.h"
#include "utils.h"

#include "fuse-fs.h"
#include "workspaces.h"
#include "workspace-context.h"
#include "fuse-utils.h"
#include "fuse-interface.h"

#include "path-caching.h"
#include "fuse-fs-common.h"

#include "common-protocol.h"
#include "common.h"
#include "attr-common.h"
#include "send-common.h"

#include "fuse-sftp-common.h"
#include "fuse-fs-special.h"

extern const char *dotdotname;
extern const char *dotname;

static const char *rootpath="/.";

extern void *create_sftp_request_ctx(void *ptr, struct sftp_request_s *sftp_r, unsigned int *error);
extern unsigned char wait_sftp_response_ctx(struct context_interface_s *i, void *r, struct timespec *timeout, unsigned int *error);
extern void get_sftp_request_timeout(struct timespec *timeout);

static unsigned int _cb_cache_size(struct create_entry_s *ce)
{
    /* unfortunatly with a name response (=readdir response) there is no
	other way to determine the size than to process the ATTR and than comnpare the new position
	in the buffer with the old one .... */

    struct name_response_s *response=(struct name_response_s *) ce->cache.link.link.ptr;
    struct fuse_sftp_attr_s attr;
    unsigned int size=0;

    memset(&attr, 0, sizeof(struct fuse_sftp_attr_s));
    size=read_attr_response_ctx(ce->context->interface.ptr, response, &attr);
    fill_inode_attr_sftp(ce->context->interface.ptr, &ce->cache.st, &attr);
    logoutput("_cb_cache_size: attr type %i permissions %i", attr.type, attr.permissions);
    return size;
}


static void _cb_created(struct entry_s *entry, struct create_entry_s *ce)
{
    struct service_context_s *context=ce->context;
    struct name_response_s *response=(struct name_response_s *) ce->cache.link.link.ptr;
    struct entry_s *parent=entry->parent;
    struct inode_s *inode=entry->inode;
    struct fuse_opendir_s *fo=ce->tree.opendir;
    struct directory_s *directory=(* ce->get_directory)(ce);

    fill_inode_stat(inode, &ce->cache.st); /* from ce cache */
    inode->st.st_mode=ce->cache.st.st_mode;
    inode->st.st_size=ce->cache.st.st_size;
    inode->st.st_nlink=1;
    inode->nlookup=1;
    fo->count_created++; /* count the numbers added */

    memcpy(&inode->stim, &directory->synctime, sizeof(struct timespec));
    add_inode_context(context, inode);

    if (S_ISDIR(inode->st.st_mode)) {

	inode->st.st_nlink=2;
	parent->inode->st.st_nlink++;
	set_directory_dump(inode, get_dummy_directory());

    }

    memcpy(&directory->inode->st.st_ctim, &directory->synctime, sizeof(struct timespec));
    memcpy(&directory->inode->st.st_mtim, &directory->synctime, sizeof(struct timespec));
    memcpy(inode->cache, response->pos - inode->cache_size, inode->cache_size);
    inode->flags |= INODE_FLAG_CACHED;

}

static void _cb_found(struct entry_s *entry, struct create_entry_s *ce)
{
    struct service_context_s *context=ce->context;
    struct name_response_s *response=(struct name_response_s *) ce->cache.link.link.ptr;
    struct inode_s *inode=entry->inode;
    struct fuse_opendir_s *fo=ce->tree.opendir;
    struct directory_s *directory=(* ce->get_directory)(ce);

    logoutput("_cb_found");

    if (memcmp(inode->cache, response->pos - inode->cache_size, inode->cache_size)!=0) {

	fill_inode_stat(inode, &ce->cache.st);
	inode->st.st_mode=ce->cache.st.st_mode;
	inode->st.st_size=ce->cache.st.st_size;
	memcpy(inode->cache, response->pos - inode->cache_size, inode->cache_size);
	inode->flags |= INODE_FLAG_CACHED;

    }

    fo->count_found++;
    inode->nlookup++;
    memcpy(&inode->stim, &directory->synctime, sizeof(struct timespec));


}

static void _cb_error(struct entry_s *parent, struct name_s *xname, struct create_entry_s *ce, unsigned int error)
{
    logoutput_warning("_cb_error: error %i:%s creating %s", error, strerror(error), xname->name);
    ce->error=error;
}

/* OPEN a directory */

/*
    TODO:
    1.
    - 	when using the "normal" readdir (not readdirplus) it's possible to first send a getattr, and test there is a change in mtim
	if there is continue the normal way by sending an sftp open message
	if there isn't a change, just list the already cached entries ib this client
    2.
    -	use readdirplus
*/

void _fs_sftp_opendir(struct fuse_opendir_s *opendir, struct fuse_request_s *f_request, struct pathinfo_s *pathinfo, unsigned int flags)
{
    struct service_context_s *context=(struct service_context_s *) opendir->context;
    struct context_interface_s *interface=&context->interface;
    struct sftp_request_s sftp_r;
    unsigned int error=EIO;
    struct directory_s *directory=get_directory(opendir->inode);
    unsigned int pathlen=(* interface->backend.sftp.get_complete_pathlen)(interface, pathinfo->len);
    char path[pathlen];

    logoutput("_fs_sftp_opendir_common: send opendir %i %s", pathinfo->len, pathinfo->path);

    if ((* f_request->is_interrupted)(f_request)) {

	reply_VFS_error(f_request, EINTR);
	opendir->mode |= _FUSE_READDIR_MODE_INCOMPLETE;
	return;

    }

    /* test a full opendir/readdir is required: test entries are deleted and/or created */

    if (directory && directory->synctime.tv_sec>0) {
	struct entry_s *entry=opendir->inode->alias;

	if ((entry->flags & _ENTRY_FLAG_REMOTECHANGED)==0) {

	    /* no entries added and deleted: no need to read all entries again: use cache */

	    opendir->readdir=_fs_common_virtual_readdir;
	    opendir->readdirplus=_fs_common_virtual_readdirplus;
	    opendir->fsyncdir=_fs_common_virtual_fsyncdir;
	    opendir->releasedir=_fs_common_virtual_releasedir;
	    _fs_common_virtual_opendir(opendir, f_request, flags);

	    return;

	}

    }

    pathinfo->len += (* interface->backend.sftp.complete_path)(interface, path, pathinfo);
    init_sftp_request(&sftp_r);

    sftp_r.id=0;
    sftp_r.call.opendir.path=(unsigned char *) pathinfo->path;
    sftp_r.call.opendir.len=pathinfo->len;
    sftp_r.fuse_request=f_request;

    if (send_sftp_opendir_ctx(context->interface.ptr, &sftp_r)==0) {
	void *request=NULL;

	request=create_sftp_request_ctx(context->interface.ptr, &sftp_r, &error);

	if (request) {
	    struct timespec timeout;

	    get_sftp_request_timeout(&timeout);

	    if (wait_sftp_response_ctx(interface, request, &timeout, &error)==1) {

		if (sftp_r.type==SSH_FXP_HANDLE) {
		    struct fuse_open_out open_out;

		    /* take over handle */
		    opendir->handle.name.name=(char *)sftp_r.response.handle.name;
		    opendir->handle.name.len=sftp_r.response.handle.len;
		    sftp_r.response.handle.name=NULL;
		    sftp_r.response.handle.len=0;

		    open_out.fh=(uint64_t) opendir;
		    open_out.open_flags=0;
		    open_out.padding=0;

		    reply_VFS_data(f_request, (char *) &open_out, sizeof(open_out));
		    get_current_time(&directory->synctime);
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

    if (error==EOPNOTSUPP) {

	logoutput("_fs_sftp_opendir_common: not supported, switching to virtual");

	opendir->readdir=_fs_common_virtual_readdir;
	opendir->fsyncdir=_fs_common_virtual_fsyncdir;
	opendir->releasedir=_fs_common_virtual_releasedir;
	_fs_common_virtual_opendir(opendir, f_request, flags);

	return;

    }

    opendir->error=error;
    if (error==EINTR || error==ETIMEDOUT) opendir->mode |= _FUSE_READDIR_MODE_INCOMPLETE;
    reply_VFS_error(f_request, error);

}

/* send readdir to server to get list of names */

static int _sftp_get_readdir_names(struct fuse_opendir_s *opendir, struct fuse_request_s *f_request, unsigned int *error)
{
    struct service_context_s *context=opendir->context;
    struct sftp_request_s sftp_r;
    int result=-1;

    init_sftp_request(&sftp_r);

    logoutput("_sftp_get_readdir_names");

    sftp_r.id=0;
    sftp_r.call.readdir.handle=(unsigned char *) opendir->handle.name.name;
    sftp_r.call.readdir.len=opendir->handle.name.len;
    sftp_r.fuse_request=f_request;

    if (opendir->data) {
	struct name_response_s *response=(struct name_response_s *) opendir->data;

	if (response->buff) {

	    free(response->buff);
	    response->buff=NULL;

	}

	free(response);
	opendir->data=NULL;

    }

    if (send_sftp_readdir_ctx(context->interface.ptr, &sftp_r)==0) {
	void *request=NULL;

	request=create_sftp_request_ctx(context->interface.ptr, &sftp_r, error);

	if (request) {
	    struct timespec timeout;

	    get_sftp_request_timeout(&timeout);

	    if (wait_sftp_response_ctx(&context->interface, request, &timeout, error)==1) {

		if (sftp_r.type==SSH_FXP_NAME) {
		    struct name_response_s *response=NULL;

		    logoutput("_sftp_get_readdir_names: reply name");

		    /* take the response from server to read the entries from */

		    response=malloc(sizeof(struct name_response_s));

		    if (response) {

			/* copy the pointers to the names, not the names (and attr) self */
			memcpy(response, &sftp_r.response.names, sizeof(struct name_response_s));
			opendir->data=(void *) response;
			result=(response->buff && response->size>0) ? response->count : 0;

		    } else {

			*error=ENOMEM;
			free(sftp_r.response.names.buff);
			sftp_r.response.names.buff=NULL;
			result=-1;

		    }

		} else if (sftp_r.type==SSH_FXP_STATUS) {

		    logoutput("_sftp_get_readdir_names: reply status");

		    if (sftp_r.response.status.linux_error==ENODATA) {

			*error=0;
			result=0;

		    } else {

			*error=sftp_r.response.status.linux_error;
			result=-1;

		    }

		} else {

		    *error=EPROTO;
		    result=-1;

		}

	    }

	}

    }

    logoutput("_sftp_get_readdir_names: result %i", result);
    return result;

}

/* TODO: this readdir uses one big exclusive lock around the getting the names of the server and the processing of this data and creating of entries
    possibly it's better to use the locking only when the entry is added to the directory */

static void _fs_sftp_readdir_common(struct fuse_opendir_s *opendir, struct fuse_request_s *f_request, size_t size, off_t offset, unsigned char mode)
{
    struct service_context_s *context=opendir->context;
    struct directory_s *directory=NULL;
    struct stat st;
    size_t pos=0, dirent_size=0;
    struct name_s xname={NULL, 0, 0};
    struct inode_s *inode=NULL;
    struct entry_s *entry=NULL;
    char buff[size];
    unsigned int error=EIO;
    struct simple_lock_s wlock;

    if (opendir->mode & _FUSE_READDIR_MODE_FINISH) {
	char dummy='\0';

	reply_VFS_data(f_request, &dummy, 0);
	return;

    }

    if ((* f_request->is_interrupted)(f_request)) {

	reply_VFS_error(f_request, EINTR);
	opendir->mode |= _FUSE_READDIR_MODE_INCOMPLETE;
	return;

    }

    directory=get_directory(opendir->inode);

    if (directory==NULL) {

	reply_VFS_error(f_request, ENOMEM);
	return;

    }

    if (wlock_directory(directory, &wlock)==-1) {

	reply_VFS_error(f_request, EAGAIN);
	return;

    }

    memset(&st, 0, sizeof(struct stat));

    while (pos<size) {

	if (offset==0) {

	    inode=opendir->inode;

    	    /* the . entry */

    	    st.st_ino = inode->st.st_ino;
	    st.st_mode = S_IFDIR;
	    xname.name = (char *) dotname;
	    xname.len=1;

    	} else if (offset==1) {
    	    struct entry_s *parent=NULL;

	    inode=opendir->inode;

	    /* the .. entry */

	    parent=inode->alias;
	    if (parent->parent) inode=parent->parent->inode;

    	    st.st_ino = inode->st.st_ino;
	    st.st_mode = S_IFDIR;
	    xname.name = (char *) dotdotname;
	    xname.len=2;

    	} else {

	    if (! opendir->entry) {
		struct name_response_s *response=(struct name_response_s *) opendir->data;

		sftp_readdir:

		if (response==NULL || response->count==0) {
		    int result=0;

		    result=_sftp_get_readdir_names(opendir, f_request, &error);

		    if (result==-1) {

			/* some error */

			reply_VFS_error(f_request, error);
			if (error==EINTR || error==ETIMEDOUT) opendir->mode |= _FUSE_READDIR_MODE_INCOMPLETE;
			goto unlock;

		    } else if (result==0) {

			/* no more names from server */

			opendir->mode |= _FUSE_READDIR_MODE_FINISH;
			break;

		    }

		    response=(struct name_response_s *) opendir->data;

		}

		readentry:

		if (response->count>0) {
		    unsigned int len=0;
		    char *tmp=NULL;

		    /* extract name and attributes from names
			only get the name, do the attr later */

		    read_name_response_ctx(context->interface.ptr, response, &tmp, &len);

		    if ((len==1 && strncmp(tmp, ".", 1)==0) || (len==2 && strncmp(tmp, "..", 2)==0)) {
			struct fuse_sftp_attr_s attr;

			/* skip the . and .. entries */

			read_attr_response_ctx(context->interface.ptr, response, &attr);
			goto sftp_readdir;

		    } else {
			struct create_entry_s ce;

			xname.name=tmp;
			xname.len=len;
			calculate_nameindex(&xname);

			init_create_entry(&ce, &xname, NULL, NULL, opendir, context, NULL, NULL);

			ce.cache.link.link.ptr=(void *) response;
			ce.cache.link.type=INODE_LINK_TYPE_CACHE;

			ce.cb_cache_size=_cb_cache_size;
			ce.cb_created=_cb_created;
			ce.cb_found=_cb_found;
			ce.cb_error=_cb_error;

			entry=create_entry_extended_batch(&ce);

			if (! entry) {

			    if (error==0) error=ENOMEM;
			    reply_VFS_error(f_request, error);
			    goto unlock;

			}

			xname.name=entry->name.name;
			xname.len=entry->name.len;
			xname.index=0;

		    }

		    inode=entry->inode;

		    st.st_ino=inode->st.st_ino;
		    st.st_mode=inode->st.st_mode;

		} else {

		    /* all names read: check the "eof" boolean */

		    if (response->eof==1) {

			opendir->mode |= _FUSE_READDIR_MODE_FINISH;
			break;

		    }

		    goto sftp_readdir;

		}

	    } else {

		logoutput("_fs_sftp_readdir_common: entry");

		entry=opendir->entry;
		xname.name=entry->name.name;
		xname.len=entry->name.len;

		inode=entry->inode;
		st.st_ino=inode->st.st_ino;
		st.st_mode=inode->st.st_mode;

	    }

	}

	dirent:

	error=0;
	logoutput("_fs_sftp_readdir_common: add %li %.*s %i", st.st_ino, xname.len, xname.name, st.st_mode);

	dirent_size=add_direntry_buffer(get_root_ptr_context(context), buff + pos, size - pos, offset + 1, &xname, &st, &error);

	if (error==ENOBUFS) {

	    opendir->entry=entry; /* keep it for the next batch */
	    break;

	}

	/* increase counter and clear the various fields */

	opendir->entry=NULL; /* forget current entry to force readdir */
	offset++;
	pos+=dirent_size;

    }

    reply_VFS_data(f_request, buff, pos);

    unlock:

    unlock_directory(directory, &wlock);

}

void _fs_sftp_readdir(struct fuse_opendir_s *opendir, struct fuse_request_s *r, size_t size, off_t offset)
{
    return _fs_sftp_readdir_common(opendir, r, size, offset, 0);
}

void _fs_sftp_readdirplus(struct fuse_opendir_s *opendir, struct fuse_request_s *r, size_t size, off_t offset)
{
    struct sftp_subsystem_s *sftp=(struct sftp_subsystem_s *) opendir->context->interface.ptr;

    if ((sftp->flags & SFTP_SUBSYSTEM_FLAG_READDIRPLUS)==0) {

	reply_VFS_error(r, EOPNOTSUPP);
	return;

    }

    return _fs_sftp_readdir_common(opendir, r, size, offset, 1);
}

void _fs_sftp_fsyncdir(struct fuse_opendir_s *opendir, struct fuse_request_s *r, unsigned char datasync)
{
    reply_VFS_error(r, 0);
}

void _fs_sftp_releasedir(struct fuse_opendir_s *opendir, struct fuse_request_s *f_request)
{
    struct service_context_s *context=opendir->context;
    struct sftp_request_s sftp_r;
    unsigned int error=EIO;
    struct entry_s *entry=opendir->inode->alias;
    struct simple_lock_s wlock;
    struct directory_s *directory=NULL;

    logoutput("_fs_sftp_releasedir");

    if ((* f_request->is_interrupted)(f_request)) {

	reply_VFS_error(f_request, EINTR);
	return;

    }

    init_sftp_request(&sftp_r);

    sftp_r.id=0;
    sftp_r.call.close.handle=(unsigned char *) opendir->handle.name.name;
    sftp_r.call.close.len=opendir->handle.name.len;
    sftp_r.fuse_request=f_request;

    if (send_sftp_close_ctx(context->interface.ptr, &sftp_r)==0) {
	void *request=NULL;

	request=create_sftp_request_ctx(context->interface.ptr, &sftp_r, &error);

	if (request) {
	    struct timespec timeout;

	    get_sftp_request_timeout(&timeout);

	    if (wait_sftp_response_ctx(&context->interface, request, &timeout, &error)==1) {

		if (sftp_r.type==SSH_FXP_STATUS) {

		    /* send ok reply to VFS no matter what the ssh server reports */

		    error=0;

		    if (sftp_r.response.status.code>0) {

			logoutput_notice("_fs_sftp_releasedir: got reply %i:%s when closing dir", sftp_r.response.status.linux_error, strerror(sftp_r.response.status.linux_error));

		    }

		} else {

		    error=EPROTO;

		}

	    }

	}

    }

    out:

    reply_VFS_error(f_request, error);

    /* free opendir handle */

    free(opendir->handle.name.name);
    opendir->handle.name.name=NULL;
    opendir->handle.name.len=0;

    /* free cached data */

    if (opendir->data) {
	struct name_response_s *response=(struct name_response_s *) opendir->data;

	if (response->buff) {

	    free(response->buff);
	    response->buff=NULL;

	}

	free(response);
	opendir->data=NULL;

    }

    if ((entry->flags & _ENTRY_FLAG_REMOTECHANGED) && (opendir->mode & _FUSE_READDIR_MODE_INCOMPLETE)==0) entry->flags-=_ENTRY_FLAG_REMOTECHANGED;

    /* remove local entries not found on server */

    directory=get_directory(opendir->inode);

    if (wlock_directory(directory, &wlock)==0) {

	/*
		only check when there are deleted entries:
		- the entries found on server (opendir->created plus the already found opendir->count)
		is not equal to the number of entries in this local directory
	*/

	if (opendir->count_created + opendir->count_found != directory->count) {
	    struct inode_s *inode=NULL;
	    struct entry_s *entry=NULL;
	    struct entry_s *next=NULL;

	    entry=directory->first;

	    while (entry) {

		next=entry->name_next;
		inode=entry->inode;
		if (check_entry_special(inode)==0) goto next;

		if (inode->stim.tv_sec < directory->synctime.tv_sec || (inode->stim.tv_sec == directory->synctime.tv_sec && inode->stim.tv_nsec < directory->synctime.tv_nsec)) {

		    logoutput("_fs_sftp_releasedir: remove inode %li", inode->st.st_ino);
		    queue_inode_2forget(inode->st.st_ino, context->unique, FORGET_INODE_FLAG_DELETED, 0);

		}

		next:
		entry=next;

	    }

	}

	unlock_directory(directory, &wlock);

    }

}

void _fs_sftp_opendir_disconnected(struct fuse_opendir_s *opendir, struct fuse_request_s *r, struct pathinfo_s *pathinfo, unsigned int flags)
{
    _fs_common_virtual_opendir(opendir, r, flags);
}

void _fs_sftp_readdir_disconnected(struct fuse_opendir_s *opendir, struct fuse_request_s *r, size_t size, off_t offset)
{
    _fs_common_virtual_readdir(opendir, r, size, offset);
}

void _fs_sftp_readdirplus_disconnected(struct fuse_opendir_s *opendir, struct fuse_request_s *r, size_t size, off_t offset)
{
    _fs_common_virtual_readdirplus(opendir, r, size, offset);
}

void _fs_sftp_fsyncdir_disconnected(struct fuse_opendir_s *opendir, struct fuse_request_s *r, unsigned char datasync)
{
    reply_VFS_error(r, 0);
}

void _fs_sftp_releasedir_disconnected(struct fuse_opendir_s *opendir, struct fuse_request_s *r)
{
    _fs_common_virtual_releasedir(opendir, r);
}

static int _fs_sftp_opendir_root(struct fuse_opendir_s *opendir, struct context_interface_s *interface)
{
    struct pathinfo_s pathinfo={rootpath, strlen(rootpath), 0, 0};
    struct sftp_request_s sftp_r;
    unsigned int error=EIO;
    unsigned int pathlen=(* interface->backend.sftp.get_complete_pathlen)(interface, pathinfo.len);
    char path[pathlen];
    int result=-1;

    logoutput("_fs_sftp_opendir_root: send opendir %i %s", pathinfo.len, pathinfo.path);

    pathinfo.len += (* interface->backend.sftp.complete_path)(interface, path, &pathinfo);
    init_sftp_request(&sftp_r);

    sftp_r.id=0;
    sftp_r.call.opendir.path=(unsigned char *) pathinfo.path;
    sftp_r.call.opendir.len=pathinfo.len;
    sftp_r.fuse_request=NULL;

    if (send_sftp_opendir_ctx(interface->ptr, &sftp_r)==0) {
	void *request=NULL;

	request=create_sftp_request_ctx(interface->ptr, &sftp_r, &error);

	if (request) {
	    struct timespec timeout;

	    get_sftp_request_timeout(&timeout);

	    if (wait_sftp_response_ctx(interface, request, &timeout, &error)==1) {

		if (sftp_r.type==SSH_FXP_HANDLE) {
		    struct fuse_open_out open_out;

		    /* take over handle */
		    opendir->handle.name.name=(char *)sftp_r.response.handle.name;
		    opendir->handle.name.len=sftp_r.response.handle.len;
		    sftp_r.response.handle.name=NULL;
		    sftp_r.response.handle.len=0;

		    open_out.fh=(uint64_t) opendir;
		    open_out.open_flags=0;
		    open_out.padding=0;

		    result=0;

		} else if (sftp_r.type==SSH_FXP_STATUS) {

		    error=sftp_r.response.status.linux_error;

		} else {

		    error=EPROTO;

		}

	    }

	}

    }

    out:

    opendir->error=error;
    return result;
}

static int _sftp_get_readdir_names_root(struct fuse_opendir_s *opendir, struct context_interface_s *interface, unsigned int *error)
{
    struct sftp_request_s sftp_r;
    int result=-1;

    init_sftp_request(&sftp_r);

    logoutput("_sftp_get_readdir_names_root");

    sftp_r.id=0;
    sftp_r.call.readdir.handle=(unsigned char *) opendir->handle.name.name;
    sftp_r.call.readdir.len=opendir->handle.name.len;
    sftp_r.fuse_request=NULL;

    if (opendir->data) {
	struct name_response_s *response=(struct name_response_s *) opendir->data;

	if (response->buff) {

	    free(response->buff);
	    response->buff=NULL;

	}

	free(response);
	opendir->data=NULL;

    }

    if (send_sftp_readdir_ctx(interface->ptr, &sftp_r)==0) {
	void *request=NULL;

	request=create_sftp_request_ctx(interface->ptr, &sftp_r, error);

	if (request) {
	    struct timespec timeout;

	    get_sftp_request_timeout(&timeout);

	    if (wait_sftp_response_ctx(interface, request, &timeout, error)==1) {

		if (sftp_r.type==SSH_FXP_NAME) {
		    struct name_response_s *response=NULL;

		    logoutput("_sftp_get_readdir_names: reply name");

		    /* take the response from server to read the entries from */

		    response=malloc(sizeof(struct name_response_s));

		    if (response) {

			/* copy the pointers to the names, not the names (and attr) self */
			memcpy(response, &sftp_r.response.names, sizeof(struct name_response_s));
			opendir->data=(void *) response;
			result=(response->buff && response->size>0) ? response->count : 0;

		    } else {

			*error=ENOMEM;
			free(sftp_r.response.names.buff);
			sftp_r.response.names.buff=NULL;
			result=-1;

		    }

		} else if (sftp_r.type==SSH_FXP_STATUS) {

		    logoutput("_sftp_get_readdir_names: reply status");

		    if (sftp_r.response.status.linux_error==ENODATA) {

			*error=0;
			result=0;

		    } else {

			*error=sftp_r.response.status.linux_error;
			result=-1;

		    }

		} else {

		    *error=EPROTO;
		    result=-1;

		}

	    }

	}

    }

    logoutput("_sftp_get_readdir_names: result %i", result);
    return result;

}

static unsigned int _fs_sftp_readdir_root(struct fuse_opendir_s *opendir, struct context_interface_s *interface, size_t size, off_t offset, struct fuse_sftp_attr_s *attr, unsigned int *tmp)
{
    unsigned int valid=0;
    size_t pos=0;
    struct name_s xname={NULL, 0, 0};
    char buff[size];
    unsigned int error=EIO;

    while (pos<size) {
	struct name_response_s *response=(struct name_response_s *) opendir->data;

	sftp_readdir:

	if (response==NULL || response->count==0) {
	    int result=0;

	    result=_sftp_get_readdir_names_root(opendir, interface, &error);

	    if (result==-1) {

		/* some error */

		opendir->mode |= _FUSE_READDIR_MODE_FINISH;
		break;

	    } else if (result==0) {

		/* no more names from server */

		opendir->mode |= _FUSE_READDIR_MODE_FINISH;
		break;

	    }

	    response=(struct name_response_s *) opendir->data;

	}

	readentry:

	if (response->count>0) {
	    unsigned int len=0;
	    char *name=NULL;
	    char *pos2=response->pos;

	    read_name_response_ctx(interface->ptr, response, &name, &len);

	    logoutput("_fs_sftp_readdir_root: count %i name %.*s", response->count, len, name);

	    if (tmp && *tmp==0) {
		struct ssh_string_s test;

		if (read_ssh_string(response->pos, (unsigned int)(response->size + pos2 - response->pos), &test)>0) {
		    char *sep=memrchr(test.ptr, ' ', test.len);

		    if (sep) *tmp=(unsigned int)(sep - test.ptr);

		    /* test the length of the longname */

		    logoutput("_fs_sftp_readdir_common: found length readdir longname %i", *tmp);

		}

	    }

	    read_attr_response_ctx(interface->ptr, response, attr);
	    valid=attr->received;

	}

    }

    return valid;

}

void _fs_sftp_releasedir_root(struct fuse_opendir_s *opendir, struct context_interface_s *interface)
{
    struct sftp_request_s sftp_r;
    unsigned int error=EIO;

    logoutput("_fs_sftp_releasedir_root");

    init_sftp_request(&sftp_r);

    sftp_r.id=0;
    sftp_r.call.close.handle=(unsigned char *) opendir->handle.name.name;
    sftp_r.call.close.len=opendir->handle.name.len;
    sftp_r.fuse_request=NULL;

    if (send_sftp_close_ctx(interface->ptr, &sftp_r)==0) {
	void *request=NULL;

	request=create_sftp_request_ctx(interface->ptr, &sftp_r, &error);

	if (request) {
	    struct timespec timeout;

	    get_sftp_request_timeout(&timeout);

	    if (wait_sftp_response_ctx(interface, request, &timeout, &error)==1) {

		if (sftp_r.type==SSH_FXP_STATUS) {

		    /* send ok reply to VFS no matter what the ssh server reports */

		    error=0;

		    if (sftp_r.response.status.code>0) {

			logoutput_notice("_fs_sftp_releasedir_root: got reply %i:%s when closing dir", sftp_r.response.status.linux_error, strerror(sftp_r.response.status.linux_error));

		    }

		} else {

		    error=EPROTO;

		}

	    }

	}

    }

    out:

    /* free opendir handle */

    free(opendir->handle.name.name);
    opendir->handle.name.name=NULL;
    opendir->handle.name.len=0;

    /* free cached data */

    if (opendir->data) {
	struct name_response_s *response=(struct name_response_s *) opendir->data;

	if (response->buff) {

	    free(response->buff);
	    response->buff=NULL;

	}

	free(response);
	opendir->data=NULL;

    }

}

int test_valid_sftp_readdir(struct context_interface_s *interface, void *ptr, unsigned int *len)
{
    struct fuse_opendir_s opendir;
    int result=0;
    struct fuse_sftp_attr_s *attr=(struct fuse_sftp_attr_s *) ptr;

    logoutput("test_valid_sftp_readdir");

    memset(&opendir, 0, sizeof(struct fuse_opendir_s));

    if (_fs_sftp_opendir_root(&opendir, interface)==0) {
	unsigned int valid=0;

	readdir:

	valid=_fs_sftp_readdir_root(&opendir, interface, 1024, 0, attr, len);
	if ((opendir.mode & _FUSE_READDIR_MODE_FINISH)==0) goto readdir;

	_fs_sftp_releasedir_root(&opendir, interface);
	result=0;

    }

    return result;
}

