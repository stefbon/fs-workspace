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
#include "entry-utils.h"
#include "fuse-interface.h"

#include "path-caching.h"
#include "fuse-fs-common.h"

#include "sftp-common-protocol.h"
#include "sftp-attr-common.h"
#include "sftp-send-common.h"

#include "fuse-sftp-common.h"

extern const char *dotdotname;
extern const char *dotname;

extern void *create_sftp_request_ctx(void *ptr, struct sftp_request_s *sftp_r, unsigned int *error);
extern unsigned char wait_sftp_response_ctx(void *ptr, void *r, struct timespec *timeout, unsigned int *error);
extern void get_sftp_request_timeout(struct timespec *timeout);
extern unsigned int get_uint32(unsigned char *buf);

/*
    common functions to create an entry
    typically used by readdir
*/

struct _fs_sftp_readdir_struct {
    struct workspace_mount_s			*workspace;
    struct fuse_sftp_attr_s 			*fuse_attr;
    struct directory_s 				*directory;
    struct fuse_opendir_s 			*opendir;
    unsigned int 				*error;
};

static void _cb_created(struct entry_s *entry, void *data)
{
    struct _fs_sftp_readdir_struct *_readdir_sftp=(struct _fs_sftp_readdir_struct *) data;
    struct service_context_s *context=_readdir_sftp->opendir->context;
    struct fuse_sftp_attr_s *fuse_attr=_readdir_sftp->fuse_attr;
    struct directory_s *directory=_readdir_sftp->directory;
    struct inode_s *inode=entry->inode;

    inode->nlink=1;
    inode->mode=fuse_attr->permissions | fuse_attr->type;
    _readdir_sftp->opendir->created++;

    memcpy(&inode->stim, &directory->synctime, sizeof(struct timespec));

    fill_inode_attr_sftp(context->interface.ptr, inode, fuse_attr);
    add_inode_context(context, inode);

    if (S_ISDIR(inode->mode)) {

	inode->nlink=2;

	/* adjust the parent inode:
	    - a directory is added: link count is changed: ctim
	*/

	directory->inode->nlink++;
	get_current_time(&directory->inode->ctim);

    } else {

	/* adjust the parent inode:
	    - a file is added: mtim
	*/

	get_current_time(&directory->inode->mtim);

    }

}

static void _cb_found(struct entry_s *entry, void *data)
{
    struct _fs_sftp_readdir_struct *_readdir_sftp=(struct _fs_sftp_readdir_struct *) data;
    struct service_context_s *context=_readdir_sftp->opendir->context;
    struct directory_s *directory=_readdir_sftp->directory;
    struct fuse_sftp_attr_s *fuse_attr=_readdir_sftp->fuse_attr;
    struct inode_s *inode=entry->inode;

    fill_inode_attr_sftp(context->interface.ptr, inode, fuse_attr);
    _readdir_sftp->opendir->count++;

    memcpy(&inode->stim, &directory->synctime, sizeof(struct timespec));

}

static void _cb_error(struct entry_s *parent, struct name_s *xname, void *data, unsigned int error)
{
    struct _fs_sftp_readdir_struct *_readdir_sftp=(struct _fs_sftp_readdir_struct *) data;
    logoutput_warning("_fs_ssh_readdir_cb_error: error %i:%s creating %s", error, strerror(error), xname->name);
    *_readdir_sftp->error=error;

}

static struct entry_s *_fs_sftp_readdir_entry(struct workspace_mount_s *workspace, struct directory_s *directory, struct name_s *xname, struct fuse_sftp_attr_s *fuse_attr, struct fuse_opendir_s *opendir, unsigned int *error)
{
    struct _fs_sftp_readdir_struct _readdir_sftp;

    _readdir_sftp.workspace=workspace;
    _readdir_sftp.fuse_attr=fuse_attr;
    _readdir_sftp.directory=directory;
    _readdir_sftp.opendir=opendir;
    _readdir_sftp.error=error;

    return create_entry_extended_batch(directory, xname, _cb_created, _cb_found, _cb_error, (void *) &_readdir_sftp);

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

    if (f_request->flags & FUSEDATA_FLAG_INTERRUPTED) {

	reply_VFS_error(f_request, EINTR);
	return;

    }

    /* test a full opendir/readdir is required: test entries are deleted and/or created */

    if (directory && directory->synctime.tv_sec>0) {
	struct entry_s *entry=opendir->inode->alias;

	if (!(entry->flags & _ENTRY_FLAG_REMOTECHANGED)) {

	    /* no entries added and deleted: no need to read all entries again: use cache */

	    opendir->readdir=_fs_common_virtual_readdir;
	    opendir->fsyncdir=_fs_common_virtual_fsyncdir;
	    opendir->releasedir=_fs_common_virtual_releasedir;
	    _fs_common_virtual_opendir(opendir, f_request, flags);

	    return;

	}

    }

    pathinfo->len += (* interface->backend.sftp.complete_path)(interface, path, pathinfo);

    logoutput("_fs_sftp_opendir_common: send opendir %i %s", pathinfo->len, pathinfo->path);

    memset(&sftp_r, 0, sizeof(struct sftp_request_s));

    sftp_r.id=0;
    sftp_r.call.opendir.path=(unsigned char *) pathinfo->path;
    sftp_r.call.opendir.len=pathinfo->len;
    sftp_r.fusedata_flags=&f_request->flags;

    if (send_sftp_opendir_ctx(context->interface.ptr, &sftp_r)==0) {
	void *request=NULL;

	request=create_sftp_request_ctx(context->interface.ptr, &sftp_r, &error);

	if (request) {
	    struct timespec timeout;

	    get_sftp_request_timeout(&timeout);

	    if (wait_sftp_response_ctx(context->interface.ptr, request, &timeout, &error)==1) {

		if (sftp_r.type==SSH_FXP_HANDLE) {
		    struct fuse_open_out open_out;

		    opendir->handle.name.name=sftp_r.response.handle.name;
		    opendir->handle.name.len=sftp_r.response.handle.len;

		    open_out.fh=(uint64_t) opendir;
		    open_out.open_flags=0;
		    open_out.padding=0;

		    reply_VFS_data(f_request, (char *) &open_out, sizeof(open_out));

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

	opendir->readdir=_fs_common_virtual_readdir;
	opendir->fsyncdir=_fs_common_virtual_fsyncdir;
	opendir->releasedir=_fs_common_virtual_releasedir;
	_fs_common_virtual_opendir(opendir, f_request, flags);

	return;

    }

    opendir->error=error;
    reply_VFS_error(f_request, error);

}

/* send readdir to server to get list of names */

static int _sftp_get_readdir_names(struct fuse_opendir_s *opendir, struct fuse_request_s *f_request, unsigned int *error)
{
    struct service_context_s *context=opendir->context;
    struct sftp_request_s sftp_r;
    int result=-1;

    memset(&sftp_r, 0, sizeof(struct sftp_request_s));

    sftp_r.id=0;
    sftp_r.call.readdir.handle=(unsigned char *) opendir->handle.name.name;
    sftp_r.call.readdir.len=opendir->handle.name.len;
    sftp_r.fusedata_flags=&f_request->flags;

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

	    if (wait_sftp_response_ctx(context->interface.ptr, request, &timeout, error)==1) {

		if (sftp_r.type==SSH_FXP_NAME) {
		    struct name_response_s *response=NULL;

		    /* take the response from server to read the entries from */

		    response=malloc(sizeof(struct name_response_s));

		    if (response) {

			/* copy the pointers to the names, not the names (and attr) self */
			memcpy(response, &sftp_r.response.names, sizeof(struct name_response_s));
			opendir->data=(void *) response;
			result=response->left;

		    } else {

			*error=ENOMEM;
			free(sftp_r.response.names.buff);
			sftp_r.response.names.buff=NULL;
			result=-1;

		    }

		} else if (sftp_r.type==SSH_FXP_STATUS) {

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

    return result;

}

void _fs_sftp_readdir(struct fuse_opendir_s *opendir, struct fuse_request_s *f_request, size_t size, off_t offset)
{

    if (opendir->mode & _FUSE_READDIR_MODE_FINISH) {
	char dummy='\0';

	reply_VFS_data(f_request, &dummy, 0);

    } else {
	struct service_context_s *context=opendir->context;
	struct directory_s *directory=NULL;
	struct stat st;
	size_t pos=0, dirent_size=0;
	struct name_s xname={NULL, 0, 0};
	struct inode_s *inode=NULL;
	struct entry_s *entry=NULL;
	char buff[size];
	unsigned int error=EIO;

	if (f_request->flags & FUSEDATA_FLAG_INTERRUPTED) {

	    reply_VFS_error(f_request, EINTR);
	    return;

	}

	if (lock_directory_excl(opendir->inode)==0) {

	    directory=get_directory(opendir->inode);
	    if (offset==0) get_current_time(&directory->synctime);

	} else {

	    reply_VFS_error(f_request, EAGAIN);
	    return;

	}

	memset(&st, 0, sizeof(struct stat));

	while (pos<size) {

	    if (offset==0) {

		inode=opendir->inode;

    		/* the . entry */

    		st.st_ino = inode->ino;
		st.st_mode = S_IFDIR;
		xname.name = (char *) dotname;
		xname.len=1;

    	    } else if (offset==1) {
    		struct entry_s *parent=NULL;

		inode=opendir->inode;

		/* the .. entry */

		parent=inode->alias;
		if (parent->parent) inode=parent->parent->inode;

    		st.st_ino = inode->ino;
		st.st_mode = S_IFDIR;
		xname.name = (char *) dotdotname;
		xname.len=2;

    	    } else {

		if (! opendir->entry) {
		    struct name_response_s *response=(struct name_response_s *) opendir->data;

		    sftp_readdir:

		    if (response==NULL || response->left==0) {
			int result=0;

			result=_sftp_get_readdir_names(opendir, f_request, &error);

			if (result==-1) {

			    /* some error */

			    reply_VFS_error(f_request, error);
			    goto unlock;

			} else if (result==0) {

			    /* no more names from server */

			    opendir->mode |= _FUSE_READDIR_MODE_FINISH;
			    break;

			}

			response=(struct name_response_s *) opendir->data;

		    }

		    if (response->left>0) {
			unsigned int len=0;
			char *name=NULL;
			struct fuse_sftp_attr_s fuse_attr;

			/*
			    extract name and attributes from names
			*/

			memset(&fuse_attr, 0, sizeof(struct fuse_sftp_attr_s));
			read_name_response_ctx(context->interface.ptr, response, &name, &len, &fuse_attr);

			if ((len==1 && strncmp(name, ".", 1)==0) || (len==2 && strncmp(name, "..", 2)==0)) {

			    /* skip the . and .. entries */

			    goto sftp_readdir;

			} else {
			    char buffer[len+1];

			    memcpy(buffer, name, len);
			    *(buffer+len)='\0';

			    xname.name=buffer;
			    xname.len=len;
			    calculate_nameindex(&xname);

			    entry=_fs_sftp_readdir_entry(context->workspace, directory, &xname, &fuse_attr, opendir, &error);

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

			st.st_ino=inode->ino;
			st.st_mode=inode->mode;

		    } else {

			/* all names read: check the "eof" boolean */

			if (response->eof==1) {

			    opendir->mode |= _FUSE_READDIR_MODE_FINISH;
			    break;

			}

			goto sftp_readdir;

		    }

		} else {

		    entry=opendir->entry;

		    inode=entry->inode;

		    st.st_ino=inode->ino;
		    st.st_mode=inode->mode;
		    xname.name=entry->name.name;
		    xname.len=entry->name.len;

		}

	    }

	    logoutput("READDIR sftp: add %s", xname.name);

	    error=0;
	    dirent_size=add_direntry_buffer(buff + pos, size - pos, offset + 1, &xname, &st, &error);

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

	unlock_directory_excl(opendir->inode);

    }

}

void _fs_sftp_readdirplus(struct fuse_opendir_s *opendir, struct fuse_request_s *r, size_t size, off_t offset)
{
    reply_VFS_error(r, ENOSYS);
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

    if (f_request->flags & FUSEDATA_FLAG_INTERRUPTED) {

	reply_VFS_error(f_request, EINTR);
	return;

    }

    memset(&sftp_r, 0, sizeof(struct sftp_request_s));

    sftp_r.id=0;
    sftp_r.call.close.handle=(unsigned char *) opendir->handle.name.name;
    sftp_r.call.close.len=opendir->handle.name.len;
    sftp_r.fusedata_flags=&f_request->flags;

    if (send_sftp_close_ctx(context->interface.ptr, &sftp_r)==0) {
	void *request=NULL;

	request=create_sftp_request_ctx(context->interface.ptr, &sftp_r, &error);

	if (request) {
	    struct timespec timeout;

	    get_sftp_request_timeout(&timeout);

	    if (wait_sftp_response_ctx(context->interface.ptr, request, &timeout, &error)==1) {

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

    if (entry->flags & _ENTRY_FLAG_REMOTECHANGED) entry->flags-=_ENTRY_FLAG_REMOTECHANGED;

    /* remove local entries not found on server */

    if (lock_directory_excl(opendir->inode)==0) {
	struct directory_s *directory=get_directory(opendir->inode);

	/*
		only check when there are deleted entries:
		- the entries found on server (opendir->created plus the already found opendir->count)
		is not equal to the number of entries in this local directory
	*/

	if (opendir->count + opendir->created != directory->count) {
	    struct directory_s *directory=NULL;
	    struct inode_s *inode=NULL;
	    struct entry_s *entry=NULL;
	    struct entry_s *next=NULL;

	    directory=get_directory(opendir->inode);

	    entry=directory->first;

	    while (entry) {

		next=entry->name_next;

		inode=entry->inode;
		if (inode->stim.tv_sec < directory->synctime.tv_sec || (inode->stim.tv_sec == directory->synctime.tv_sec && inode->stim.tv_nsec < directory->synctime.tv_nsec)) {

		    notify_VFS_delete(get_root_ptr_context(context), opendir->inode->ino, inode->ino, entry->name.name, entry->name.len);
		    remove_entry_batch(directory, entry, &error);
		    entry->inode=NULL;
		    destroy_entry(entry);
		    remove_inode(inode);
		    free(inode);

		}

		entry=next;

	    }

	}

	unlock_directory_excl(opendir->inode);

    }

}
