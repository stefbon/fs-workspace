/*
  2010, 2011, 2012, 2013, 2014, 2015, 2016, 2017 Stef Bon <stefbon@gmail.com>

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
#include <errno.h>
#include <err.h>
#include <dirent.h>

#include <inttypes.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <sys/mount.h>

#include <pthread.h>

#ifndef ENOATTR
#define ENOATTR ENODATA        /* No such attribute */
#endif

#include "logging.h"

#include "main.h"
#include "utils.h"
#include "pathinfo.h"
#include "beventloop.h"
#include "beventloop-xdata.h"
#include "entry-management.h"
#include "directory-management.h"
#include "entry-utils.h"

#include "workerthreads.h"
#include "fuse-fs.h"
#include "workspaces.h"
#include "workspace-context.h"
#include "workspace-session.h"
#include "discover.h"

#include "fuse-fs-common.h"
#include "fuse-sftp.h"

struct entry_s *create_network_map_entry(struct workspace_mount_s *workspace, struct directory_s *directory, struct name_s *xname, unsigned int *error)
{
    struct stat st;

    st.st_mode=S_IFDIR | S_IRUSR | S_IXUSR | S_IWUSR | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH;
    st.st_uid=0;
    st.st_gid=0;
    st.st_ino=0;
    st.st_dev=0;
    st.st_nlink=2;
    st.st_rdev=0;
    st.st_size=_INODE_DIRECTORY_SIZE;
    st.st_blksize=0;
    st.st_blocks=0;

    get_current_time(&st.st_mtim);
    memcpy(&st.st_ctim, &st.st_mtim, sizeof(struct timespec));
    memcpy(&st.st_atim, &st.st_mtim, sizeof(struct timespec));

    return _fs_common_create_entry(workspace, directory, xname, &st, 0, error);

}


/* function called when a network FUSE context is mounted */

static void install_net_services_context(unsigned int service, struct context_address_s *address, struct timespec *found, unsigned long hostid, unsigned int serviceid, void *ptr)
{
    struct service_context_s *context=(struct service_context_s *) ptr;
    struct workspace_mount_s *workspace=context->workspace;
    struct inode_s *inode=NULL;
    struct directory_s *root_directory=NULL;

    if (workspace->syncdate.tv_sec < found->tv_sec || (workspace->syncdate.tv_sec == found->tv_sec && workspace->syncdate.tv_nsec < found->tv_nsec)) {

	workspace->syncdate.tv_sec = found->tv_sec;
	workspace->syncdate.tv_nsec = found->tv_nsec;

    }

    inode=&workspace->rootinode;

    if (lock_directory_excl(inode)==-1) {

	logoutput("install_net_services_context: unable to lock root directory");
	return;

    }

    root_directory=get_directory(inode);
    unlock_directory_excl(inode);

    if (service==WORKSPACE_SERVICE_SFTP) {
	unsigned int error=0;

	if (install_ssh_server_context(workspace, inode->alias, address->target.network.address, address->target.network.port, &error)!=0) {

	    logoutput("install_net_services_context: unable to connect to %s:%i", address->target.network.address, address->target.network.port);

	}

    }

}

/* function called when a network service on a host is detected
    walk every FUSE context for network services and test it should be used here
*/

static void install_net_services_all(unsigned int service, struct context_address_s *address, struct timespec *found, unsigned long hostid, unsigned long serviceid)
{
    struct fuse_user_s *user=NULL;
    struct workspace_mount_s *workspace=NULL;
    struct workspace_base_s *base=NULL;
    unsigned int hashvalue=0;
    void *index=NULL;
    struct list_element_s *list=NULL;

    rwlock:

    lock_users_hash();

    nextuser:

    user=get_next_fuse_user(&index, &hashvalue);
    if (! user) {

	logoutput("install_net_services_all: ready");
	unlock_users_hash();
	return;

    }

    if (!(user->options & WORKSPACE_TYPE_NETWORK)) goto nextuser;

    pthread_mutex_lock(&user->mutex);
    unlock_users_hash();

    list=user->workspaces.head;

    while(list) {

	workspace=get_container_workspace(list);
	base=workspace->base;

	if (base->type==WORKSPACE_TYPE_NETWORK) {
	    struct service_context_s *context=NULL;

	    /* test service is already in use on this workspace
		if not install it */

	    context=get_container_context(workspace->contexes.head);

	    while (context) {

		if (context->type==SERVICE_CTX_TYPE_SERVICE && context->serviceid==serviceid) break;
		context=get_container_context(context->list.next);

	    }

	    if (! context) install_net_services_context(service, address, found, hostid, serviceid, (void *) workspace->context);

	}

	list=workspace->list.next;

    }

    pthread_mutex_unlock(&user->mutex);
    goto rwlock;

}

void install_net_services_cb(unsigned int service, struct context_address_s *address, struct timespec *found, unsigned long hostid, unsigned long serviceid, void *ptr)
{

    if (service==WORKSPACE_SERVICE_SFTP) {

	logoutput("install_net_services_cb: found sftp at %s", address->target.network.address);

    } else {

	if (service==WORKSPACE_SERVICE_SMB) {

	    logoutput("install_net_services_cb: found smb://%s; not supported yet", address->target.smbshare.server);

	} else if (service==WORKSPACE_SERVICE_NFS) {

	    logoutput("install_net_services_cb: found nfs at %s; not supported yet", address->target.network.address);

	} else if (service==WORKSPACE_SERVICE_WEBDAV) {

	    logoutput("install_net_services_cb: found webdav at %s; not supported yet", address->target.network.address);

	} else if (service==WORKSPACE_SERVICE_SSH) {

	    logoutput("install_net_services_cb: found ssh at %s; ignoring", address->target.network.address);

	}

	return;

    }

    if (ptr) {

	install_net_services_context(service, address, found, hostid, serviceid, ptr);

    } else {

	install_net_services_all(service, address, found, hostid, serviceid);

    }

}
