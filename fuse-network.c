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

#define LOGGING
#include "logging.h"

#include "main.h"
#include "options.h"
#include "utils.h"
#include "pathinfo.h"
#include "beventloop.h"
#include "beventloop-xdata.h"
#include "fuse-dentry.h"
#include "fuse-directory.h"
#include "fuse-utils.h"

#include "workerthreads.h"
#include "fuse-fs.h"
#include "workspaces.h"
#include "workspace-context.h"
#include "workspace-session.h"
#include "discover.h"

#include "fuse-fs-common.h"
#include "fuse-sftp.h"

extern struct fs_options_s fs_options;
extern unsigned int get_ssh_interface_info(struct context_interface_s *interface, const char *what, void *data, struct common_buffer_s *buffer);

struct entry_s *create_network_map_entry(struct service_context_s *context, struct directory_s *directory, struct name_s *xname, unsigned int *error)
{
    struct create_entry_s ce;
    struct stat st;

    /* stat values for a network map */

    st.st_mode=S_IFDIR | S_IRUSR | S_IXUSR | S_IWUSR | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH;
    st.st_uid=0;
    st.st_gid=0;
    st.st_ino=0;
    st.st_dev=0;
    st.st_nlink=2;
    st.st_rdev=0;
    st.st_size=_INODE_DIRECTORY_SIZE;
    st.st_blksize=1024;
    st.st_blocks=(unsigned int) (st.st_size / st.st_blksize) + ((st.st_size % st.st_blksize)==0) ? 1 : 0;

    get_current_time(&st.st_mtim);
    memcpy(&st.st_ctim, &st.st_mtim, sizeof(struct timespec));
    memcpy(&st.st_atim, &st.st_mtim, sizeof(struct timespec));

    init_create_entry(&ce, xname, NULL, directory, NULL, context, &st, NULL);
    return create_entry_extended_batch(&ce);

}


/* function called when a network FUSE context is mounted */

static void install_net_services_context(struct host_address_s *host, struct service_address_s *service, unsigned int code, struct timespec *found, unsigned long hostid, unsigned int serviceid, void *ptr)
{
    struct service_context_s *context=(struct service_context_s *) ptr;
    struct workspace_mount_s *workspace=context->workspace;
    struct inode_s *inode=NULL;
    struct directory_s *root_directory=NULL;
    struct simple_lock_s wlock;

    logoutput("install_net_services_context");

    if (workspace->syncdate.tv_sec < found->tv_sec || (workspace->syncdate.tv_sec == found->tv_sec && workspace->syncdate.tv_nsec < found->tv_nsec)) {

	workspace->syncdate.tv_sec = found->tv_sec;
	workspace->syncdate.tv_nsec = found->tv_nsec;

    }

    inode=&workspace->rootinode;
    root_directory=get_directory(inode);

    if (wlock_directory(root_directory, &wlock)==-1) {

	logoutput("install_net_services_context: unable to lock root directory");
	return;

    }

    unlock_directory(root_directory, &wlock);

    if (code==WORKSPACE_SERVICE_SFTP) {
	unsigned int error=0;
	char *target=NULL;
	unsigned int port=22;

	translate_context_host_address(host, &target, NULL);
	translate_context_network_port(service, &port);

	logoutput("install_net_services_context: connecting to %s:%i", target, port);

	if (install_ssh_server_context(workspace, inode->alias, host, service, &error)!=0) {

	    logoutput("install_net_services_context: unable to connect to %s:%i", target, port);

	}

    }

}

/* function called when a network service on a host is detected
    walk every FUSE context for network services and test it should be used here
*/

static void install_net_services_all(struct host_address_s *host, struct service_address_s *service, unsigned int code, struct timespec *found, unsigned long hostid, unsigned long serviceid)
{
    struct fuse_user_s *user=NULL;
    struct workspace_mount_s *workspace=NULL;
    struct workspace_base_s *base=NULL;
    unsigned int hashvalue=0;
    void *index=NULL;
    struct list_element_s *list=NULL;
    struct simple_lock_s wlock;

    logoutput("install_net_services_all");

    init_wlock_users_hash(&wlock);

    rwlock:

    lock_users_hash(&wlock);

    nextuser:

    user=get_next_fuse_user(&index, &hashvalue);
    if (user==NULL) {

	logoutput("install_net_services_all: ready");
	unlock_users_hash(&wlock);
	return;

    }

    if (!(user->options & WORKSPACE_TYPE_NETWORK)) goto nextuser;

    pthread_mutex_lock(&user->mutex);
    unlock_users_hash(&wlock);

    list=get_list_head(&user->workspaces, 0);

    while(list) {

	workspace=get_container_workspace(list);
	base=workspace->base;

	if (base->type==WORKSPACE_TYPE_NETWORK) {
	    struct service_context_s *context=NULL;

	    /* test service is already in use on this workspace
		if not install it */

	    context=get_container_context(workspace->contexes.head);

	    while (context) {

		if ((context->type==SERVICE_CTX_TYPE_FILESYSTEM || context->type==SERVICE_CTX_TYPE_CONNECTION || context->type==SERVICE_CTX_TYPE_SOCKET) && context->serviceid==serviceid) break;
		context=get_container_context(get_next_element(&context->list));

	    }

	    /* only install when not found
		TODO: when it's found earlier (does exist) but not connected does this here again */

	    if (! context) {

		install_net_services_context(host, service, code, found, hostid, serviceid, (void *) workspace->context);

	    } else {
		char connectionstatus[4];
		struct common_buffer_s bufferstatus;

		bufferstatus.ptr=connectionstatus;
		bufferstatus.size=4;
		bufferstatus.len=bufferstatus.size;
		bufferstatus.pos=bufferstatus.ptr;

		if (get_ssh_interface_info(&context->interface, "status", NULL, &bufferstatus)==4) {

		    logoutput("install_net_services_all: host %i serviceid %i found, reconnect", hostid, serviceid);
		    install_net_services_context(host, service, code, found, hostid, serviceid, (void *) workspace->context);

		}

	    }

	}

	list=get_next_element(&workspace->list);

    }

    pthread_mutex_unlock(&user->mutex);
    goto rwlock;

}

void install_net_services_cb(struct host_address_s *host, struct service_address_s *service, unsigned int code, struct timespec *found, unsigned long hostid, unsigned long serviceid, void *ptr)
{

    logoutput("install_net_services_cb");

    if (code==WORKSPACE_SERVICE_SFTP) {

	logoutput("install_net_services_cb: found sftp");

    } else {

	if (code==WORKSPACE_SERVICE_SMB) {

	    logoutput("install_net_services_cb: found smb:// not supported yet");

	} else if (code==WORKSPACE_SERVICE_NFS) {

	    logoutput("install_net_services_cb: found nfs:// not supported yet");

	} else if (code==WORKSPACE_SERVICE_WEBDAV) {

	    logoutput("install_net_services_cb: found webdav not supported yet");

	} else if (code==WORKSPACE_SERVICE_SSH) {

	    logoutput("install_net_services_cb: found ssh ignoring");

	}

	return;

    }

    if (ptr) {

	install_net_services_context(host, service, code, found, hostid, serviceid, ptr);

    } else {

	install_net_services_all(host, service, code, found, hostid, serviceid);

    }

}
