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
#include <sys/syscall.h>
#include <sys/statvfs.h>
#include <sys/mount.h>

#ifdef HAVE_SETXATTR
#include <sys/xattr.h>
#endif

#ifndef ENOATTR
#define ENOATTR ENODATA        /* No such attribute */
#endif

#include "logging.h"

#include "main.h"
#include "utils.h"
#include "pathinfo.h"

#include "workerthreads.h"
#include "beventloop.h"
#include "beventloop-signal.h"
#include "beventloop-timer.h"
#include "beventloop-xdata.h"
#include "entry-management.h"
#include "directory-management.h"
#include "entry-utils.h"

#include "options.h"

#include "fuse-fs.h"
#include "fuse-interface.h"
#include "workspaces.h"
#include "workspace-utils.h"
#include "workspace-session.h"
#include "workspace-context.h"
#include "fuse-fs-virtual.h"

#include "fschangenotify.h"
#include "monitorsessions.h"
#include "monitormounts.h"

#include "pidfile.h"
#include "localsocket.h"
#include "discover/discover-avahi.h"
#include "discover.h"
#include "fuse-network.h"

struct fs_options_struct fs_options;
char *program_name=NULL;

static void _disconnect_service(struct entry_s *entry, void *ptr)
{
    struct inode_s *inode=entry->inode;
    if (inode) (* inode->fs->forget)(inode);
}

static void _disconnect_workspace(struct context_interface_s *interface)
{
    struct service_context_s *root=get_service_context(interface);
    struct workspace_mount_s *workspace=NULL;
    unsigned int error=0;
    struct directory_s *root_directory=NULL;

    logoutput("_disconnect_workspace");

    workspace=root->workspace;
    if (! workspace) return;

    pthread_mutex_lock(&workspace->mutex);
    workspace->status=WORKSPACE_STATUS_UNMOUNTING;
    pthread_mutex_unlock(&workspace->mutex);

    logoutput("_disconnect_workspace: umount");

    free_fuse_interface(interface);
    if (workspace->mountpoint.path && workspace->mountpoint.len>0) {

	if (umount2(workspace->mountpoint.path, MNT_DETACH)==0) {

	    logoutput("_disconnect_workspace: umounted %s", workspace->mountpoint.path);

	} else {

	    logoutput("_disconnect_workspace: error %i (%s) umounting %s", errno, strerror(errno), workspace->mountpoint.path);

	}

    }

    pthread_mutex_lock(&workspace->mutex);
    workspace->status=WORKSPACE_STATUS_UNMOUNTED;
    pthread_mutex_unlock(&workspace->mutex);

    logoutput("_disconnect_workspace: remove inodes, entries and directories");

    root_directory=remove_directory(&workspace->rootinode, &error);

    if (root_directory) {

	/* this will also close and free connections */
	clear_directory(root_directory, _disconnect_service, NULL);
	destroy_directory(root_directory);

    }

    if (workspace->contexes.head) {
	struct list_element_s *list=NULL;
	struct service_context_s *context=NULL;

	list=get_list_head(&workspace->contexes.head, &workspace->contexes.tail);

	while (list) {

	    context=get_container_context(list);

	    /* TODO: build some protection here */

	    if (context->refcount==0 || (context->flags & SERVICE_CTX_FLAG_REFCOUNTNONZERO)) {

		logoutput("_disconnect_workspace: disconnect service %s context", context->name);

		(* context->interface.free)(&context->interface);

		if (context->parent) {

		    logoutput("_disconnect_workspace: parent service %s refcount %i->%i", context->parent->name, context->parent->refcount, context->parent->refcount-1);
		    context->parent->refcount--;

		}

		logoutput("_disconnect_workspace: free service");

		free_service_context(context);

	    } else {

		logoutput("_disconnect_workspace: service %s refcount %i", context->name, context->refcount);
		add_list_element_last(&workspace->contexes.head, &workspace->contexes.tail, list);
		context->flags|=SERVICE_CTX_FLAG_REFCOUNTNONZERO;

	    }

	    list=get_list_head(&workspace->contexes.head, &workspace->contexes.tail);

	}

    }

}

static void disconnect_workspace(struct context_interface_s *interface)
{
    struct service_context_s *context=get_service_context(interface);
    struct workspace_mount_s *workspace=context->workspace;
    struct fuse_user_s *user=workspace->user;

    logoutput("disconnect_workspace");

    _disconnect_workspace(interface);

    (* user->remove_workspace)(user, workspace);
    free_service_context(context);
    free_workspace_mount(workspace);

}

/* enable/disable flags for filesystem
    depends on the type:
    - flock enabled on filesystems
    - xattr ?
*/

static unsigned int get_option_mount(struct context_interface_s *interface, const char *name, struct context_option_s *option)
{
    struct service_context_s *context=get_service_context(interface);
    struct workspace_base_s *base=context->workspace->base;

    if (strcmp(name, "async-read")==0) {

	option->type=_INTERFACE_OPTION_INT;
	option->value.number=0;

    } else if (strcmp(name, "posix-locks")==0) {

	option->type=_INTERFACE_OPTION_INT;
	option->value.number=0;

    } else if (strcmp(name, "file-ops")==0) {

	option->type=_INTERFACE_OPTION_INT;
	option->value.number=1;

    } else if (strcmp(name, "atomic-o-trunc")==0) {

	option->type=_INTERFACE_OPTION_INT;
	option->value.number=0; /* test this ... */

    } else if (strcmp(name, "export_support")==0) {

	option->type=_INTERFACE_OPTION_INT;
	option->value.number=0;

    } else if (strcmp(name, "big-writes")==0) {

	option->type=_INTERFACE_OPTION_INT;
	option->value.number=1;

    } else if (strcmp(name, "dont-mask")==0) {

	option->type=_INTERFACE_OPTION_INT;
	option->value.number=0;

    } else if (strcmp(name, "splice-write")==0) {

	option->type=_INTERFACE_OPTION_INT;
	option->value.number=0;

    } else if (strcmp(name, "splice-move")==0) {

	option->type=_INTERFACE_OPTION_INT;
	option->value.number=0;

    } else if (strcmp(name, "splice-read")==0) {

	option->type=_INTERFACE_OPTION_INT;
	option->value.number=0;

    } else if (strcmp(name, "flock-locks")==0) {

	option->type=_INTERFACE_OPTION_INT;

	if (base->type==WORKSPACE_TYPE_NETWORK) {

	    option->value.number=1;

	} else {

	    option->value.number=0;

	}

    } else if (strcmp(name, "has-ioctl-dir")==0) {

	option->type=_INTERFACE_OPTION_INT;
	option->value.number=0;

    } else if (strcmp(name, "auto-inval-data")==0) {

	option->type=_INTERFACE_OPTION_INT;
	option->value.number=0;

    } else if (strcmp(name, "do-readdirplus")==0) {

	option->type=_INTERFACE_OPTION_INT;
	option->value.number=0;

    } else if (strcmp(name, "readdirplus-auto")==0) {

	option->type=_INTERFACE_OPTION_INT;
	option->value.number=1;

    } else if (strcmp(name, "async-dio")==0) {

	option->type=_INTERFACE_OPTION_INT;
	option->value.number=0;

    } else if (strcmp(name, "writeback-cache")==0) {

	option->type=_INTERFACE_OPTION_INT;
	option->value.number=1;

    } else if (strcmp(name, "no-open-support")==0) {

	option->type=_INTERFACE_OPTION_INT;
	option->value.number=0;

    } else if (strcmp(name, "parallel-dirops")==0) {

	option->type=_INTERFACE_OPTION_INT;
	option->value.number=0;

    } else if (strcmp(name, "posix-acl")==0) {

	option->type=_INTERFACE_OPTION_INT;
	option->value.number=0; /* todo ... */

    } else if (strcmp(name, "fsnotify")==0) {

	option->type=_INTERFACE_OPTION_INT;
	option->value.number=1;

    }

    return sizeof(unsigned int);
}

struct service_context_s *create_mount_context(struct fuse_user_s *user, struct workspace_base_s *base, struct pathinfo_s *pathinfo)
{
    struct service_context_s *context=NULL;
    struct workspace_mount_s *workspace=NULL;
    unsigned int error=0;

    logoutput("create_mount_context: uid %i", (int) user->uid);

    workspace=malloc(sizeof(struct workspace_mount_s));
    context=create_service_context(NULL, SERVICE_CTX_TYPE_WORKSPACE);

    if (! context || ! workspace) goto error;

    context->workspace=workspace;
    //add_list_element_first(&workspace->contexes.head, &workspace->contexes.tail, &context->list);
    strcpy(context->name, "virtual");

    if (init_workspace_mount(workspace, &error)==0) {
	char source[64];
	char name[32];

	snprintf(source, 64, "fs-workspace");

	workspace->base=base;
	workspace->user=user;
	workspace->context=context;

	workspace->mountpoint.path=pathinfo->path;
	workspace->mountpoint.len=pathinfo->len;
	workspace->mountpoint.flags=pathinfo->flags;
	workspace->mountpoint.refcount=pathinfo->refcount;

	pathinfo->path=NULL;
	pathinfo->len=0;
	pathinfo->flags=0;
	pathinfo->refcount=0;

	if (base->type==WORKSPACE_TYPE_NETWORK) {

	    snprintf(name, 32, "network");

	} else if (base->type==WORKSPACE_TYPE_DEVICES) {

	    snprintf(name, 32, "devices");

	} else if (base->type==WORKSPACE_TYPE_BACKUP) {

	    snprintf(name, 32, "backup");

	} else if (base->type==WORKSPACE_TYPE_FILE) {

	    snprintf(name, 32, "file");

	} else {

	    snprintf(name, 32, "unknown");

	}

	logoutput("create_mount_context: init fuse");

	if (init_fuse_interface(&context->interface)==0) {
	    struct context_address_s fuse_address;
	    union datalink_u *link=&workspace->rootinode.link;

	    context->interface.disconnect=disconnect_workspace;
	    context->interface.get_interface_option=get_option_mount;

	    register_fuse_functions(&context->interface);
	    link->data=(void *) get_dummy_directory();
	    use_virtual_fs(context, &workspace->rootinode);

	    /* connect to the fuse interface: mount */
	    /* target address of interface is a local mountpoint */

	    memset(&fuse_address, 0, sizeof(struct context_address_s));
	    fuse_address.type=_INTERFACE_FUSE_MOUNT;
	    fuse_address.target.fuse.source=source;
	    fuse_address.target.fuse.mountpoint=workspace->mountpoint.path;
	    fuse_address.target.fuse.name=name;

	    if ((* context->interface.connect)(user->uid, &context->interface, &fuse_address, &error)) {

		(* user->add_workspace)(user, workspace);
		user->options |= base->type;

		logoutput("create_mount_context: %s mounted", workspace->mountpoint.path);

	    } else {

		logoutput("create_mount_context: failed to mount %s", workspace->mountpoint.path);
		goto error;

	    }

	    return context;

	}

    }

    error:

    if (context) free_service_context(context);
    if (workspace) free_workspace_mount(workspace);

    return NULL;

}

static void terminate_user_workspaces(struct fuse_user_s *user)
{
    struct workspace_mount_s *workspace=NULL;
    struct list_element_s *list=NULL;

    logoutput("terminate_user_workspaces");

    list=get_list_head(&user->workspaces.head, &user->workspaces.tail);

    while (list) {

	workspace=get_container_workspace(list);

	if (workspace->context) {
	    struct service_context_s *context=workspace->context;

	    _disconnect_workspace(&context->interface);

	    context->workspace=NULL;
	    free_service_context(context);
	    workspace->context=NULL;
	}

	logoutput("terminate_user_workspaces: free mount");

	free_workspace_mount(workspace);
	list=get_list_head(&user->workspaces.head, &user->workspaces.tail);

    }

    logoutput("terminate_user_workspaces: ready");

}

static void terminate_fuse_user(void *ptr)
{
    struct fuse_user_s *user=(struct fuse_user_s *) ptr;

    logoutput("terminate_fuse_user: %i", user->uid);

    terminate_user_workspaces(user);
    pthread_mutex_destroy(&user->mutex);
    free(user);
    user=NULL;

}

static void terminate_fuse_users(void *ptr)
{
    struct fuse_user_s *user=NULL;
    void *index=NULL;
    unsigned int hashvalue=0;

    logoutput("terminate_fuse_users");

    getuser:

    index=NULL;

    lock_users_hash();
    user=get_next_fuse_user(&index, &hashvalue);
    if (user) remove_fuse_user_hash(user);
    unlock_users_hash();

    if (user) {
	unsigned int error=0;

	work_workerthread(NULL, 0, terminate_fuse_user, (void *) user, &error);
	index=NULL;
	goto getuser;

    }

    logoutput("terminate_fuse_users: ready");

}

static void add_usersession(uid_t uid, char *what)
{
    struct fuse_user_s *user=NULL;
    unsigned int error=0;

    logoutput("add_usersession: %i", (int) uid);

    user=add_fuse_user(uid, what, &error);

    if (user && error==0) {
	struct workspace_base_s *base=NULL;

	/* lookup in workspaces... which applies */

	base=get_next_workspace_base(NULL);

	while (base) {

	    logoutput("add_usersession: testing %s", base->name);

	    if (use_workspace_base(user, base)==1) {
		struct pathinfo_s pathinfo=PATHINFO_INIT;

		/* mountpoint */

		if (get_mountpoint_workspace_base(user, base, &pathinfo)) {

		    if (create_directory(&pathinfo, S_IFDIR | S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH, &error) == 0) {

			if (create_mount_context(user, base, &pathinfo)) {

			    logoutput_notice("add_usersession: mount context created");
			    base=get_next_workspace_base(base);
			    continue;

			}

		    } else {

			logoutput_error("add_usersession: error %i:%s creating directory %s", error, strerror(error), pathinfo.path);

		    }

		    free_path_pathinfo(&pathinfo);

		}

	    }

	    next:
	    base=get_next_workspace_base(base);

	}

    }

}

static void change_usersession(uid_t uid, char *status)
{
    struct fuse_user_s *user=NULL;

    logoutput("change_usersession");

    lock_users_hash();

    user=lookup_fuse_user(uid);

    if (user) {

	/* remove user when not active anymore */

	if (strcmp(status, "active")!=0 && strcmp(user->status, "active")==0) {

	    remove_fuse_user_hash(user);
	    unlock_users_hash();
	    work_workerthread(NULL, 0, terminate_fuse_user, NULL, (void *) user);
	    return;

	}

    } else {

	if (strcmp(status, "active")==0) add_usersession(uid, status);

    }

    unlock_users_hash();

    logoutput("change_usersession: done");

}

static void update_usersessions(uid_t uid, char *status, signed char change)
{

    if (change==1) {

	/* add user only if the session is active */

	change_usersession(uid, status);

    } else if (change==0) {

	/* same user: maybe status has changed */

	change_usersession(uid, status);

    } else if (change==-1) {

	/* user removed */

	change_usersession(uid, "offline");

    }

}

static void workspace_signal_handler(struct beventloop_s *bloop, void *data, struct signalfd_siginfo *fdsi)
{
    unsigned int signo=fdsi->ssi_signo;

    if ( signo==SIGHUP || signo==SIGINT || signo==SIGTERM ) {

	logoutput("workspace_signal_handler: got signal (%i): terminating", signo);
	bloop->status=BEVENTLOOP_STATUS_DOWN;

    } else if ( signo==SIGIO ) {

	logoutput("workspace_signal_handler: received SIGIO signal");

	/*
	    TODO:
	    when receiving an SIGIO signal another application is trying to open a file
	    is this really the case?
	    then the fuse fs is the owner!?
	*/

    } else if ( signo==SIGPIPE ) {

	logoutput("workspace_signal_handler: received SIGPIPE signal");

    } else if ( signo==SIGCHLD ) {

	logoutput("workspace_signal_handler: received SIGCHLD signal");

    } else if ( signo==SIGUSR1 ) {

	logoutput("workspace_signal_handler: received SIGUSR1 signal");

    } else {

        logoutput("workspace_signal_handler: received unknown %i signal", signo);

    }

}

/* accept only connections from users with a complete session
    what api??
    SSH_MSG_CHANNEL_REQUEST...???
*/

struct fs_connection_s *accept_client_connection(uid_t uid, gid_t gid, pid_t pid, void *ptr)
{
    struct fuse_user_s *user=NULL;

    logoutput("accept_client_connection");

    lock_users_hash();

    user=lookup_fuse_user(uid);

    if (user) {

    }

    unlock:
    unlock_users_hash();

    return NULL;
}

int main(int argc, char *argv[])
{
    int res=0;
    unsigned int error=0;
    struct bevent_xdata_s *xdata=NULL;
    struct fs_connection_s socket;

    /* daemonize */

    res=custom_fork();

    if (res<0) {

        fprintf(stderr, "MAIN: error daemonize.");
        return 1;

    } else if (res>0) {

	fprintf(stdout, "MAIN: created a service with pid %i.\n", res);
	return 0;

    }

    umask(0);
    program_name=argv[0];

    /* parse commandline options and initialize the fuse options */

    if (parse_arguments(argc, argv, &error)==-1) {

	if (error>0) logoutput_error("MAIN: error, cannot parse arguments, error: %i (%s).", error, strerror(error));
	goto options;

    }

    if (fs_options.basemap.path) {

	logoutput("MAIN: reading workspaces from %s.", fs_options.basemap.path);
	read_workspace_files(fs_options.basemap.path);

    } else {

	logoutput("MAIN: reading workspaces from %s.", FS_WORKSPACE_BASEMAP);
	read_workspace_files(FS_WORKSPACE_BASEMAP);

    }

    init_workerthreads(NULL);
    set_max_numberthreads(NULL, 6);
    init_directory_calls();
    init_special_fs();

    if (init_discover_group(&error)==-1) {

	logoutput_error("MAIN: error, cannot initialize discover group, error: %i (%s).", error, strerror(error));
	goto post;

    } else {

	logoutput("MAIN: initialized discover group");

    }

    set_discover_net_cb(install_net_services_cb);

    if (init_inode_hashtable(&error)==-1) {

	logoutput_error("MAIN: error, cannot initialize inode hash table, error: %i (%s).", error, strerror(error));
	goto post;

    }

    if (initialize_fuse_users(&error)==-1) {

	logoutput_error("MAIN: error, cannot initialize fuse users hash table, error: %i (%s).", error, strerror(error));
	goto post;

    }

    if (init_beventloop(NULL, &error)==-1) {

        logoutput_error("MAIN: error creating eventloop, error: %i (%s).", error, strerror(error));
        goto post;

    } else {

	logoutput("MAIN: creating eventloop");

    }

    if (enable_beventloop_signal(NULL, workspace_signal_handler, NULL, &error)==-1) {

	logoutput_error("MAIN: error adding signal handler to eventloop: %i (%s).", error, strerror(error));
        goto out;

    } else {

	logoutput("MAIN: adding signal handler");

    }

    if (add_mountinfo_watch(NULL, &error)==-1) {

        logoutput_error("MAIN: unable to open mountmonitor, error=%i (%s)", error, strerror(error));
        goto out;

    } else {

	logoutput("MAIN: open mountmonitor");

    }

    if (init_fschangenotify(NULL, &error)==-1) {

	logoutput_error("MAIN: error initializing fschange notify, error: %i (%s)", error, strerror(error));
	goto out;

    }

    if (create_socket_path(&fs_options.socket)==0) {
	unsigned int alreadyrunning=0;
	unsigned int count=0;

	checkpidfile:

	alreadyrunning=check_pid_file(&fs_options.socket);

	if (alreadyrunning>0 && count < 10) {
	    char procpath[64];
	    struct stat st;

	    snprintf(procpath, 64, "/proc/%i/cmdline", alreadyrunning);

	    /* check here for existence of cmdline
		a better check will be to test also the cmdline contains this programname if it exists */

	    if (stat(procpath, &st)==-1) {

		/* pid file found, but no process */

		remove_pid_file(&fs_options.socket, (pid_t) alreadyrunning);
		alreadyrunning=0;
		count++;
		goto checkpidfile;

	    }

	}

	if (check_socket_path(&fs_options.socket, alreadyrunning)==-1) goto out;
	init_connection(&socket, FS_CONNECTION_TYPE_LOCALSERVER);

	if (create_local_serversocket(fs_options.socket.path, &socket, NULL, accept_client_connection, &error)>=0) {

	    logoutput("MAIN: created socket %s", fs_options.socket.path);

	} else {

	    logoutput("MAIN: error creating socket %s", fs_options.socket.path);
	    goto out;

	}

    } else {

	logoutput("MAIN: error creating directory for socket %s", fs_options.socket.path);

    }

    create_pid_file(&fs_options.socket);

    browse_services_avahi();

    res=init_sessions_monitor(update_usersessions, NULL);

    if (res<0) {

	logoutput_error("MAIN: error initializing usersessions monitor, error: %i", res);
	goto out;

    }

    process_current_sessions();
    res=start_beventloop(NULL);

    out:

    // logoutput("MAIN: stop browse avahi");
    // stop_browse_avahi();

    logoutput("MAIN: close sessions monitor");
    close_sessions_monitor();

    terminate_fuse_users(NULL);

    logoutput("MAIN: end fschangenotify");
    end_fschangenotify();
    free_workspaces_base();

    //logoutput("MAIN: stop workerthreads");
    //stop_workerthreads(NULL);

    post:

    logoutput("MAIN: terminate workerthreads");

    // remove_special_files();
    // stop_workerthreads(NULL);

    terminate_workerthreads(NULL, 0);

    logoutput("MAIN: destroy eventloop");
    clear_beventloop(NULL);

    free_fuse_users();
    free_inode_hashtable();
    end_sshlibrary();

    remove_pid_file(&fs_options.socket, getpid());
    remove_special_files();

    options:

    logoutput("MAIN: free options");
    free_options();

    if (error>0) {

	logoutput_error("MAIN: error (error: %i).", error);
	return 1;

    }

    return 0;

}
