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
#include "options.h"

#include "workerthreads.h"
#include "beventloop.h"
#include "beventloop-signal.h"
#include "beventloop-timer.h"
#include "beventloop-xdata.h"
#include "fuse-dentry.h"
#include "fuse-directory.h"
#include "fuse-utils.h"
#include "fuse-fs.h"
#include "fuse-interface.h"

#include "workspaces.h"
#include "workspace-utils.h"
#include "workspace-session.h"
#include "workspace-context.h"
#include "fuse-fs-virtual.h"
#include "fuse-fs-special.h"
#include "backup/backup-common.h"

#include "fschangenotify.h"
#include "monitorsessions.h"
#include "monitormounts.h"

#include "pidfile.h"
#include "localsocket.h"
#include "discover/discover-avahi.h"
#include "discover/discover-staticfile.h"
#include "discover.h"
#include "fuse-network.h"

struct fs_options_s fs_options;
char *program_name=NULL;

struct finish_script_s {
    void 			(* finish)(void *ptr);
    void			*ptr;
    char			*name;
    struct finish_script_s	*next;
};

static struct finish_script_s *finish_scripts=NULL;
static pthread_mutex_t finish_scripts_mutex=PTHREAD_MUTEX_INITIALIZER;

void add_finish_script(void (* finish_cb)(void *ptr), void *ptr, char *name)
{
    struct finish_script_s *script=NULL;

    script=malloc(sizeof(struct finish_script_s));

    if (script) {

	script->finish=finish_cb;
	script->ptr=ptr;
	script->name=name;
	script->next=NULL;

	pthread_mutex_lock(&finish_scripts_mutex);

	script->next=finish_scripts;
	finish_scripts=script;

	pthread_mutex_unlock(&finish_scripts_mutex);

    } else {

	logoutput_warning("add_finish_script: error allocating memory to add finish script");

    }

}

void run_finish_scripts()
{
    struct finish_script_s *script=NULL;

    pthread_mutex_lock(&finish_scripts_mutex);

    script=finish_scripts;

    while (script) {

	finish_scripts=script->next;

	if (script->name) logoutput_info("run_finish_scripts: run script %s", script->name);

	(* script->finish)(script->ptr);
	free(script);

	script=finish_scripts;

    }

    pthread_mutex_unlock(&finish_scripts_mutex);

}

void end_finish_scripts()
{
    pthread_mutex_destroy(&finish_scripts_mutex);
}

static void _disconnect_workspace(struct context_interface_s *interface)
{
    struct service_context_s *root=get_service_context(interface);
    struct workspace_mount_s *workspace=NULL;
    unsigned int error=0;
    struct directory_s *root_directory=NULL;
    struct list_element_s *list=NULL;
    struct service_context_s *context=NULL;

    logoutput_info("_disconnect_workspace");

    workspace=root->workspace;
    if (! workspace) return;

    pthread_mutex_lock(&workspace->mutex);
    workspace->status=WORKSPACE_STATUS_UNMOUNTING;
    pthread_mutex_unlock(&workspace->mutex);

    (* interface->signal_interface)(interface, "disconnecting");
    (* interface->signal_interface)(interface, "close");
    root->service.connection=NULL;

    logoutput_info("_disconnect_workspace: umount");

    if (workspace->mountpoint.path && workspace->mountpoint.len>0) {

	if (umount2(workspace->mountpoint.path, MNT_DETACH)==0) {

	    logoutput_info("_disconnect_workspace: umounted %s", workspace->mountpoint.path);

	} else {

	    logoutput_info("_disconnect_workspace: error %i (%s) umounting %s", errno, strerror(errno), workspace->mountpoint.path);

	}

    }

    pthread_mutex_lock(&workspace->mutex);
    workspace->status=WORKSPACE_STATUS_UNMOUNTED;
    pthread_mutex_unlock(&workspace->mutex);

    logoutput_info("_disconnect_workspace: remove inodes, entries and directories");

    root_directory=remove_directory(&workspace->rootinode, &error);

    if (root_directory) {

	/* this will also close and free connections */
	clear_directory(interface, root_directory);
	destroy_directory(root_directory);

    }

    list=get_list_head(&workspace->contexes, SIMPLE_LIST_FLAG_REMOVE);

    while (list) {

	context=get_container_context(list);

	/* TODO: build some protection here */

	if (context->refcount==0 || (context->flags & SERVICE_CTX_FLAG_REFCOUNTNONZERO)) {

	    logoutput_info("_disconnect_workspace: disconnect service %s context", context->name);

	    (* context->interface.signal_interface)(&context->interface, "disconnecting");
	    (* context->interface.signal_interface)(&context->interface, "close");
	    (* context->interface.signal_interface)(&context->interface, "free");
	    if (context->parent) context->parent->refcount--;
	    free_service_context(context);

	} else {

	    logoutput_info("_disconnect_workspace: service %s refcount %i", context->name, context->refcount);
	    add_list_element_last(&workspace->contexes, list);
	    context->flags|=SERVICE_CTX_FLAG_REFCOUNTNONZERO;

	}

	list=get_list_head(&workspace->contexes, SIMPLE_LIST_FLAG_REMOVE);

    }

    (* interface->signal_interface)(interface, "free");

}

static void signal_workspace_context(struct context_interface_s *interface, const char *what)
{
    struct service_context_s *context=get_service_context(interface);
    struct workspace_mount_s *workspace=context->workspace;
    struct fuse_user_s *user=workspace->user;

    logoutput_info("signal_workspace_context: what %s", what);

    /* what to do here ? */

}

/* enable/disable flags for filesystem
    depends on the type:
    - flock enabled on filesystems
    - xattr ?
*/

static unsigned int get_mount_context_option(struct context_interface_s *interface, const char *name, struct context_option_s *option)
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
	option->value.number=0;

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
	option->value.number=0; /* try */

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
    char source[64];
    char name[32];

    logoutput("create_mount_context: uid %i", (int) user->uid);

    workspace=malloc(sizeof(struct workspace_mount_s));
    if (workspace==NULL || init_workspace_mount(workspace, &error)==-1) goto error;

    context=create_service_context(workspace, SERVICE_CTX_TYPE_WORKSPACE);
    if (context==NULL) goto error;
    strcpy(context->name, "virtual");

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

    /* choose a good name for fuse fs */

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

    logoutput_info("create_mount_context: init fuse");

    if (init_fuse_interface(&context->interface)==0) {
	struct context_address_s address;
	struct inode_link_s link;
	int fd=-1;

	context->interface.signal_context=signal_workspace_context;
	context->interface.get_context_option=get_mount_context_option;

	register_fuse_functions(&context->interface);
	use_virtual_fs(context, &workspace->rootinode);
	set_directory_dump(&workspace->rootinode, get_dummy_directory());
	// is this required???
	//link.type=INODE_LINK_TYPE_CONTEXT;
	//link.link.ptr=(void *) context;
	//set_inode_link_directory(&workspace->rootinode, &link);

	/* connect to the fuse interface: mount */
	/* target address of interface is a local mountpoint */

	memset(&address, 0, sizeof(struct context_address_s));
	address.network.type=_INTERFACE_ADDRESS_NONE;
	address.service.type=_INTERFACE_SERVICE_FUSE;
	address.service.target.fuse.source=source;
	address.service.target.fuse.mountpoint=workspace->mountpoint.path;
	address.service.target.fuse.name=name;
	fd=(* context->interface.connect)(user->uid, &context->interface, &address, &error);

	if (fd==-1) {

	    logoutput("create_mount_context: failed to mount %s", workspace->mountpoint.path);
	    goto error;

	}

	if ((* context->interface.start)(&context->interface, fd, NULL)==0) {

	    (* user->add_workspace)(user, workspace);
	    user->options |= base->type;
	    logoutput("create_mount_context: %s mounted", workspace->mountpoint.path);
	    create_personal_workspace_mount(workspace);
	    return context;

	}

	logoutput("create_mount_context: failed to start %s", workspace->mountpoint.path);
	close(fd);

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

    list=get_list_head(&user->workspaces, 0);

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
	list=get_list_head(&user->workspaces, 0);

    }

    logoutput("terminate_user_workspaces: ready");

}

static void terminate_fuse_user(void *ptr)
{
    struct fuse_user_s *user=(struct fuse_user_s *) ptr;

    logoutput("terminate_fuse_user: %i", user->uid);

    terminate_user_workspaces(user);
    umount_mounts_found(user, UMOUNT_WORKSPACE_FLAG_EXTRA | UMOUNT_WORKSPACE_FLAG_MOUNT);
    pthread_mutex_destroy(&user->mutex);
    free(user);
    user=NULL;

}

static void terminate_fuse_users(void *ptr)
{
    struct fuse_user_s *user=NULL;
    void *index=NULL;
    unsigned int hashvalue=0;
    struct simple_lock_s wlock;

    logoutput_info("terminate_fuse_users");
    init_wlock_users_hash(&wlock);

    getuser:

    index=NULL;

    lock_users_hash(&wlock);
    user=get_next_fuse_user(&index, &hashvalue);
    if (user) remove_fuse_user_hash(user);
    unlock_users_hash(&wlock);

    if (user) {
	unsigned int error=0;

	work_workerthread(NULL, 0, terminate_fuse_user, (void *) user, &error);
	index=NULL;
	goto getuser;

    }

    logoutput_info("terminate_fuse_users: ready");

}

static void add_usersession(uid_t uid, char *what)
{
    struct fuse_user_s *user=NULL;
    unsigned int error=0;

    logoutput_info("add_usersession: %i", (int) uid);

    user=add_fuse_user(uid, what, &error);

    if (user && error==0) {
	struct workspace_base_s *base=NULL;

	/* lookup in workspaces... which applies */

	base=get_next_workspace_base(NULL);

	while (base) {

	    logoutput_info("add_usersession: testing %s", base->name);

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
    struct simple_lock_s wlock;

    logoutput_info("change_usersession");

    init_wlock_users_hash(&wlock);
    lock_users_hash(&wlock);

    user=lookup_fuse_user(uid);

    if (user) {

	/* remove user when not active anymore */

	if (strcmp(status, "active")!=0 && strcmp(user->status, "active")==0) {

	    remove_fuse_user_hash(user);
	    unlock_users_hash(&wlock);
	    work_workerthread(NULL, 0, terminate_fuse_user, NULL, (void *) user);
	    return;

	}

    } else {

	if (strcmp(status, "active")==0) add_usersession(uid, status);

    }

    unlock_users_hash(&wlock);

    logoutput_info("change_usersession: done");

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

    logoutput("workspace_signal_handler: received %i", signo);

    if ( signo==SIGHUP || signo==SIGINT || signo==SIGTERM ) {

	logoutput("workspace_signal_handler: got signal (%i): terminating", signo);
	bloop->status=BEVENTLOOP_STATUS_DOWN;

	/*
	    TODO: send a signal to all available io contexes to stop waiting
	*/

    } else if ( signo==SIGIO ) {

	logoutput("workspace_signal_handler: SIGIO");

	/*
	    TODO:
	    when receiving an SIGIO signal another application is trying to open a file
	    is this really the case?
	    then the fuse fs is the owner!?

	    note 	fdsi->ssi_pid
			fdsi->ssi_fd
	*/

    } else if ( signo==SIGPIPE ) {

	logoutput("workspace_signal_handler: SIGPIPE");

    } else if ( signo==SIGCHLD ) {

	logoutput("workspace_signal_handler: SIGCHLD");

    } else if ( signo==SIGUSR1 ) {

	logoutput("workspace_signal_handler: SIGUSR1");

	/* TODO: use to reread the configuration ?*/

    } else {

        logoutput("workspace_signal_handler: received unknown %i signal", signo);

    }

}
/* accept only connections from users with a complete session
    what api??
    SSH_MSG_CHANNEL_REQUEST...???
*/

struct fs_connection_s *accept_client_connection(uid_t uid, gid_t gid, pid_t pid, struct fs_connection_s *s_conn)
{
    struct fuse_user_s *user=NULL;
    struct simple_lock_s wlock;

    logoutput_info("accept_client_connection");
    init_wlock_users_hash(&wlock);

    lock_users_hash(&wlock);

    user=lookup_fuse_user(uid);

    if (user) {
	struct fs_connection_s *c_conn=malloc(sizeof(struct fs_connection_s));

	if (c_conn) {

	    init_connection(c_conn, FS_CONNECTION_TYPE_LOCAL, FS_CONNECTION_ROLE_CLIENT);
	    unlock_users_hash(&wlock);
	    return c_conn;

	}

    }

    unlock:
    unlock_users_hash(&wlock);
    return NULL;
}

int main(int argc, char *argv[])
{
    int res=0;
    unsigned int error=0;
    struct bevent_xdata_s *xdata=NULL;
    struct fs_connection_s socket;

    switch_logging_backend("std");
    setlogmask(LOG_UPTO(LOG_DEBUG));

    logoutput_info("%s started", argv[0]);

    /* parse commandline options and initialize the fuse options */

    res=parse_arguments(argc, argv, &error);

    if (res==-1 || res==1) {

	if (res==-1 && error>0) {

	    if (error>0) logoutput_error("MAIN: error, cannot parse arguments, error: %i (%s).", error, strerror(error));

	}

	goto options;

    }

    /* daemonize */

    res=custom_fork();

    if (res<0) {

        logoutput_error("MAIN: error daemonize.");
        return 1;

    } else if (res>0) {

	logoutput_info("MAIN: created a service with pid %i.", res);
	return 0;

    }

    /* output to stdout/stderr is useless since daemonized */

    switch_logging_backend("syslog");

    if (fs_options.basemap.path) {

	logoutput_info("MAIN: reading workspaces from %s.", fs_options.basemap.path);
	read_workspace_files(fs_options.basemap.path);

    } else {

	logoutput_info("MAIN: reading workspaces from %s.", _OPTIONS_MAIN_BASEMAP);
	read_workspace_files(_OPTIONS_MAIN_BASEMAP);

    }

    init_directory_calls();
    init_special_fs();

    if (init_discover_group(&error)==-1) {

	logoutput_error("MAIN: error, cannot initialize discover group, error: %i (%s).", error, strerror(error));
	goto post;

    } else {

	logoutput_info("MAIN: initialized discover group");

    }

    set_discover_net_cb(install_net_services_cb);

    if (init_inode_hashtable(&error)==-1) {

	logoutput_error("MAIN: error, cannot initialize inode hash table, error: %i (%s).", error, strerror(error));
	goto post;

    }

    if (initialize_context_hashtable()==-1) {

	logoutput_error("MAIN: error, cannot initialize service context hash table.");
	goto post;

    }

    if (initialize_fuse_users(&error)==-1) {

	logoutput_error("MAIN: error, cannot initialize fuse users hash table, error: %i (%s).", error, strerror(error));
	goto post;

    }

    init_backuphash();
    init_directory_hashtable();

    if (init_beventloop(NULL, &error)==-1) {

        logoutput_error("MAIN: error creating eventloop, error: %i (%s).", error, strerror(error));
        goto post;

    } else {

	logoutput_info("MAIN: creating eventloop");

    }

    if (enable_beventloop_signal(NULL, workspace_signal_handler, NULL, &error)==-1) {

	logoutput_error("MAIN: error adding signal handler to eventloop: %i (%s).", error, strerror(error));
        goto out;

    } else {

	logoutput_info("MAIN: adding signal handler");

    }

    if (add_mountinfo_watch(NULL, &error)==-1) {

        logoutput_error("MAIN: unable to open mountmonitor, error=%i (%s)", error, strerror(error));
        goto out;

    } else {

	logoutput_info("MAIN: open mountmonitor");

    }

    umount_mounts_found(NULL, UMOUNT_WORKSPACE_FLAG_EXTRA | UMOUNT_WORKSPACE_FLAG_MOUNT);

    /* Initialize and start default threads
	NOTE: important to start these after initializing the signal handler, if not doing this this way any signal will make the program crash */

    init_workerthreads(NULL);
    set_max_numberthreads(NULL, 6); /* depends on the number of users and connected workspaces, 6 is a reasonable amount for this moment */
    start_default_workerthreads(NULL);

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

		/* pid file found, but no process, so it's not running: remove the pid file */

		remove_pid_file(&fs_options.socket, (pid_t) alreadyrunning);
		alreadyrunning=0;
		count++;
		goto checkpidfile;

	    } else {
		int fd=0;

		/* check the contents of the procfile cmdline: it should be the same as argv[0] */

		fd=open(procpath, O_RDONLY);

		if (fd>0) {
		    char buffer[PATH_MAX];
		    ssize_t bytesread=0;

		    memset(buffer, '\0', PATH_MAX);
		    bytesread=read(fd, buffer, PATH_MAX);
		    if (bytesread>0) {

			// if (strcmp(buffer, argv[0]) != 0) {

			    logoutput_info("MAIN: cmdline pid %i is %s", alreadyrunning, buffer);

			//}

		    }

		    close(fd);

		}

	    }

	}

	if (check_socket_path(&fs_options.socket, alreadyrunning)==-1) goto out;
	init_connection(&socket, FS_CONNECTION_TYPE_LOCAL, FS_CONNECTION_ROLE_SERVER);

	if (create_local_serversocket(fs_options.socket.path, &socket, NULL, accept_client_connection, &error)>=0) {

	    logoutput_info("MAIN: created socket %s", fs_options.socket.path);

	} else {

	    logoutput_info("MAIN: error %i creating socket %s (%s)", error, fs_options.socket.path, strerror(error));
	    goto out;

	}

    } else {

	logoutput_info("MAIN: error creating directory for socket %s", fs_options.socket.path);

    }

    create_pid_file(&fs_options.socket);

    if (fs_options.network.flags & _OPTIONS_NETWORK_DISCOVER_METHOD_FILE) {

	if (fs_options.network.discover_static_file) {

	    browse_services_staticfile(fs_options.network.discover_static_file);

	} else {

	    browse_services_staticfile(_OPTIONS_NETWORK_DISCOVER_STATIC_FILE_DEFAULT);

	}

    }

    browse_services_avahi();

    res=init_sessions_monitor(update_usersessions, NULL);

    if (res<0) {

	logoutput_error("MAIN: error initializing usersessions monitor, error: %i", res);
	goto out;

    }

    process_current_sessions();

    res=start_beventloop(NULL);

    out:

    // logoutput_info("MAIN: stop browse avahi");
    // stop_browse_avahi();

    logoutput_info("MAIN: close sessions monitor");
    close_sessions_monitor();
    terminate_fuse_users(NULL);

    logoutput_info("MAIN: end fschangenotify");
    end_fschangenotify();
    free_workspaces_base();
    free_directory_hashtable();

    logoutput_info("MAIN: stop workerthreads");
    stop_workerthreads(NULL);

    post:

    logoutput_info("MAIN: terminate workerthreads");

    free_special_fs();
    // stop_workerthreads(NULL);

    run_finish_scripts();
    end_finish_scripts();

    terminate_workerthreads(NULL, 0);

    logoutput_info("MAIN: destroy eventloop");
    clear_beventloop(NULL);

    free_fuse_users();
    free_inode_hashtable();

    remove_pid_file(&fs_options.socket, getpid());

    options:

    logoutput_info("MAIN: free options");
    free_options();

    if (error>0) {

	logoutput_error("MAIN: error (error: %i).", error);
	return 1;

    }

    return 0;

}
