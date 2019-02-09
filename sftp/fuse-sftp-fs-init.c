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
#include "utils.h"
#include "logging.h"
#include "pathinfo.h"
#include "beventloop.h"

#include "fuse-dentry.h"
#include "fuse-directory.h"
#include "fuse-utils.h"

#include "fuse-fs.h"
#include "workspaces.h"
#include "workspace-context.h"
#include "path-caching.h"

#include "fuse-fs-common.h"
#include "fuse-fs-virtual.h"

#include "fuse-sftp-getattr.h"
#include "fuse-sftp-fsnotify.h"
#include "fuse-sftp-lookup.h"
#include "fuse-sftp-lock.h"
#include "fuse-sftp-open.h"
#include "fuse-sftp-opendir.h"
#include "fuse-sftp-rm.h"
#include "fuse-sftp-mk.h"
#include "fuse-sftp-setattr.h"
#include "fuse-sftp-symlink.h"
#include "fuse-sftp-statfs.h"
#include "fuse-sftp-xattr.h"

extern unsigned int get_sftp_interface_info(struct context_interface_s *interface, const char *what, void *data, struct common_buffer_s *buffer);
extern int connect_sftp_common(uid_t uid, struct context_interface_s *interface, struct context_address_s *address, unsigned int *error);
extern int start_sftp_common(struct context_interface_s *interface, int fd, void *data);

/* generic sftp fs */

static struct service_fs_s sftp_fs = {

    .lookup_existing		= _fs_sftp_lookup_existing,
    .lookup_new			= _fs_sftp_lookup_new,

    .getattr			= _fs_sftp_getattr,
    .setattr			= _fs_sftp_setattr,

    .mkdir			= _fs_sftp_mkdir,
    .mknod			= _fs_sftp_mknod,
    .symlink			= _fs_sftp_symlink,
    .symlink_validate		= _fs_sftp_symlink_validate,
    .readlink			= _fs_sftp_readlink,

    .unlink			= _fs_sftp_unlink,
    .rmdir			= _fs_sftp_rmdir,

    .create			= _fs_sftp_create,
    .open			= _fs_sftp_open,
    .read			= _fs_sftp_read,
    .write			= _fs_sftp_write,
    .fsync			= _fs_sftp_fsync,
    .flush			= _fs_sftp_flush,
    .fgetattr			= _fs_sftp_fgetattr,
    .fsetattr			= _fs_sftp_fsetattr,
    .release			= _fs_sftp_release,

    .getlock			= _fs_sftp_getlock,
    .setlock			= _fs_sftp_setlock,
    .setlockw			= _fs_sftp_setlockw,
    .flock			= _fs_sftp_flock,

    .opendir			= _fs_sftp_opendir,
    .readdir			= _fs_sftp_readdir,
    .readdirplus		= _fs_sftp_readdirplus,
    .fsyncdir			= _fs_sftp_fsyncdir,
    .releasedir			= _fs_sftp_releasedir,

    .getxattr			= _fs_sftp_getxattr,
    .setxattr			= _fs_sftp_setxattr,
    .listxattr			= _fs_sftp_listxattr,
    .removexattr		= _fs_sftp_removexattr,

    .fsnotify			= _fs_sftp_fsnotify,

    .statfs			= _fs_sftp_statfs,

};

static struct service_fs_s sftp_fs_disconnected = {

    .lookup_existing		= _fs_sftp_lookup_existing_disconnected,
    .lookup_new			= _fs_sftp_lookup_new_disconnected,

    .getattr			= _fs_sftp_getattr_disconnected,
    .setattr			= _fs_sftp_setattr_disconnected,

    .mkdir			= _fs_sftp_mkdir_disconnected,
    .mknod			= _fs_sftp_mknod_disconnected,
    .symlink			= _fs_sftp_symlink_disconnected,
    .symlink_validate		= _fs_sftp_symlink_validate_disconnected,
    .readlink			= _fs_sftp_readlink_disconnected,

    .unlink			= _fs_sftp_unlink_disconnected,
    .rmdir			= _fs_sftp_rmdir_disconnected,

    .create			= _fs_sftp_create_disconnected,
    .open			= _fs_sftp_open_disconnected,
    .read			= _fs_sftp_read_disconnected,
    .write			= _fs_sftp_write_disconnected,
    .fsync			= _fs_sftp_fsync_disconnected,
    .flush			= _fs_sftp_flush_disconnected,
    .fgetattr			= _fs_sftp_fgetattr_disconnected,
    .fsetattr			= _fs_sftp_fsetattr_disconnected,
    .release			= _fs_sftp_release_disconnected,

    .getlock			= _fs_sftp_getlock_disconnected,
    .setlock			= _fs_sftp_setlock_disconnected,
    .setlockw			= _fs_sftp_setlockw_disconnected,
    .flock			= _fs_sftp_flock_disconnected,

    .opendir			= _fs_sftp_opendir_disconnected,
    .readdir			= _fs_sftp_readdir_disconnected,
    .readdirplus		= _fs_sftp_readdirplus_disconnected,
    .fsyncdir			= _fs_sftp_fsyncdir_disconnected,
    .releasedir			= _fs_sftp_releasedir_disconnected,

    .getxattr			= _fs_sftp_getxattr,
    .setxattr			= _fs_sftp_setxattr,
    .listxattr			= _fs_sftp_listxattr,
    .removexattr		= _fs_sftp_removexattr,

    .fsnotify			= _fs_sftp_fsnotify_disconnected,

    .statfs			= _fs_sftp_statfs_disconnected,

};

/* on disconnect */

static void signal_sftp_context(struct context_interface_s *interface, const char *what)
{
    struct service_context_s *context=get_service_context(interface);
    struct workspace_mount_s *workspace=context->workspace;

    if (strcmp(what, "disconnect")==0) {

	/* when remote side disconnects: use a "disconnect" filesystem */

	pthread_mutex_lock(&workspace->mutex);

	if ((context->flags & SERVICE_CTX_FLAG_DISCONNECTED)==0) {

	    context->service.filesystem.fs=&sftp_fs_disconnected;
	    context->flags |= SERVICE_CTX_FLAG_DISCONNECTED;

	}

	pthread_mutex_unlock(&workspace->mutex);

    }

}


/* initialize a sftp subsystem interface using sftp fs */

void init_sftp_filesystem_context(struct service_context_s *context)
{
    context->interface.connect=connect_sftp_common;
    context->interface.start=start_sftp_common;
    context->interface.signal_context=signal_sftp_context;
    context->interface.get_interface_info=get_sftp_interface_info;
    context->service.filesystem.fs=&sftp_fs;
}
