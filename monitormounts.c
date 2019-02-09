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
#include "fuse-dentry.h"
#include "fuse-directory.h"
#include "fuse-utils.h"

#include "workerthreads.h"
#include "fuse-fs.h"
#include "workspaces.h"
#include "workspace-context.h"
#include "workspace-session.h"

#include "mountinfo.h"
#include "mountinfo-monitor.h"
#include "monitormounts.h"

#include "fuse-fs-common.h"
#include "fuse-network.h"
#include "fuse-backup.h"
#include "discover.h"

static struct bevent_xdata_s xdata;

static int update_mountinfo(unsigned long generation, struct mountentry_s *(*next) (void **index, unsigned long generation, unsigned char type))
{
    struct mountentry_s *entry=NULL;
    void *index=NULL;
    unsigned int error=0;

    logoutput("update_mountinfo: generation %li", generation);

    entry=next(&index, generation, MOUNTLIST_ADDED);

    while (entry) {

	logoutput("update_mountinfo: found %s at %s", entry->fs, entry->mountpoint);

	if (strncmp(entry->fs, "fuse.", 5)==0 ) {
	    struct service_context_s *context=NULL;

	    error=0;

	    /* look for matching workspace/context */

	    context=get_next_service_context(NULL, "FUSE");

	    while (context) {

		if (context->workspace) {
		    struct workspace_mount_s *workspace=context->workspace;

		    if (strcmp(entry->mountpoint, workspace->mountpoint.path)==0) break;

		}

		context=get_next_service_context(context, "FUSE");

	    }

	    if (context) {
		struct workspace_mount_s *workspace=context->workspace;
		struct workspace_base_s *base=workspace->base;

		if (base->type==WORKSPACE_TYPE_NETWORK) {

		    /* get all network services */

		    logoutput("update_mountinfo: found network workspace %s on %s", base->name, workspace->mountpoint.path);
		    get_net_services(&workspace->syncdate, install_net_services_cb, (void *) context);

		} else if (base->type==WORKSPACE_TYPE_BACKUP) {

		    logoutput("update_mountinfo: found backup workspace %s on %s", base->name, workspace->mountpoint.path);
		    start_backup_service(context);

		} else {

		    logoutput("update_mountinfo: unable to process workspace %s on %s", base->name, workspace->mountpoint.path);

		}

	    }

	}

	logoutput("update_mountinfo: next");
	entry=next(&index, generation, MOUNTLIST_ADDED);

    }

    return 1;

}

void umount_workspace_mounts(struct workspace_mount_s *workspace)
{
    unsigned int error=0;
    void *index=NULL;
    struct mountentry_s *entry=NULL;
    unsigned int len=0;

    lock_mountlist("write", &error);

    entry=get_next_mountentry(&index, 0, MOUNTLIST_CURRENT);

    while (entry) {

	len=strlen(entry->mountpoint);

	if (len>workspace->mountpoint.len) {

	    if (strncmp(entry->mountpoint, workspace->mountpoint.path, len)==0 && entry->mountpoint[len]=='/') {

		umount2(entry->mountpoint, MNT_DETACH);

	    }

	}

	entry=get_next_mountentry(&index, 0, MOUNTLIST_CURRENT);

    }

    unlock_mountlist("write", &error);

}

static unsigned char ignore_mountinfo (char *source, char *fs, char *path)
{

    if (strncmp(fs, "fuse.", 5)==0) return 0;
    return 1;

}

int add_mountinfo_watch(struct beventloop_s *loop, unsigned int *error)
{
    init_xdata(&xdata);
    if (! loop) loop=get_mainloop();

    if (open_mountmonitor(&xdata, error)==0) {

	set_updatefunc_mountmonitor(update_mountinfo);
	set_ignorefunc_mountmonitor(ignore_mountinfo);
	set_threadsqueue_mountmonitor(NULL);

	if (add_to_beventloop(xdata.fd, EPOLLPRI, xdata.callback, NULL, &xdata, loop)) {

    	    logoutput_info("add_mountinfo_watch: mountinfo fd %i added to eventloop", xdata.fd);

	    /* read the mountinfo to initialize */
	    (* xdata.callback)(0, NULL, 0);
	    return 0;

	} else {

	    logoutput_info("add_mountinfo_watch: unable to add mountinfo fd %i to eventloop", xdata.fd);
	    *error=EIO;

	}

    } else {

	logoutput_info("add_mountinfo_watch: unable to open mountmonitor");

    }

    return -1;

}
