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

extern unsigned int get_ssh_interface_info(struct context_interface_s *interface, const char *what, void *data, struct common_buffer_s *buffer);
extern int create_ssh_session(uid_t uid, struct context_interface_s *interface, struct context_address_s *address, unsigned int *error);
extern void signal_ssh_interface(struct context_interface_s *interface, const char *what);

static int start_ssh_session(struct context_interface_s *interface, int fd, void *data)
{
    return 0;
}

/* initialize a ssh interface */

void init_ssh_interface(struct context_interface_s *interface)
{
    struct service_context_s *context=get_service_context(interface);

    interface->get_interface_info=get_ssh_interface_info;
    interface->connect=create_ssh_session;
    interface->start=start_ssh_session;
    interface->signal_interface=signal_ssh_interface;

    context->fscount=0;

}
