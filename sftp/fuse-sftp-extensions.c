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
#include <stdint.h>
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
#include <sys/vfs.h>

#include "main.h"
#include "logging.h"
#include "utils.h"
#include "pathinfo.h"

#include "common-protocol.h"
#include "common.h"
#include "fuse-fs.h"
#include "workspaces.h"
#include "workspace-context.h"
#include "fuse-utils.h"
#include "fuse-interface.h"

#include "fuse-fs-common.h"
#include "common-protocol.h"
#include "attr-common.h"
#include "send-common.h"
#include "extensions.h"
#include "fuse-sftp-common.h"

#define NAME_MAPEXTENSION_DEFAULT "mapextension@bononline.nl"

extern void *create_sftp_request_ctx(void *ptr, struct sftp_request_s *sftp_r, unsigned int *error);
extern unsigned char wait_sftp_response_ctx(struct context_interface_s *i, void *r, struct timespec *timeout, unsigned int *error);
extern void get_sftp_request_timeout(struct timespec *timeout);

#define SFTP_EXTENSION_NAME_STATVFS			"statvfs@openssh.com"
#define SFTP_EXTENSION_NAME_FSYNC			"fsync@openssh.com"

static void fuse_sftp_extension_event_cb(struct ssh_string_s *name, struct ssh_string_s *data, void *ptr, unsigned int event)
{
    switch (event) {

    case SFTP_EXTENSION_EVENT_SUPPORTED:

	logoutput("fuse_sftp_extension_event_cb: %.*s supported by server", name->len, name->ptr);

    case SFTP_EXTENSION_EVENT_DATA:

    case SFTP_EXTENSION_EVENT_MAPPED:

    case SFTP_EXTENSION_EVENT_ERROR:

	break;

    }

}

/*
    test some extensions are supported and if so, try to map these */

void init_fuse_sftp_extensions(struct context_interface_s *interface)
{
    struct ssh_string_s name;

    /* register the statvfs extension */

    init_ssh_string(&name);
    name.len=strlen(SFTP_EXTENSION_NAME_STATVFS);
    name.ptr=SFTP_EXTENSION_NAME_STATVFS;

    register_sftp_protocolextension_ctx(interface->ptr, &name, NULL, fuse_sftp_extension_event_cb, NULL);

    /* register the fsync extension */

    init_ssh_string(&name);
    name.len=strlen(SFTP_EXTENSION_NAME_FSYNC);
    name.ptr=SFTP_EXTENSION_NAME_FSYNC;

    register_sftp_protocolextension_ctx(interface->ptr, &name, NULL, fuse_sftp_extension_event_cb, NULL);

    /* more ? like */

    /*
    - posix-rename@openssh.com
    - fstatvfs@openssh.com (not required by fuse)
    - hardlink@openssh.com
    - backup related extensions
    - opendir@sftp.bononline.nl
    */
}

void complete_fuse_sftp_extensions(struct context_interface_s *interface)
{
    char *mapname=NULL;
    struct context_option_s option;

    memset(&option, 0, sizeof(struct context_option_s));

    if ((* interface->get_context_option)(interface, "option:sftp.mapextension.name", &option)==_INTERFACE_OPTION_PCHAR) {

	mapname=(char *) option.value.ptr;

    }

    if (mapname==NULL) mapname=NAME_MAPEXTENSION_DEFAULT;

    complete_sftp_protocolextensions_ctx(interface->ptr, mapname);
}
