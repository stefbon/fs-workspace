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

#include "fuse-fs.h"
#include "workspaces.h"
#include "workspace-context.h"
#include "fuse-utils.h"
#include "fuse-interface.h"

#include "fuse-fs-common.h"
#include "common-protocol.h"
#include "attr-common.h"
#include "send-common.h"

#include "fuse-sftp-common.h"

#define NAME_MAPEXTENSION_DEFAULT "mapextension@bononline.nl"

extern void *create_sftp_request_ctx(void *ptr, struct sftp_request_s *sftp_r, unsigned int *error);
extern unsigned char wait_sftp_response_ctx(struct context_interface_s *i, void *r, struct timespec *timeout, unsigned int *error);
extern void get_sftp_request_timeout(struct timespec *timeout);
extern void *lookup_sftp_extension_ctx(void *ptr, char *name);
extern int test_extension_supported_ctx(void *ptr, char *mapname);

static unsigned char map_sftp_extension(struct context_interface_s *interface, char *name, unsigned int *error)
{
    struct sftp_request_s sftp_r;
    unsigned char mapped=0;
    char *mapname=NULL;
    struct context_option_s option;

    memset(&option, 0, sizeof(struct context_option_s));

    if ((* interface->get_context_option)(interface, "option:sftp.mapextension.name", &option)==_INTERFACE_OPTION_PCHAR) {

	mapname=(char *) option.value.ptr;

    }

    if (mapname==NULL) mapname=NAME_MAPEXTENSION_DEFAULT;

    if (test_extension_supported_ctx(interface->ptr, mapname)==-1) {

	*error=ENOTSUP;
	return 0;

    }

    init_sftp_request(&sftp_r);
    *error=EIO;

    sftp_r.id=0;

    sftp_r.call.extension.len=strlen(mapname);
    sftp_r.call.extension.name=(unsigned char *)mapname;
    sftp_r.call.extension.size=strlen(name);
    sftp_r.call.extension.data=(unsigned char *)name;
    sftp_r.fuse_request=NULL;

    if (send_sftp_extension_ctx(interface->ptr, &sftp_r)==0) {
	void *request=NULL;

	request=create_sftp_request_ctx(interface->ptr, &sftp_r, error);

	if (request) {
	    struct timespec timeout;

	    get_sftp_request_timeout(&timeout);

	    if (wait_sftp_response_ctx(interface, request, &timeout, error)==1) {

		if (sftp_r.type==SSH_FXP_EXTENDED_REPLY) {

		    if (sftp_r.response.extension.size>=4) {

			mapped=get_uint32(sftp_r.response.extension.buff);
			*error=0;

		    }

		} else if (sftp_r.type==SSH_FXP_STATUS) {

		    *error=sftp_r.response.status.linux_error;

		} else {

		    *error=EPROTO;

		}

	    }

	}

    } else {

	*error=sftp_r.error;

    }

    return mapped;

}

/*
    test some extensions are supported and if so, try to map these */

void init_fuse_sftp_extensions(struct context_interface_s *interface)
{

    if (lookup_sftp_extension_ctx(interface->ptr, "statvfs@openssh.com")) {
	unsigned int error=0;

	interface->backend.sftp.flags |= CONTEXT_INTERFACE_BACKEND_SFTP_FLAG_STATFS_OPENSSH;

	unsigned char mapped=map_sftp_extension(interface, "statvfs@openssh.com", &error);

	if (mapped>0) {

	    logoutput("init_sftp_extensions: extension statvfs@openssh.com found and mapped to %i", mapped);
	    interface->backend.sftp.mapped_statfs=mapped;

	} else {

	    logoutput("init_sftp_extensions: extension statvfs@openssh.com found");

	}

    }

    if (lookup_sftp_extension_ctx(interface->ptr, "fsync@openssh.com")) {
	unsigned int error=0;

	interface->backend.sftp.flags |= CONTEXT_INTERFACE_BACKEND_SFTP_FLAG_FSYNC_OPENSSH;

	unsigned char mapped=map_sftp_extension(interface, "fsync@openssh.com", &error);

	if (mapped>0) {

	    logoutput("init_sftp_extensions: extension fsync@openssh.com found and mapped to %i", mapped);
	    interface->backend.sftp.mapped_fsync=mapped;

	} else {

	    logoutput("init_sftp_extensions: extension fsync@openssh.com found");

	}

    }

}
