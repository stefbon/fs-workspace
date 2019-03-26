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
#include "fuse-utils.h"
#include "fuse-interface.h"

#include "path-caching.h"
#include "workspace-interface.h"

#include "fuse-fs-common.h"

#include "common-protocol.h"
#include "attr-common.h"
#include "send-common.h"

#include "fuse-sftp-common.h"

extern void *create_sftp_request_ctx(void *ptr, struct sftp_request_s *sftp_r, unsigned int *error);
extern unsigned char wait_sftp_response_simple_ctx(void *ptr, void *r, struct timespec *timeout, unsigned int *error);
extern void get_sftp_request_timeout(struct timespec *t);
extern unsigned int get_uint32(char *b);

char *get_realpath_sftp(struct context_interface_s *interface, unsigned char *target, unsigned char **path)
{
    struct sftp_request_s sftp_r;

    memset(&sftp_r, 0, sizeof(struct sftp_request_s));

    sftp_r.id=0;
    sftp_r.call.realpath.path=target;
    sftp_r.call.realpath.len=strlen((const char *)target);

    if (send_sftp_realpath_ctx(interface->ptr, &sftp_r)==0) {
	void *request=NULL;
	unsigned int error=0;

	request=create_sftp_request_ctx(interface->ptr, &sftp_r, &error);

	if (request) {
	    struct timespec timeout;

	    get_sftp_request_timeout(&timeout);

	    if (wait_sftp_response_simple_ctx(interface->ptr, request, &timeout, &error)==1) {

		if (sftp_r.type==SSH_FXP_NAME) {
		    char *pos=sftp_r.response.names.buff;
		    unsigned int len=0;

		    /*
			reply NAME looks like:
			- string		filename
			- ATTRS
		    */

		    len=get_uint32((char *)pos);
		    memmove(pos, pos+4, len);
		    *path=(unsigned char *) pos;
		    pos+=len;
		    *pos='\0';

		    logoutput("get_realpath_sftp: remote target %s", *path);

		} else if (sftp_r.type==SSH_FXP_STATUS) {

		    error=sftp_r.response.status.linux_error;
		    logoutput("get_realpath_sftp: server reply error %i getting realpath (%s)", error, strerror(error));
		    *path=NULL;

		} else {

		    *path=NULL;

		}

	    }

	}

    }

    return (char *) *path;

}
