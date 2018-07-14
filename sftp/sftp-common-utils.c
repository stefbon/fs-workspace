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
#include <string.h>
#include <unistd.h>
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

#include "logging.h"
#include "main.h"
#include "utils.h"
#include "pathinfo.h"

#include "workerthreads.h"

#include "ssh-common-protocol.h"
#include "ssh-common.h"
#include "ssh-channel.h"

#include "ssh-hostinfo.h"
#include "ssh-utils.h"

#include "sftp-common-protocol.h"
#include "sftp-common.h"
#include "sftp-request-hash.h"
#include "fuse-sftp-realpath.h"

int get_session_status_ctx(struct context_interface_s *interface)
{
    struct sftp_subsystem_s *sftp_subsystem=(struct sftp_subsystem_s *) interface->ptr;

    if (sftp_subsystem) {
	struct ssh_session_s *session=sftp_subsystem->channel.session;
	struct ssh_status_s *status=&session->status;

	return (status->sessionphase.phase==SESSION_PHASE_DISCONNECT || (status->sessionphase.status & SESSION_STATUS_DISCONNECTING)) ? -1 : 0;

    }

    return -1;

}

/*
    various functions to complete the path of a sftp shared map
    examples:

    - home		: with sftp a path without the starting slash is relative to the homedirectory on the server
    - root		: normal absolute path on the server
    - custom prefix	: a path is set before the path
*/

int complete_path_sftp_home(struct context_interface_s *interface, char *buffer, struct pathinfo_s *pathinfo)
{
    /* path starts with a slash: ignore that by going one position to the right */
    pathinfo->path++;
    return -1;
}

int complete_path_sftp_root(struct context_interface_s *interface, char *buffer, struct pathinfo_s *pathinfo)
{
    /* path starts with a slash: leave that intact */
    return 0;
}

int complete_path_sftp_custom(struct context_interface_s *interface, char *buffer, struct pathinfo_s *pathinfo)
{

    /* custom prefix */

    buffer[interface->backend.sftp.prefix.len + pathinfo->len]='\0';
    memcpy(&buffer[interface->backend.sftp.prefix.len], pathinfo->path, pathinfo->len);
    memcpy(buffer, interface->backend.sftp.prefix.path, interface->backend.sftp.prefix.len);
    pathinfo->path=buffer;

    return interface->backend.sftp.prefix.len;
}

unsigned int get_complete_pathlen_home(struct context_interface_s *interface, unsigned int len)
{
    return 0;
}

unsigned int get_complete_pathlen_root(struct context_interface_s *interface, unsigned int len)
{
    return 0;
}

unsigned int get_complete_pathlen_custom(struct context_interface_s *interface, unsigned int len)
{
    return len + interface->backend.sftp.prefix.len + 1;
}

/* check the path */

int check_realpath_sftp(struct context_interface_s *interface, char *path, char **remote_target)
{

    if (get_realpath_sftp(interface, path, remote_target)) {
	struct sftp_subsystem_s *sftp_subsystem=(struct sftp_subsystem_s *) interface->ptr;
	char *result=*remote_target;
	struct ssh_session_s *session=sftp_subsystem->channel.session;
	struct ssh_hostinfo_s *hostinfo=&session->hostinfo;

	logoutput("check_realpath_sftp: path %s remote target %s", path, result);

	// if (strlen(result)>hostinfo->remote_home.len && strncmp(result, hostinfo->remote_home.ptr, hostinfo->remote_home.len)==0 && result[hostinfo->remote_home.len]=='/') {

	return 0;

    }

    return -1;

}

void sftp_fsnotify_event(struct sftp_subsystem_s *sftp, uint64_t unique, uint32_t mask, struct ssh_string_s *who, struct ssh_string_s *host, struct ssh_string_s *file)
{
    char w[who->len + 1];
    char h[host->len + 1];

    if (who->len>0) {

	memcpy(w, who->ptr, who->len);

    }

    w[who->len]='\0';

    if (host->len>0) {

	memcpy(h, host->ptr, host->len);

    }

    h[host->len]='\0';

    if (file->len>0) {
	char f[file->len + 1];

	memcpy(f, file->ptr, file->len);
	f[file->len]='\0';

	logoutput("sftp_fsnotify_event: user %s at %s watch %li file %s", w, h, unique, f);

    } else {

	logoutput("sftp_fsnotify_event: user %s at %s on watch %li", w, h, unique);

    }

}
