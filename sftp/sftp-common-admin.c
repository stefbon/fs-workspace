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
#include "workerthreads.h"

#include "ssh-common-protocol.h"
#include "ssh-common.h"
#include "ssh-channel.h"
#include "ssh-utils.h"

#include "sftp-common-protocol.h"
#include "sftp-common.h"
#include "sftp-common-utils.h"

#include "sftp-request-hash.h"

#include "sftp-attr-common.h"
#include "sftp-recv-common.h"
#include "sftp-send-common.h"

#include "sftp-common-admin.h"

static unsigned int get_sftp_sharedmap_command(struct ssh_session_s *session, char *name, char *buffer)
{
    unsigned int size=0;

    if (buffer) {
	unsigned int len=0;

	len=strlen("echo $(/usr/lib/fs-workspace/getsharedmap.sftp ");
	memcpy(buffer, "echo $(/usr/lib/fs-workspace/getsharedmap.sftp ", len);
	size+=len;

	len=strlen(name);
	memcpy(buffer+size, name, len);
	size+=len;

	len=strlen(")");
	memcpy(buffer+size, ")", len);
	size+=len;

    } else {

	size+=strlen("echo $(/usr/lib/fs-workspace/getsharedmap.sftp)") + strlen(name) + 1;

    }

    return size;

}

static unsigned int get_sftp_userinfo_command(struct ssh_session_s *session, void *data, char *buffer)
{
    struct sftp_userinfo_s *sftp_userinfo=(struct sftp_userinfo_s *) data;
    unsigned int pos=0;

    if (buffer) memcpy(buffer, "echo ", 5);
    pos+=5;

    if (sftp_userinfo->wanted & SFTP_USERINFO_REMOTE_GROUP) {
	unsigned int len=0;

	len=strlen("remotegroup=$(id -gn):");
	if (buffer) memcpy(&buffer[pos], "remotegroup=$(id -gn):", len);
	pos+=len;

    }

    if (sftp_userinfo->wanted & SFTP_USERINFO_REMOTE_UID) {
	unsigned int len=0;

	len=strlen("remoteuid=$(id -u):");
	if (buffer) memcpy(&buffer[pos], "remoteuid=$(id -u):", len);
	pos+=len;

    }

    if (sftp_userinfo->wanted & SFTP_USERINFO_REMOTE_GID) {
	unsigned int len=0;

	len=strlen("remotegid=$(id -g):");
	if (buffer) memcpy(&buffer[pos], "remotegid=$(id -g):", len);
	pos+=len;

    }

    if (sftp_userinfo->wanted & SFTP_USERINFO_REMOTE_HOME) {
	unsigned int len=0;

	len=strlen("remotehome=$HOME:");
	if (buffer) memcpy(&buffer[pos], "remotehome=$HOME:", len);
	pos+=len;

    }

    return pos;

}

unsigned int get_sftp_sharedmap(struct ssh_session_s *session, char *name, char *buffer, unsigned int len, unsigned int *error)
{
    unsigned int size=get_sftp_sharedmap_command(session, name, NULL);
    char command[size+1];

    size=get_sftp_sharedmap_command(session, name, command);
    command[size]='\0';

    logoutput("get_sftp_sharedmap: command %s", command);

    return get_result_common(session, command, buffer, len, error);

}

unsigned int get_sftp_userinfo(struct ssh_session_s *session, void *data, char *buffer, unsigned int len, unsigned int *error)
{
    unsigned int size=get_sftp_userinfo_command(session, data, NULL);
    char command[size+1];

    size=get_sftp_userinfo_command(session, data, command);
    command[size]='\0';

    logoutput("get_sftp_userinfo: command %s", command);

    return get_result_common(session, command, buffer, len, error);

}

void get_timeinfo_sftp_server(struct sftp_subsystem_s *sftp)
{
    struct ssh_channel_s *channel=&sftp->channel;
    struct ssh_session_s *session=channel->session;

    get_timeinfo_ssh_server(session);

}

unsigned int get_sftp_interface_info(struct context_interface_s *interface, const char *what, void *data, char *buffer, unsigned int size, unsigned int *error)
{
    struct ssh_session_s *session=NULL;

    logoutput("get_sftp_interface_info: what %s", what);

    if (interface->ptr) {
	struct sftp_subsystem_s *sftp_subsystem=(struct sftp_subsystem_s *) interface->ptr;
	struct ssh_channel_s *channel=&sftp_subsystem->channel;

	session=channel->session;

    } else {

	session=(struct ssh_session_s *) data;

    }

    if (! session) return 0;

    if (strcmp(what, "sftp.userinfo")==0) {

	return get_sftp_userinfo(session, data, buffer, size, error);

    }

    return 0;
}
