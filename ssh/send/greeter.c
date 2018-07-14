/*
  2010, 2011, 2012, 2103, 2014, 2015 Stef Bon <stefbon@gmail.com>

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

#include "main.h"
#include "logging.h"

#include "utils.h"

#include "ssh-common.h"
#include "ssh-utils.h"

unsigned int create_greeter(char *pos)
{
    unsigned int len0=strlen("SSH-2.0-sftpfs_");
#ifdef FS_WORKSPACE_VERSION
    unsigned int len1=strlen(FS_WORKSPACE_VERSION);
#else
    unsigned int len1=strlen("1.0a1");
#endif

    if (pos) {

	memcpy(pos, "SSH-2.0-sftpfs_", len0);
	pos+=len0;

#ifdef FS_WORKSPACE_VERSION

	memcpy(pos, FS_WORKSPACE_VERSION, len1);

#else

	memcpy(pos, "1.0a1", len1);

#endif

	pos+=len1;

    }

    return len0+len1;
}


int send_greeter(struct ssh_session_s *session)
{
    unsigned int len=create_greeter(NULL);
    char line[len+2];

    len=create_greeter(&line[0]);

    line[len]=0;

    logoutput("send_greeter: sending %s", line);

    line[len]=(unsigned char) 13;
    line[len+1]=(unsigned char) 10;

    if (write(session->connection.fd, line, len+2)==-1) {

	session->status.error=errno;
	logoutput("send_greeter: error %i:%s", errno, strerror(errno));
	return -1;

    }

    if (create_ssh_string(&session->data.greeter_client, len)==len) {

	memcpy(session->data.greeter_client.ptr, line, len);
	session->data.greeter_client.len=len;

    } else {

	return -1;

    }

    return 0;

}
