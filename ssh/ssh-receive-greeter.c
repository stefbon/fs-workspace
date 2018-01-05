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

#include "logging.h"
#include "main.h"

#include "utils.h"

#include "ssh-common.h"
#include "ssh-receive.h"

#define SSH_GREETER_START		"SSH-"

/*
    get the remote ssh version
    this string has the form:

    SSH-x.yz-softwareversion<SP>comment<CR><LF>

    - it's also possible that there is no comment, then there is also no <SP>
*/

static int read_ssh_version(struct ssh_session_s *session)
{
    struct ssh_string_s *greeter=&session->data.greeter_server;
    char *sep=NULL;
    unsigned len_start=strlen(SSH_GREETER_START);

    sep=memchr((char *) (greeter->ptr+len_start), '-', greeter->len-len_start);

    if (sep) {
	unsigned int len=(unsigned int) (sep - (greeter->ptr+len_start));
	unsigned char ssh_version[len+1];
	char *dot=NULL;

	memset(ssh_version, '\0', len+1);
	memcpy(ssh_version, (char *) (greeter->ptr+len_start), len);

	dot=memchr((char *) ssh_version, '.', len);

	if (dot) {

	    *dot='\0';

	    session->status.remote_version_major=atoi((char *) ssh_version);
	    session->status.remote_version_minor=atoi(dot+1);

	} else {

	    session->status.remote_version_major=atoi((char *) ssh_version);
	    session->status.remote_version_minor=0;

	}

    } else {

	/* error in the version: there should be a '-' */

	logoutput_error("read_ssh_version: format error");
	return -1;

    }

    return 0;

}

int read_server_greeter(struct rawdata_s *data)
{
    struct ssh_session_s *session=data->session;
    struct ssh_receive_s *receive=&session->receive;
    char *line=data->buffer;
    char *sep=NULL;
    unsigned int pos=0;
    unsigned char found=0;


    logoutput("read_server_greeter");

    processline:

    /* dealing with the line seperator :
       for SSH1 lines end with 10, SSH2 lines end with 13 and 10
    */

    sep=memchr(line, 13, (unsigned int) (data->buffer + data->size - line));

    if (! sep) {

	sep=memchr(line, 10, (unsigned int) (data->buffer + data->size - line));

    } else {

	if (*(sep+1)!=10) {

	    logoutput("read_server_greeter: greeter does not end with CRLF: LF missing");
	    return -1;

	}

    }

    if (sep) {

	if (memcmp(line, SSH_GREETER_START, strlen(SSH_GREETER_START))==0) {
	    unsigned int len=0;

	    if (found==0) {

		found=1;

	    } else {

		logoutput_error("read_server_greeter: string SSH- found more than once");
		return -1;

	    }

	    /* line with greeter may not be longer than 255 bytes */

	    len=(unsigned int) (sep - line);
	    data->len+=len+1+(*(sep+1)==10) ? 1 : 0;

	    if ( len < 255) {

		session->data.greeter_server.ptr=malloc(len);

		if (session->data.greeter_server.ptr) {
		    char tmp[len+1];

		    memcpy(session->data.greeter_server.ptr, line, len);
		    session->data.greeter_server.len=len;

		    memcpy(tmp, line, len);
		    tmp[len]='\0';

		    logoutput("read_server_greeter: received %s", tmp);

		} else {

		    logoutput_error("read_server_greeter: not enough memory");
		    return -1;

		}

		if (read_ssh_version(session)==0) {

		    logoutput("read_server_greeter: found server version %i.%i", session->status.remote_version_major, session->status.remote_version_minor);

		} else {

		    logoutput_error("read_server_greeter: unable to determine server version");
		    return -1;

		}

	    } else {

		logoutput_error("read_server_greeter: greeter too long (%i)", len);

	    }

	    line=data->buffer + data->len;
	    if (data->len < data->size) goto processline;

	} else {

	    data->len+=(unsigned int) (sep - line) + 1 + (*(sep+1)==10) ? 1 : 0;

	    line=data->buffer + data->len;
	    if (data->len < data->size) goto processline;

	}

    } else {

	logoutput("read_server_greeter: no CR or LF found");
	return -1;

    }

    return 0;

}

