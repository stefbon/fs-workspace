/*
  2016, 2017, 2018 Stef Bon <stefbon@gmail.com>

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

#define SSH_GREETER_START			"SSH-"
#define SSH_GREETER_TERMINATOR_CRLF		1
#define SSH_GREETER_TERMINATOR_LF		2

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
    char *start=NULL;
    unsigned int left=0;

    if (greeter->ptr==NULL || greeter->len==0) return -1;

    start=(char *) (greeter->ptr + strlen(SSH_GREETER_START));
    left=greeter->len - strlen(SSH_GREETER_START);
    sep=memchr(start, '-', left);

    if (sep) {
	unsigned int len=(unsigned int) (sep - start);
	char ssh_version[len+1];
	char *dot=NULL;

	memset(ssh_version, '\0', len+1);
	memcpy(ssh_version, start, len);

	dot=memchr(ssh_version, '.', len);

	if (dot) {

	    *dot='\0';

	    session->status.remote_version_major=atoi(ssh_version);
	    session->status.remote_version_minor=atoi(dot+1);

	} else {

	    session->status.remote_version_major=atoi(ssh_version);
	    session->status.remote_version_minor=0;

	}

    } else {

	/* error in the version: there should be a '-' */

	logoutput("read_ssh_version: format error (no - seperator found)");
	return -1;

    }

    return 0;

}

int read_server_greeter(struct ssh_session_s *session)
{
    struct ssh_receive_s *receive=&session->receive;
    char line[255];
    unsigned int size=0;
    char *sep=NULL;
    unsigned int len=0;
    unsigned char terminator=SSH_GREETER_TERMINATOR_CRLF;
    unsigned char found=0;
    char term_crlf[2];
    char term_lf[1];

    term_crlf[0]=13;
    term_crlf[1]=10;
    term_lf[0]=10;

    logoutput("read_server_greeter");

    readlinegreeter:

    pthread_mutex_lock(&receive->mutex);

    /* dealing with the line seperator :
       for SSH1 lines end with 10, SSH2 lines end with 13 and 10
       TODO: here a expire & cond_timedwait*/

    sep=memmem(receive->buffer, receive->read, term_crlf, 2);

    if (sep) {

	terminator=SSH_GREETER_TERMINATOR_CRLF;

    } else {

	terminator=SSH_GREETER_TERMINATOR_LF;
	sep=memmem(receive->buffer, receive->read, term_lf, 1);

    }

    if (! sep) {

	logoutput("read_server_greeter: no CR or LF found");
	pthread_mutex_unlock(&receive->mutex);
	goto error;

    }

    size = (unsigned int)(sep + ((terminator==SSH_GREETER_TERMINATOR_CRLF) ? 2 : 1) - receive->buffer);

    if (size>255) {

	logoutput("read_server_greeter: found line with size %i which is greater than 255; cannot continue", size);
	pthread_mutex_unlock(&receive->mutex);
	goto error;

    }

    size = (unsigned int)(sep - receive->buffer);
    memcpy(line, receive->buffer, size);
    line[size]='\0';

    /* shift */
    size = (unsigned int)(sep + ((terminator==SSH_GREETER_TERMINATOR_CRLF) ? 2 : 1) - receive->buffer);
    if (receive->read>size) memmove(receive->buffer, (char *)(receive->buffer + size), receive->read - size);
    receive->read-=size;

    pthread_mutex_unlock(&receive->mutex);

    len=strlen(line);

    if (len > strlen(SSH_GREETER_START) && memcmp(line, SSH_GREETER_START, strlen(SSH_GREETER_START))==0) {

	if (found==1) {

	    logoutput("read_server_greeter: string %s found more than once", SSH_GREETER_START);
	    goto error;

	}

	found=1;
	session->data.greeter_server.ptr=malloc(len);

	if (session->data.greeter_server.ptr) {

	    memcpy(session->data.greeter_server.ptr, line, len);
	    session->data.greeter_server.len=len;

	    logoutput("read_server_greeter: received identification %s", line);

	} else {

	    logoutput("read_server_greeter: not enough memory");
	    goto error;

	}

    } else {

	/* another line */

	logoutput("read_server_greeter: received extra line %s", line);
	goto readlinegreeter;

    }

    out:

    if (found==1) {

	if (read_ssh_version(session)==0) {

	    logoutput("read_server_greeter: found server version %i.%i", session->status.remote_version_major, session->status.remote_version_minor);

	} else {

	    logoutput("read_server_greeter: unable to determine server version");
	    goto error;

	}

    } else {

	logoutput("read_server_greeter: no identification string found, cannot continue");
	goto error;

    }

    return 0;

    error:

    return -1;

}

