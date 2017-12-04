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
#include "utils.h"

#include "ssh-common.h"
#include "ssh-common-protocol.h"

#include "ssh-send.h"

#include "ssh-utils.h"

static int _send_disconnect_message(struct ssh_session_s *session, struct ssh_payload_s *payload, void *ptr)
{
    unsigned int error=0;
    unsigned int *reason=(unsigned int *) ptr;
    unsigned int len=write_disconnect_reason(*reason, NULL, 0, &error);

    if (payload==NULL) {

	return 1 + 4 + 4 + len + 4;

    } else {
	char *pos=NULL;

	pos=payload->buffer;
	*pos=(unsigned char) SSH_MSG_DISCONNECT;
	pos++;

	store_uint32(pos, *reason);
	pos+=4;

	len=write_disconnect_reason(*reason, pos, (unsigned int)(payload->buffer + payload->len - pos), &error);
	pos+=len;

	store_uint32(pos, 0); /* no language tag */
	pos+=4;

	return (unsigned int)(pos - payload->buffer);

    }

    return 0;

}

void send_disconnect_message(struct ssh_session_s *session, unsigned int reason)
{
    unsigned int seq=0;

    if (send_ssh_message(session, _send_disconnect_message, (void *) &reason, &seq)==-1) {
	unsigned int error=session->status.error;

	session->status.error=0;
	logoutput("send_disconnect_message: error %i:%s", error, strerror(error));

    }

}

struct service_request_s {
    const char *service;
};

static int _send_service_request_message(struct ssh_session_s *ssh_session, struct ssh_payload_s *payload, void *ptr)
{
    unsigned int error=0;
    struct service_request_s *service_request=(struct service_request_s *) ptr;
    unsigned int len=strlen(service_request->service);

    if (payload==NULL) {

	return 1 + 4 + len;

    } else {
	char *pos=NULL;

	pos=payload->buffer;
	*pos=(unsigned char) SSH_MSG_SERVICE_REQUEST;
	pos++;

	store_uint32(pos, len);
	pos+=4;

	memcpy(pos, service_request->service, len);
	pos+=len;

	return (unsigned int)(pos - payload->buffer);

    }

    return 0;

}

int send_service_request_message(struct ssh_session_s *session, const char *service, unsigned int *seq)
{
    struct service_request_s service_request;

    service_request.service=service;

    if (send_ssh_message(session, _send_service_request_message, (void *) &service_request, seq)==-1) {
	unsigned int error=session->status.error;

	session->status.error=0;

	logoutput("send_service_request_message: error %i:%s", error, strerror(error));
	return -1;

    }

    return 0;

}

/* functions to send a global request
    (https://tools.ietf.org/html/rfc4254#section-4)
    a global request looks like:
    - byte			SSH_MSG_GLOBAL_REQUEST
    - string			request name
    - boolean			want reply
    - ....			request specific data

    for example:

    - request port forwarding
    (https://tools.ietf.org/html/rfc4254#section-7.1)
    - byte 			SSH_MSG_GLOBAL_REQUEST
    - string			"tcpip-forward"
    - boolean			want reply
    - string			address to bind (e.g., "0.0.0.0")
    - uint32			port number to bind
    */

struct global_request_s {
    const char 			*service;
    unsigned char		reply;
    char			*data;
    unsigned int 		size;
};

static int _send_global_request_message(struct ssh_session_s *ssh_session, struct ssh_payload_s *payload, void *ptr)
{
    unsigned int error=0;
    struct global_request_s *global_request=(struct global_request_s *) ptr;
    unsigned int len=strlen(global_request->service);

    if (payload==NULL) {

	return 1 + 4 + len + 1 + 4 + global_request->size;

    } else {
	char *pos=NULL;

	pos=payload->buffer;
	*pos=(unsigned char) SSH_MSG_SERVICE_REQUEST;
	pos++;

	store_uint32(pos, len);
	pos+=4;

	memcpy(pos, global_request->service, len);
	pos+=len;

	*pos='1';
	pos++;

	store_uint32(pos, global_request->size);
	pos+=4;

	memcpy(pos, global_request->data, global_request->size);
	pos+=global_request->size;

	return (unsigned int)(pos - payload->buffer);

    }

    return 0;

}

int send_global_request_message(struct ssh_session_s *session, const char *service, char *data, unsigned int size, unsigned int *seq)
{
    struct global_request_s global_request;

    global_request.service=service;
    global_request.reply=1; /* always want a reply */
    global_request.data=data;
    global_request.size=size;

    if (send_ssh_message(session, _send_global_request_message, (void *) &global_request, seq)==-1) {
	unsigned int error=session->status.error;

	session->status.error=0;

	logoutput("send_service_request_message: error %i:%s", error, strerror(error));
	return -1;

    }

    return 0;

}
