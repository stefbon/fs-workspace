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

#include "utils.h"

#include "ssh-common.h"
#include "ssh-common-protocol.h"

#include "ssh-send.h"
#include "ssh-utils.h"

#define CHANNEL_NAME_DEFAULT 					"session"
#define CHANNEL_NAME_DIRECT_STREAMLOCAL 			"direct-streamlocal@openssh.com"
#define CHANNEL_NAME_DIRECT_TCPIP 				"direct-tcpip"

/*
    opening a channel for a session and simular like direct-streamlocal
    message has the form:
    - byte			SSH_MSG_CHANNEL_OPEN
    - string			channel type
    - uint32			local channel
    - uint32			window size
    - uint32			max packet size
    - ....			additional data depends on the type of open channel

    like the default session:

    - byte			SSH_MSG_CHANNEL_OPEN
    - string			"session"
    - uint32			local channel
    - uint32			window size
    - uint32			max packet size

    and direct-tcpip

    - byte      		SSH_MSG_CHANNEL_OPEN
    - string			"direct-tcpip"
    - uint32			sender channel
    - uint32			initial window size
    - uint32			maximum packet size
    - string			host to connect
    - uint32			port to connect
    - string			originator IP address
    - uint32			originator port

    and direct-streamlocal

    - byte			SSH_MSG_CHANNEL_OPEN
    - string			"direct-streamlocal@openssh.com"
    - uint32			sender channel
    - uint32			initial window size
    - uint32			maximum packet size
    - string			socket path
    - string			reserved
    - uint32			reserved

*/

struct open_channel_s {
    const char			*name;
    unsigned int		local_channel;
    unsigned int 		window_size;
    unsigned int 		max_packet_size;
    union {
	struct direct_streamlocal_s {
	    char		*socket;
	} direct_streamlocal;
	struct direct_tcpip_s {
	    char		*host;
	    unsigned int	port;
	    char		*ip_orig;
	    unsigned int	port_orig;
	} direct_tcpip;
    } type;
};

static int _send_channel_open_message(struct ssh_session_s *session, struct ssh_payload_s *payload, void *ptr)
{
    struct open_channel_s *open_channel=(struct open_channel_s *) ptr;
    unsigned int len=0;

    len=strlen(open_channel->name);

    if (payload==NULL) {

	len += 17;

	if (strcmp(open_channel->name, CHANNEL_NAME_DIRECT_STREAMLOCAL)==0) {

	    len += 4 + strlen(open_channel->type.direct_streamlocal.socket) + 4 + 4;

	} else if (strcmp(open_channel->name, CHANNEL_NAME_DIRECT_TCPIP)==0) {

	    len += 4 + strlen(open_channel->type.direct_tcpip.host) + 4 + 4 + strlen(open_channel->type.direct_tcpip.ip_orig) + 4;

	}

    } else {
	char *pos=payload->buffer;

	*pos=(unsigned char) SSH_MSG_CHANNEL_OPEN;
	pos++;

	store_uint32(pos, len);
	pos+=4;

	memcpy(pos, open_channel->name, len);
	pos+=len;

	store_uint32(pos, open_channel->local_channel);
	pos+=4;

	store_uint32(pos, open_channel->window_size);
	pos+=4;

	store_uint32(pos, open_channel->max_packet_size);
	pos+=4;

	if (strcmp(open_channel->name, CHANNEL_NAME_DIRECT_STREAMLOCAL)==0) {

	    len=strlen(open_channel->type.direct_streamlocal.socket);

	    store_uint32(pos, len);
	    pos+=4;

	    memcpy(pos, open_channel->type.direct_streamlocal.socket, len);
	    pos+=len;

	    /* 20170528: string and uint32 for future use, now empty */

	    store_uint32(pos, 0);
	    pos+=4;

	    store_uint32(pos, 0);
	    pos+=4;

	} else if (strcmp(open_channel->name, CHANNEL_NAME_DIRECT_TCPIP)==0) {

	    len=strlen(open_channel->type.direct_tcpip.host);

	    store_uint32(pos, len);
	    pos+=4;

	    memcpy(pos, open_channel->type.direct_tcpip.host, len);
	    pos+=len;

	    store_uint32(pos, open_channel->type.direct_tcpip.port);
	    pos+=4;

	    len=strlen(open_channel->type.direct_tcpip.ip_orig);

	    store_uint32(pos, len);
	    pos+=4;

	    memcpy(pos, open_channel->type.direct_tcpip.ip_orig, len);
	    pos+=len;

	    store_uint32(pos, open_channel->type.direct_tcpip.port_orig);
	    pos+=4;

	}

	return (unsigned int)(pos - payload->buffer);

    }

    return len;

}

int send_channel_open_message(struct ssh_channel_s *channel, unsigned int *seq)
{
    struct open_channel_s open_channel;

    logoutput("send_channel_open_message");

    memset(&open_channel, 0, sizeof(struct open_channel_s));

    if (channel->type==_CHANNEL_TYPE_DIRECT_STREAMLOCAL) {

	open_channel.name=CHANNEL_NAME_DIRECT_STREAMLOCAL;
	open_channel.type.direct_streamlocal.socket=channel->target.socket.path;

    } else if (channel->type==_CHANNEL_TYPE_DIRECT_TCPIP) {

	open_channel.name=CHANNEL_NAME_DIRECT_TCPIP;
	open_channel.type.direct_tcpip.host=channel->target.tcpip.host;
	open_channel.type.direct_tcpip.port=channel->target.tcpip.port;
	open_channel.type.direct_tcpip.ip_orig="127.0.0.1"; /* does this work? */
	open_channel.type.direct_tcpip.port_orig=0;

    } else {

	open_channel.name=CHANNEL_NAME_DEFAULT;

    }

    open_channel.local_channel=channel->local_channel;
    open_channel.window_size=channel->local_window;
    open_channel.max_packet_size=get_max_packet_size(channel->session);

    if (send_ssh_message(channel->session, _send_channel_open_message, (void *) &open_channel, seq)==-1) {
	unsigned int error=channel->session->status.error;

	channel->session->status.error=0;

	logoutput("send_channel_open_message: error %i:%s", error, strerror(error));
	return -1;

    }

    return 0;

}

/* close a channel */

static int _send_channel_close_message(struct ssh_session_s *session, struct ssh_payload_s *payload, void *ptr)
{

    if (payload==NULL) {

	return 5;

    } else {
	char *pos=payload->buffer;
	struct ssh_channel_s *channel=(struct ssh_channel_s *) ptr;

	*pos=(unsigned char) SSH_MSG_CHANNEL_CLOSE;
	pos++;

	store_uint32(pos, channel->remote_channel);
	pos+=4;

	return (unsigned int)(pos - payload->buffer);

    }

    return 0;

}

void send_channel_close_message(struct ssh_channel_s *channel)
{
    unsigned int seq=0;

    if (send_ssh_message(channel->session, _send_channel_close_message, (void *) channel, &seq)==-1) {
	unsigned int error=channel->session->status.error;

	channel->session->status.error=0;

	logoutput("send_channel_close_message: error %i:%s", error, strerror(error));

    }

}

/*
    want a subsystem or exec a command (RFC4254 6.5. Starting a Shell or a Command)

    - byte 	SSH_MSG_CHANNEL_REQUEST
    - uint32    remote channel
    - string	"subsystem"/"exec"
    - boolean	want reply
    - string 	subsystem name/command
*/

struct request_command_s {
    const char *command;
    const char *name;
    unsigned int remote_channel;
    unsigned char reply;
};

static int _send_start_command_message(struct ssh_session_s *session, struct ssh_payload_s *payload, void *ptr)
{
    struct request_command_s *request=(struct request_command_s *) ptr;

    if (payload==NULL) {
	unsigned int len=0;

	len+=1;
	len+=4;
	len+=4 + strlen(request->command);
	len+=1;

	if (request->name) {

	    len+=4+strlen(request->name);

	}

	return len;

    } else {
	char *pos=payload->buffer;
	unsigned int len_command=strlen(request->command);

	*pos=(unsigned char) SSH_MSG_CHANNEL_REQUEST;
	pos++;

	store_uint32(pos, request->remote_channel);
	pos+=4;

	store_uint32(pos, len_command);
	pos+=4;

	memcpy(pos, request->command, len_command);
	pos+=len_command;

	*pos=request->reply; /* want a reply */
	pos++;

	if (request->name) {
	    unsigned int len_name=strlen(request->name);

	    store_uint32(pos, len_name);
	    pos+=4;

	    memcpy(pos, request->name, len_name);
	    pos+=len_name;

	}

	return (unsigned int)(pos - payload->buffer);

    }

    return 0;

}

int send_start_command_message(struct ssh_channel_s *channel, const char *command, const char *name, unsigned char reply, unsigned int *seq)
{
    struct request_command_s request;

    request.command=command;
    request.remote_channel=channel->remote_channel;
    request.name=name;
    request.reply=reply;

    if (send_ssh_message(channel->session, _send_start_command_message, (void *) &request, seq)==-1) {
	unsigned int error=channel->session->status.error;

	channel->session->status.error=0;

	logoutput("send_start_command_message: error %i:%s", error, strerror(error));
	return -1;

    }

    return 0;

}

/*
    send a channel data (RFC4254 5.2. Data Transfer)

    - byte 	SSH_MSG_CHANNEL_DATA
    - uint32    local channel
    - uint32	len
    - byte[len]
*/

struct channel_data_s {
    unsigned int 		len;
    unsigned char		*data;
    unsigned int 		remote_channel;
};

static int _send_channel_data_message(struct ssh_session_s *session, struct ssh_payload_s *payload, void *ptr)
{
    struct channel_data_s *channel_data=(struct channel_data_s *) ptr;

    if (payload==NULL) {

	return 9 + channel_data->len;

    } else {
	char *pos=payload->buffer;

	*pos=(unsigned char) SSH_MSG_CHANNEL_DATA;
	pos++;

	store_uint32(pos, channel_data->remote_channel);
	pos+=4;

	store_uint32(pos, channel_data->len);
	pos+=4;

	memcpy(pos, channel_data->data, channel_data->len);
	pos+=channel_data->len;

	return (unsigned int)(pos - payload->buffer);

    }

    return 0;

}

static int send_channel_data_message_connected(struct ssh_channel_s *channel, unsigned int len, unsigned char *data, unsigned int *seq)
{
    struct channel_data_s channel_data;

    channel_data.remote_channel=channel->remote_channel;
    channel_data.data=data;
    channel_data.len=len;

    if (send_ssh_message(channel->session, _send_channel_data_message, (void *) &channel_data, seq)==-1) {
	unsigned int error=channel->session->status.error;

	channel->session->status.error=0;

	logoutput("send_channel_data_message: error %i:%s", error, strerror(error));
	return -1;

    }

    return 0;

}

static int send_channel_data_message_error(struct ssh_channel_s *channel, unsigned int len, unsigned char *data, unsigned int *seq)
{
    return -1;
}

int send_channel_data_message(struct ssh_channel_s *channel, unsigned int len, unsigned char *data, unsigned int *seq)
{
    int result=0;
    pthread_mutex_lock(&channel->mutex);
    result=(* channel->send_data_message)(channel, len, data, seq);
    pthread_mutex_unlock(&channel->mutex);
    return result;
}

void switch_channel_send_data(struct ssh_channel_s *channel, const char *what)
{
    if (strcmp(what, "error")==0 || strcmp(what, "eof")==0 || strcmp(what, "close")==0) {

	channel->send_data_message=send_channel_data_message_error;

    } else if (strcmp(what, "default")==0) {

	channel->send_data_message=send_channel_data_message_connected;

    } else {

	logoutput_warning("switch_channel_send_data: status %s not reckognized", what);

    }

}
