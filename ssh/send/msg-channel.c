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

static int _send_channel_open_message(struct msg_buffer_s *mb, struct ssh_channel_s *channel)
{
    unsigned int len=0;

    logoutput_debug("_send_channel_open_message");

    msg_write_byte(mb, SSH_MSG_CHANNEL_OPEN);

    if (channel->type==_CHANNEL_TYPE_DIRECT_STREAMLOCAL) {

	msg_write_ssh_string(mb, 'c', (void *) CHANNEL_NAME_DIRECT_STREAMLOCAL);

    } else if (channel->type==_CHANNEL_TYPE_DIRECT_TCPIP) {

	msg_write_ssh_string(mb, 'c', (void *) CHANNEL_NAME_DIRECT_TCPIP);

    } else {

	msg_write_ssh_string(mb, 'c', (void *) CHANNEL_NAME_DEFAULT);

    }

    msg_store_uint32(mb, channel->local_channel);
    msg_store_uint32(mb, channel->local_window);
    msg_store_uint32(mb, get_max_packet_size(channel->session));

    if (channel->type==_CHANNEL_TYPE_DIRECT_STREAMLOCAL) {

	msg_write_ssh_string(mb, 'c', (void *) channel->target.socket.path);

	/* 20170528: string and uint32 for future use, now empty */

	msg_store_uint32(mb, 0);
	msg_store_uint32(mb, 0);

    } else if (channel->type==_CHANNEL_TYPE_DIRECT_TCPIP) {
	char *hostname=NULL, *ipv4=NULL, *ipv6=NULL;
	char *target=NULL;

	/* one of these will be set */
	get_host_address(&channel->target.network.host, &hostname, &ipv4, &ipv6);
	target=(hostname) ? hostname : ((ipv4) ? ipv4 : ipv6);

	msg_write_ssh_string(mb, 'c', (void *) target);
	msg_store_uint32(mb, channel->target.network.port);
	msg_write_ssh_string(mb, 'c', (void *) "127.0.0.1");
	msg_store_uint32(mb, 0);

    }

    return mb->pos;

}

int send_channel_open_message(struct ssh_channel_s *channel, unsigned int *seq)
{
    struct msg_buffer_s mb=INIT_SSH_MSG_BUFFER;
    unsigned int len=_send_channel_open_message(&mb, channel);
    char buffer[sizeof(struct ssh_payload_s) + len];
    struct ssh_payload_s *payload=(struct ssh_payload_s *) buffer;

    logoutput_debug("send_channel_open_message");

    init_ssh_payload(payload, len);
    payload->type=SSH_MSG_CHANNEL_OPEN;
    set_msg_buffer_payload(&mb, payload);
    payload->len=_send_channel_open_message(&mb, channel);

    return write_ssh_packet(channel->session, payload, seq);

}

/* close a channel */

int send_channel_close_message(struct ssh_channel_s *channel)
{
    char buffer[sizeof(struct ssh_payload_s) + 5];
    struct ssh_payload_s *payload=(struct ssh_payload_s *) buffer;
    unsigned int seq=0;
    char *pos=payload->buffer;

    logoutput_debug("send_channel_close_message");

    init_ssh_payload(payload, 5);
    payload->type=SSH_MSG_CHANNEL_CLOSE;

    *pos=(unsigned char) SSH_MSG_CHANNEL_CLOSE;
    pos++;

    store_uint32(pos, channel->remote_channel);
    pos+=4;

    return write_ssh_packet(channel->session, payload, &seq);

}

/* window adjust */

int send_channel_window_adjust_message(struct ssh_channel_s *channel, unsigned int increase)
{
    char buffer[sizeof(struct ssh_payload_s) + 9];
    struct ssh_payload_s *payload=(struct ssh_payload_s *) buffer;
    unsigned int seq=0;
    char *pos=payload->buffer;

    logoutput_debug("send_channel_window_adjust_message");

    init_ssh_payload(payload, 9);
    payload->type=SSH_MSG_CHANNEL_WINDOW_ADJUST;

    *pos=(unsigned char) SSH_MSG_CHANNEL_WINDOW_ADJUST;
    pos++;

    store_uint32(pos, channel->remote_channel);
    pos+=4;

    store_uint32(pos, increase);
    pos+=4;

    return write_ssh_packet(channel->session, payload, &seq);

}

/*
    want a subsystem or exec a command (RFC4254 6.5. Starting a Shell or a Command)

    - byte 	SSH_MSG_CHANNEL_REQUEST
    - uint32    remote channel
    - string	"subsystem"/"exec"
    - boolean	want reply
    - string 	subsystem name/command
*/

int send_start_command_message(struct ssh_channel_s *channel, const char *command, const char *name, unsigned char reply, unsigned int *seq)
{
    unsigned int len=10 + strlen(command) + ((name) ? (4 + strlen(name)) : 0);
    char buffer[sizeof(struct ssh_payload_s) + len];
    struct ssh_payload_s *payload=(struct ssh_payload_s *) buffer;
    char *pos=payload->buffer;

    init_ssh_payload(payload, len);
    payload->type=SSH_MSG_CHANNEL_REQUEST;

    *pos=(unsigned char) SSH_MSG_CHANNEL_REQUEST;
    pos++;

    store_uint32(pos, channel->remote_channel);
    pos+=4;

    pos+=write_ssh_string(pos, 0, 'c', (void *) command);

    *pos=(reply>0) ? 1 : 0;
    pos++;

    if (name) pos+=write_ssh_string(pos, 0, 'c', (void *) name);

    payload->len=(unsigned int)(pos - payload->buffer);

    return write_ssh_packet(channel->session, payload, seq);

}

/*
    send a channel data (RFC4254 5.2. Data Transfer)

    - byte 	SSH_MSG_CHANNEL_DATA
    - uint32    remote channel
    - uint32	len
    - byte[len]
*/

static int send_channel_data_message_connected(struct ssh_channel_s *channel, unsigned int size, char *data, unsigned int *seq)
{
    unsigned int len=9 + size;
    char buffer[sizeof(struct ssh_payload_s) + len];
    struct ssh_payload_s *payload=(struct ssh_payload_s *) buffer;
    char *pos=payload->buffer;

    init_ssh_payload(payload, len);
    payload->type=SSH_MSG_CHANNEL_DATA;

    *pos=(unsigned char) SSH_MSG_CHANNEL_DATA;
    pos++;

    store_uint32(pos, channel->remote_channel);
    pos+=4;

    store_uint32(pos, size);
    pos+=4;
    memcpy(pos, data, size);
    pos+=size;

    payload->len=(unsigned int)(pos - payload->buffer);

    return write_ssh_packet(channel->session, payload, seq);

}

static int send_channel_data_message_error(struct ssh_channel_s *channel, unsigned int len, char *data, unsigned int *seq)
{
    return -1;
}

int send_channel_data_message(struct ssh_channel_s *channel, unsigned int len, char *data, unsigned int *seq)
{
    (* channel->process_outgoing_bytes)(channel, len);
    return (* channel->send_data_message)(channel, len, data, seq);
}

void switch_channel_send_data(struct ssh_channel_s *channel, const char *what)
{

    pthread_mutex_lock(&channel->mutex);

    if (strcmp(what, "error")==0 || strcmp(what, "eof")==0 || strcmp(what, "close")==0) {

	channel->send_data_message=send_channel_data_message_error;

    } else if (strcmp(what, "default")==0) {

	channel->send_data_message=send_channel_data_message_connected;

    } else {

	logoutput_warning("switch_channel_send_data: status %s not reckognized", what);

    }

    pthread_mutex_unlock(&channel->mutex);

}
